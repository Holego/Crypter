#!/usr/bin/env python3
"""Crypter — утилита для хеширования и шифрования файлов.

Примеры:
    python crypter.py                                 # интерактивное меню
    python crypter.py list                            # список алгоритмов
    python crypter.py hash file.txt -a sha256 -a md5  # хеши файла
    python crypter.py hash file.txt --all             # все хеши сразу
    python crypter.py encrypt file.txt -a chacha20    # -> file.txt.enc
    python crypter.py decrypt file.txt.enc            # -> file.txt
"""

import argparse
import base64
import getpass
import hashlib
import io
import os
import secrets
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
except ImportError:
    sys.exit("Нужна библиотека cryptography: pip install cryptography")

CHUNK_SIZE = 1024 * 1024  # 1 МиБ — файл шифруется кусками, поэтому размер не ограничен памятью

# --- Хеширование ------------------------------------------------------------

HASH_ALGORITHMS = {
    "md5": "MD5 (устарел, только для контрольных сумм)",
    "sha1": "SHA-1 (устарел, только для контрольных сумм)",
    "sha256": "SHA-256",
    "sha512": "SHA-512",
    "sha3_256": "SHA3-256",
    "sha3_512": "SHA3-512",
    "blake2b": "BLAKE2b (512 бит)",
    "blake2s": "BLAKE2s (256 бит)",
}


def hash_file(path: Path, algorithms: list[str]) -> dict[str, str]:
    """Считает несколько хешей за один проход по файлу."""
    hashers = {name: hashlib.new(name) for name in algorithms}
    with path.open("rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            for h in hashers.values():
                h.update(chunk)
    return {name: h.hexdigest() for name, h in hashers.items()}


# --- Шифрование -------------------------------------------------------------
#
# Формат файла .enc:
#   MAGIC(4) | VERSION(1) | ALG_ID(1) | SALT(16) | NONCE_PREFIX(7) | чанки...
# Каждый чанк — шифротекст до CHUNK_SIZE байт + 16 байт тега аутентификации.
# Nonce чанка = NONCE_PREFIX(7) | номер_чанка(4) | флаг_последнего(1)
# (схема STREAM): нельзя переставить, удалить или обрезать чанки незаметно.
# Заголовок передаётся как AAD, поэтому его подмена тоже обнаруживается.
# Ключ выводится из пароля через scrypt.

MAGIC = b"CRPT"
VERSION = 1
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 7
TAG_SIZE = 16
HEADER_SIZE = len(MAGIC) + 2 + SALT_SIZE + NONCE_PREFIX_SIZE

CIPHERS = {
    # имя: (id в заголовке, класс AEAD, описание)
    "aes-gcm": (1, AESGCM, "AES-256-GCM"),
    "chacha20": (2, ChaCha20Poly1305, "ChaCha20-Poly1305"),
}
CIPHERS_BY_ID = {cid: (name, cls) for name, (cid, cls, _) in CIPHERS.items()}


def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=2**15, r=8, p=1,
        maxmem=64 * 1024 * 1024, dklen=32,
    )


def chunk_nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    return prefix + struct.pack(">IB", counter, 1 if last else 0)


def build_header(cipher_id: int, salt: bytes, prefix: bytes) -> bytes:
    return MAGIC + bytes([VERSION, cipher_id]) + salt + prefix


def parse_header(header: bytes) -> tuple[str, type, bytes, bytes]:
    """Разбирает заголовок, возвращает (имя шифра, класс, salt, prefix)."""
    if len(header) != HEADER_SIZE or not header.startswith(MAGIC):
        raise ValueError("это не файл, зашифрованный Crypter")
    version, cipher_id = header[4], header[5]
    if version != VERSION:
        raise ValueError(f"неподдерживаемая версия формата: {version}")
    if cipher_id not in CIPHERS_BY_ID:
        raise ValueError(f"неизвестный шифр: {cipher_id}")
    cipher, cipher_cls = CIPHERS_BY_ID[cipher_id]
    return cipher, cipher_cls, header[6:6 + SALT_SIZE], header[6 + SALT_SIZE:]


def encrypt_stream(fin, fout, aead, prefix: bytes, header: bytes) -> None:
    counter = 0
    chunk = fin.read(CHUNK_SIZE)
    while True:
        next_chunk = fin.read(CHUNK_SIZE)
        last = not next_chunk
        fout.write(aead.encrypt(chunk_nonce(prefix, counter, last), chunk, header))
        if last:
            break
        chunk = next_chunk
        counter += 1


def decrypt_stream(fin, fout, aead, prefix: bytes, header: bytes) -> None:
    counter = 0
    block = fin.read(CHUNK_SIZE + TAG_SIZE)
    while True:
        next_block = fin.read(CHUNK_SIZE + TAG_SIZE)
        last = not next_block
        try:
            fout.write(aead.decrypt(chunk_nonce(prefix, counter, last), block, header))
        except InvalidTag:
            raise ValueError("неверный пароль или файл повреждён") from None
        if last:
            break
        block = next_block
        counter += 1


def encrypt_file(src: Path, dst: Path, password: str, cipher: str) -> None:
    cipher_id, cipher_cls, _ = CIPHERS[cipher]
    salt = secrets.token_bytes(SALT_SIZE)
    prefix = secrets.token_bytes(NONCE_PREFIX_SIZE)
    header = build_header(cipher_id, salt, prefix)
    aead = cipher_cls(derive_key(password, salt))
    with src.open("rb") as fin, dst.open("wb") as fout:
        fout.write(header)
        encrypt_stream(fin, fout, aead, prefix, header)


def decrypt_file(src: Path, dst: Path, password: str) -> str:
    """Расшифровывает файл, возвращает имя использованного шифра."""
    tmp = dst.with_name(dst.name + ".part")
    with src.open("rb") as fin:
        cipher, cipher_cls, salt, prefix = parse_header(fin.read(HEADER_SIZE))
        aead = cipher_cls(derive_key(password, salt))
        header = build_header(CIPHERS[cipher][0], salt, prefix)
        # Пишем во временный файл: при ошибке не оставляем полурасшифрованных данных.
        try:
            with tmp.open("wb") as fout:
                decrypt_stream(fin, fout, aead, prefix, header)
            tmp.replace(dst)
        finally:
            tmp.unlink(missing_ok=True)
    return cipher


# --- Самораспаковывающийся лаунчер (pack) -----------------------------------
#
# pack шифрует файл СЛУЧАЙНЫМ ключом и генерирует самодостаточный .py-лаунчер,
# в котором ключ и зашифрованные данные вшиты (base64). При запуске лаунчер
# расшифровывает программу во временный файл, запускает её (с переданными
# аргументами) и удаляет временный файл после выхода.
#
# ВАЖНО: это ОБФУСКАЦИЯ, а не настоящая секретность. Раз ключ лежит внутри
# лаунчера, подготовленный человек может его извлечь и расшифровать. Защищает
# от обычного пользователя, который просто хочет пользоваться программой.

# Фиксированное тело лаунчера: не зависит от упакованных файлов. Преамбула
# задаёт KEY_B64, PAYLOADS (список [data_b64, interp, suffix]) и PARALLEL.
# Все программы запускаются ОТКРЫТО; при одной программе аргументы командной
# строки передаются ей насквозь.
LAUNCHER_BODY = '''
import base64, io, os, struct, subprocess, sys, tempfile, threading

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
except ImportError:
    sys.exit("Для запуска нужна библиотека cryptography: pip install cryptography")

_CIPHERS = {1: AESGCM, 2: ChaCha20Poly1305}
_HEADER = 29       # MAGIC(4)+VERSION(1)+ALG(1)+SALT(16)+PREFIX(7)
_CHUNK = 1024 * 1024
_TAG = 16
_ARGS = sys.argv[1:] if len(PAYLOADS) == 1 else []   # аргументы — только одиночной программе


def _decrypt(key, blob):
    bio = io.BytesIO(blob)
    header = bio.read(_HEADER)
    aead = _CIPHERS[header[5]](key)
    prefix = header[22:29]
    out = bytearray()
    counter = 0
    block = bio.read(_CHUNK + _TAG)
    while True:
        nxt = bio.read(_CHUNK + _TAG)
        last = not nxt
        nonce = prefix + struct.pack(">IB", counter, 1 if last else 0)
        out += aead.decrypt(nonce, block, header)
        if last:
            break
        block = nxt
        counter += 1
    return bytes(out)


def _run_inprocess(data):
    # Python-payload выполняется прямо в этом процессе: внешний интерпретатор
    # не нужен (важно для standalone-сборки) и ничего не пишется на диск.
    g = {"__name__": "__main__", "__file__": "<packed>"}
    saved = sys.argv
    sys.argv = ["<packed>"] + _ARGS
    try:
        exec(compile(data, "<packed>", "exec"), g)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    finally:
        sys.argv = saved
    return 0


def _run_tempfile(interp, suffix, data):
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, data)
        os.close(fd)
        os.chmod(path, 0o700)
        return subprocess.call(interp + [path] + _ARGS)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _run_one(entry, key):
    data = _decrypt(key, base64.b64decode(entry[0]))
    interp, suffix = entry[1], entry[2]
    if interp is None:
        return _run_inprocess(data)
    return _run_tempfile(interp, suffix, data)


def _main():
    key = base64.b64decode(KEY_B64)
    if PARALLEL and len(PAYLOADS) > 1:
        results = {}
        threads = []
        for i, entry in enumerate(PAYLOADS):
            t = threading.Thread(target=lambda i=i, e=entry: results.__setitem__(i, _run_one(e, key)))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        codes = [results.get(i) or 0 for i in range(len(PAYLOADS))]
    else:
        codes = [(_run_one(e, key) or 0) for e in PAYLOADS]
    return max(codes) if codes else 0   # ненулевой код, если хоть одна программа упала


if __name__ == "__main__":
    sys.exit(_main())
'''


def _encrypt_blob(src: Path, cipher: str, key: bytes) -> bytes:
    """Шифрует файл в памяти заданным ключом, возвращает blob (header+чанки)."""
    cipher_id, cipher_cls, _ = CIPHERS[cipher]
    salt = secrets.token_bytes(SALT_SIZE)       # не используется, нужен для формата
    prefix = secrets.token_bytes(NONCE_PREFIX_SIZE)
    header = build_header(cipher_id, salt, prefix)
    buf = io.BytesIO()
    buf.write(header)
    with src.open("rb") as fin:
        encrypt_stream(fin, buf, cipher_cls(key), prefix, header)
    return buf.getvalue()


def render_launcher(key: bytes, payloads: list[tuple[bytes, list, str]], parallel: bool) -> str:
    entries = [[base64.b64encode(blob).decode(), interp, suffix] for blob, interp, suffix in payloads]
    note = "зашифрованная программа" if len(entries) == 1 else f"{len(entries)} зашифрованные программы"
    return (
        "#!/usr/bin/env python3\n"
        f"# Сгенерировано Crypter. Внутри — {note}.\n"
        f"KEY_B64 = {base64.b64encode(key).decode()!r}\n"
        f"PAYLOADS = {entries!r}\n"
        f"PARALLEL = {parallel!r}\n"
        + LAUNCHER_BODY
    )


def pack_file(src: Path, dst: Path, cipher: str, interpreter: list, suffix: str) -> None:
    key = secrets.token_bytes(32)
    payloads = [(_encrypt_blob(src, cipher, key), interpreter, suffix)]
    dst.write_text(render_launcher(key, payloads, parallel=False), encoding="utf-8")


def bundle_files(entries: list[tuple[Path, list, str]], dst: Path, cipher: str, parallel: bool) -> None:
    """Объединяет несколько программ в один лаунчер (все запускаются открыто)."""
    key = secrets.token_bytes(32)
    payloads = [(_encrypt_blob(src, cipher, key), interp, suffix) for src, interp, suffix in entries]
    dst.write_text(render_launcher(key, payloads, parallel), encoding="utf-8")


def build_standalone(launcher: Path, exe_path: Path) -> None:
    """Собирает самодостаточный исполняемый файл из лаунчера через PyInstaller.

    В результат встраиваются интерпретатор Python и зависимости — на целевой
    машине Python не нужен. Собирается под ТУ ОС, где запущена сборка
    (Linux-сборка не даёт Windows .exe — для .exe собирайте на Windows).
    """
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        raise ValueError("нужен PyInstaller: pip install pyinstaller") from None

    work = Path(tempfile.mkdtemp(prefix="crypter_build_"))
    try:
        subprocess.run(
            [sys.executable, "-m", "PyInstaller", "--onefile", "--clean",
             "--name", exe_path.stem,
             "--distpath", str(work / "dist"), "--workpath", str(work / "build"),
             "--specpath", str(work), str(launcher)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        produced = next((work / "dist").iterdir())   # единственный файл в dist
        exe_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(produced), str(exe_path))
    except subprocess.CalledProcessError as e:
        raise ValueError(f"PyInstaller не справился:\n{e.stderr.strip()}") from None
    finally:
        shutil.rmtree(work, ignore_errors=True)


def sign_executable(exe_path: Path, pfx: Path, password: str | None) -> None:
    """Подписывает .exe ВАШИМ сертификатом (.pfx) через signtool (только Windows).

    Сертификат нужно получить самому: купить в центре сертификации для публичной
    раздачи или сделать самоподписанный для своих машин. Подпись лишь подтверждает
    автора — это не связано с шифрованием содержимого.
    """
    signtool = shutil.which("signtool")
    if not signtool:
        raise ValueError("signtool не найден (ставится с Windows SDK); подпись доступна только на Windows")
    if not pfx.is_file():
        raise ValueError(f"файл сертификата не найден: {pfx}")
    cmd = [signtool, "sign", "/fd", "SHA256", "/f", str(pfx),
           "/tr", "http://timestamp.digicert.com", "/td", "SHA256"]
    if password:
        cmd += ["/p", password]
    cmd.append(str(exe_path))
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
        raise ValueError(f"signtool не смог подписать:\n{e.stderr.strip()}") from None


# --- Интерфейс --------------------------------------------------------------

def ask_password(confirm: bool) -> str:
    env = os.environ.get("CRYPTER_PASSWORD")
    if env:
        return env
    while True:
        pw = getpass.getpass("Пароль: ")
        if not pw:
            print("Пароль не может быть пустым.")
            continue
        if confirm and getpass.getpass("Повторите пароль: ") != pw:
            print("Пароли не совпадают, попробуйте ещё раз.")
            continue
        return pw


def check_output(dst: Path, force: bool) -> None:
    if dst.exists() and not force:
        sys.exit(f"Ошибка: {dst} уже существует (используйте --force для перезаписи)")


def default_decrypt_name(src: Path) -> Path:
    if src.suffix == ".enc":
        return src.with_suffix("")
    return src.with_name(src.name + ".dec")


def cmd_list(_args=None) -> None:
    print("Хеши:")
    for name, desc in HASH_ALGORITHMS.items():
        print(f"  {name:<10} {desc}")
    print("Шифры (encrypt — ключ из пароля через scrypt; pack — случайный ключ в лаунчере):")
    for name, (_, _, desc) in CIPHERS.items():
        print(f"  {name:<10} {desc}")


def cmd_hash(args) -> None:
    algorithms = list(HASH_ALGORITHMS) if args.all else (args.algorithm or ["sha256"])
    for name, digest in hash_file(args.file, algorithms).items():
        print(f"{name:<10} {digest}")


def cmd_encrypt(args) -> None:
    dst = args.output or args.file.with_name(args.file.name + ".enc")
    check_output(dst, args.force)
    encrypt_file(args.file, dst, ask_password(confirm=True), args.algorithm)
    print(f"Зашифровано ({CIPHERS[args.algorithm][2]}): {dst}")


def cmd_decrypt(args) -> None:
    dst = args.output or default_decrypt_name(args.file)
    check_output(dst, args.force)
    try:
        cipher = decrypt_file(args.file, dst, ask_password(confirm=False))
    except ValueError as e:
        sys.exit(f"Ошибка: {e}")
    print(f"Расшифровано ({CIPHERS[cipher][2]}): {dst}")


def resolve_interpreter(args_file: Path, interpreter: str | None):
    """Определяет, чем запускать payload.

    Возвращает (interp, суффикс), где interp:
      None       — Python-payload, выполняется в самом процессе лаунчера
                    (не нужен внешний Python, ничего не пишется на диск);
      []         — запуск напрямую как исполняемого файла (через temp-файл);
      [команда]  — запуск внешним интерпретатором (node/java/…), через temp-файл.
    interpreter='auto' → по расширению: .py в процессе, остальное напрямую.
    """
    suffix = args_file.suffix
    if interpreter in (None, "auto"):
        return (None, ".py") if suffix == ".py" else ([], suffix)
    if interpreter == "none":
        return [], suffix
    return [interpreter], suffix


def cmd_pack(args) -> None:
    interp, suffix = resolve_interpreter(args.file, args.interpreter)
    if interp is None:
        how = "в процессе лаунчера (Python) "
    elif interp:
        how = " ".join(interp) + " "
    else:
        how = "напрямую "

    if args.standalone:
        exe = args.output or args.file.with_name(args.file.stem + "_app")
        if sys.platform == "win32" and exe.suffix.lower() != ".exe":
            exe = exe.with_suffix(".exe")   # на Windows без .exe файл не запустится
        check_output(exe, args.force)
        # Лаунчер — это временный промежуточный файл: собираем из него exe.
        with tempfile.TemporaryDirectory(prefix="crypter_pack_") as tmp:
            launcher = Path(tmp) / (args.file.stem + "_packed.py")
            pack_file(args.file, launcher, args.algorithm, interp, suffix)
            print("Собираю standalone через PyInstaller (это займёт минуту)...")
            try:
                build_standalone(launcher, exe)
            except ValueError as e:
                sys.exit(f"Ошибка: {e}")
        print(f"Готов самодостаточный файл ({CIPHERS[args.algorithm][2]}): {exe}")
        print(f"На целевой машине Python НЕ нужен. Собрано под: {sys.platform}.")
        if args.sign:
            try:
                sign_executable(exe, args.sign, args.sign_password)
                print(f"Подписано сертификатом: {args.sign}")
            except ValueError as e:
                sys.exit(f"Ошибка подписи: {e}")
    else:
        dst = args.output or args.file.with_name(args.file.stem + "_packed.py")
        check_output(dst, args.force)
        pack_file(args.file, dst, args.algorithm, interp, suffix)
        print(f"Упаковано ({CIPHERS[args.algorithm][2]}): {dst}")
        print("Для запуска нужен Python с библиотекой cryptography "
              "(для машины без Python добавьте --standalone).")

    print(f"Запуск payload: {how}(аргументы передаются насквозь)")
    print("Напоминание: ключ вшит внутрь — это обфускация, а не стойкая защита.")


def cmd_bundle(args) -> None:
    entries = []
    for f in args.files:
        interp, suffix = resolve_interpreter(f, args.interpreter)
        entries.append((f, interp, suffix))
    dst = args.output or args.files[0].with_name(args.files[0].stem + "_bundle.py")
    check_output(dst, args.force)
    bundle_files(entries, dst, args.algorithm, args.parallel)
    mode = "параллельно (сразу все)" if args.parallel else "по очереди"
    print(f"Объединено программ: {len(entries)} ({CIPHERS[args.algorithm][2]})")
    print(f"Все запускаются открыто, {mode}: {dst}")
    for f in args.files:
        print(f"  • {f.name}")
    if args.standalone:
        exe = dst.with_name(dst.stem.replace("_bundle", "") + "_app")
        if sys.platform == "win32" and exe.suffix.lower() != ".exe":
            exe = exe.with_suffix(".exe")
        print("Собираю standalone через PyInstaller...")
        try:
            build_standalone(dst, exe)
        except ValueError as e:
            sys.exit(f"Ошибка: {e}")
        dst.unlink(missing_ok=True)
        print(f"Готов самодостаточный файл: {exe} (Python на целевой машине не нужен)")
    print("Напоминание: ключ вшит внутрь — это обфускация, а не стойкая защита.")


def choose(prompt: str, options: list[str]) -> str:
    for i, opt in enumerate(options, 1):
        print(f"  {i}. {opt}")
    while True:
        answer = input(f"{prompt} [1-{len(options)}]: ").strip()
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1]
        print("Неверный выбор.")


def ask_file() -> Path:
    while True:
        path = Path(input("Путь к файлу: ").strip().strip("'\"")).expanduser()
        if path.is_file():
            return path
        print("Файл не найден.")


def interactive() -> None:
    print("=== Crypter ===")
    action = choose("Действие", ["Хешировать", "Зашифровать", "Расшифровать",
                                  "Упаковать в исполняемый лаунчер",
                                  "Объединить несколько программ", "Список алгоритмов"])
    if action == "Список алгоритмов":
        cmd_list()
        return
    if action == "Объединить несколько программ":
        files = []
        print("Указывайте файлы по одному, пустая строка — закончить (минимум 2).")
        while True:
            raw = input(f"Файл #{len(files) + 1} (Enter — готово): ").strip().strip("'\"")
            if not raw:
                if len(files) >= 2:
                    break
                print("Нужно минимум два файла.")
                continue
            path = Path(raw).expanduser()
            if path.is_file():
                files.append(path)
            else:
                print("Файл не найден.")
        alg = choose("Шифр", list(CIPHERS))
        parallel = choose("Запуск", ["По очереди", "Все сразу"]) == "Все сразу"
        cmd_bundle(argparse.Namespace(files=files, output=None, force=False,
                                      algorithm=alg, interpreter="auto",
                                      parallel=parallel, standalone=False))
        return
    file = ask_file()
    ns = argparse.Namespace(file=file, output=None, force=False, all=False,
                            interpreter="auto", standalone=False)
    if action == "Хешировать":
        alg = choose("Алгоритм", list(HASH_ALGORITHMS) + ["все сразу"])
        ns.all = alg == "все сразу"
        ns.algorithm = None if ns.all else [alg]
        cmd_hash(ns)
    elif action == "Зашифровать":
        ns.algorithm = choose("Шифр", list(CIPHERS))
        cmd_encrypt(ns)
    elif action == "Упаковать в исполняемый лаунчер":
        ns.algorithm = choose("Шифр", list(CIPHERS))
        target = choose("Цель", ["Лаунчер .py (на машине нужен Python)",
                                 "Самодостаточный файл (Python не нужен)"])
        ns.standalone = target.startswith("Само")
        cmd_pack(ns)
    else:
        cmd_decrypt(ns)


def existing_file(value: str) -> Path:
    path = Path(value)
    if not path.is_file():
        raise argparse.ArgumentTypeError(f"файл не найден: {value}")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Хеширование и шифрование файлов.")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="показать доступные алгоритмы").set_defaults(func=cmd_list)

    p = sub.add_parser("hash", help="посчитать хеш файла")
    p.add_argument("file", type=existing_file)
    p.add_argument("-a", "--algorithm", action="append", choices=HASH_ALGORITHMS,
                   help="алгоритм (можно указать несколько раз), по умолчанию sha256")
    p.add_argument("--all", action="store_true", help="все алгоритмы сразу")
    p.set_defaults(func=cmd_hash)

    for name, func, help_text in [("encrypt", cmd_encrypt, "зашифровать файл паролем"),
                                  ("decrypt", cmd_decrypt, "расшифровать файл")]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("file", type=existing_file)
        p.add_argument("-o", "--output", type=Path, help="куда сохранить результат")
        p.add_argument("-f", "--force", action="store_true", help="перезаписать существующий файл")
        if name == "encrypt":
            p.add_argument("-a", "--algorithm", choices=CIPHERS, default="aes-gcm",
                           help="шифр (по умолчанию aes-gcm)")
        p.set_defaults(func=func)

    p = sub.add_parser("pack", help="упаковать файл в самозапускающийся .py-лаунчер")
    p.add_argument("file", type=existing_file)
    p.add_argument("-o", "--output", type=Path, help="куда сохранить лаунчер (по умолчанию <имя>_packed.py)")
    p.add_argument("-f", "--force", action="store_true", help="перезаписать существующий файл")
    p.add_argument("-a", "--algorithm", choices=CIPHERS, default="aes-gcm",
                   help="шифр (по умолчанию aes-gcm)")
    p.add_argument("-i", "--interpreter", default="auto",
                   help="чем запускать payload: auto (по расширению), none (напрямую) "
                        "или команда, например python3/node/java")
    p.add_argument("-s", "--standalone", action="store_true",
                   help="собрать самодостаточный исполняемый файл (Python на целевой машине не нужен; "
                        "требует pyinstaller, собирается под текущую ОС)")
    p.add_argument("--sign", type=Path, metavar="PFX",
                   help="подписать собранный .exe вашим сертификатом .pfx (только Windows, с --standalone)")
    p.add_argument("--sign-password", help="пароль к .pfx (можно не указывать для интерактивного ввода signtool)")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("bundle", help="объединить несколько программ в один лаунчер (все запускаются открыто)")
    p.add_argument("files", nargs="+", type=existing_file, help="две или более программы")
    p.add_argument("-o", "--output", type=Path, help="куда сохранить результат")
    p.add_argument("-f", "--force", action="store_true", help="перезаписать существующий файл")
    p.add_argument("-a", "--algorithm", choices=CIPHERS, default="aes-gcm",
                   help="шифр (по умолчанию aes-gcm)")
    p.add_argument("-i", "--interpreter", default="auto",
                   help="чем запускать программы: auto (по расширению), none (напрямую) или команда")
    p.add_argument("-p", "--parallel", action="store_true",
                   help="запускать все программы сразу (по умолчанию — по очереди)")
    p.add_argument("-s", "--standalone", action="store_true",
                   help="собрать самодостаточный исполняемый файл (Python на целевой машине не нужен)")
    p.set_defaults(func=cmd_bundle)

    args = parser.parse_args()
    try:
        if args.command is None:
            interactive()
        else:
            args.func(args)
    except KeyboardInterrupt:
        sys.exit("\nОтменено.")


if __name__ == "__main__":
    main()
