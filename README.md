# Crypter

*Read this in other languages: [Русский](README.ru.md)*

A command-line tool for **hashing** and **encrypting** files, and for packing
programs into a self-launching executable. A single Python script with no extra
dependencies beyond [`cryptography`](https://pypi.org/project/cryptography/).

## Features

- Hash a file with several algorithms in a single pass.
- Encrypt/decrypt a file with a password (AEAD, streaming — file size is not limited by memory).
- `pack` — wrap any program into a self-launching `.py` launcher.
- `--standalone` — build a self-contained executable (no Python needed on the target machine).
- `--sign` — sign the built `.exe` with your certificate (Windows).
- `bundle` — combine several programs into one file; all run **openly**.
- Interactive menu when run without arguments.

## Installation

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt      # cryptography; pyinstaller — for --standalone
```

Requires Python 3.10+.

## Usage

### Hashing

```bash
python crypter.py hash file.txt                      # sha256 by default
python crypter.py hash file.txt -a sha256 -a md5     # several algorithms
python crypter.py hash file.txt --all                # all at once
```

Available hashes: `md5`, `sha1`, `sha256`, `sha512`, `sha3_256`, `sha3_512`,
`blake2b`, `blake2s` (md5/sha1 — checksum only).

### Password encryption

```bash
python crypter.py encrypt file.txt                   # -> file.txt.enc (AES-256-GCM)
python crypter.py encrypt file.txt -a chacha20       # ChaCha20-Poly1305
python crypter.py decrypt file.txt.enc               # -> file.txt
```

The key is derived from the password via `scrypt`. The algorithm is stored in the
header, so you don't specify it when decrypting. Corruption or a wrong password is
detected (authenticated encryption). The password can be passed via the
`CRYPTER_PASSWORD` environment variable.

### Packing into a self-launching launcher

```bash
python crypter.py pack myprog.py                     # -> myprog_packed.py (needs Python)
python crypter.py pack myprog.py --standalone        # -> myprog_app (no Python needed)
python crypter.py pack program.exe -i none           # any binary, run directly
python crypter.py pack app.js -i node                # custom interpreter
```

On start the launcher decrypts the program, runs it, passes command-line arguments
through, and returns its exit code. A Python program runs in-process (no temp file);
anything else runs via a temporary file that is deleted after exit.

### Combining programs (bundle)

```bash
python crypter.py bundle prog1.py prog2.exe          # one after another
python crypter.py bundle prog1.py prog2.exe -p       # all at once
python crypter.py bundle prog1.py prog2.py --standalone
```

All programs run **openly**, their output is visible. The resulting exit code is the
highest of the codes (non-zero if any program failed).

### Signing the .exe (Windows)

```bash
python crypter.py pack myprog.py --standalone --sign mycert.pfx --sign-password PASSWORD
```

Requires your `.pfx` certificate and `signtool` (from the Windows SDK). You obtain the
certificate yourself: buy one from a certificate authority for public distribution, or
make a self-signed one for your own machines. Signing confirms the author and removes
SmartScreen/antivirus warnings — it is unrelated to encrypting the contents.

## Building a Windows .exe

PyInstaller builds the file **for the OS it runs on** — there is no cross-compilation.
To get a Windows `.exe`, run `--standalone` on Windows (Python + `pyinstaller` are only
needed on the build machine, not on the target).

## Important: level of protection

- **`encrypt`/`decrypt`** — real encryption: without the password the data cannot be read.
- **`pack`/`bundle` without a password** — this is **obfuscation**, not strong protection:
  the key is embedded in the launcher and a skilled person can extract it. It protects
  against an ordinary user, but not against a reverse engineer.

## License

MIT
