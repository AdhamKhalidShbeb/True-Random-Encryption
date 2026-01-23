# True Random Encryption (TRE)

> A simple tool to encrypt your files using hardware-generated randomness.

![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-blue)
![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## What is this?

TRE is a small utility I built to help protect files. Most encryption tools use software to generate "random" numbers, but TRE tries to be a bit more thorough by using your CPU's actual hardware (RDRAND) to get true physical randomness.

It's not meant to be a massive enterprise suite—just a reliable, open-source tool for anyone who wants to keep their data private using modern standards.

### Core Features
- **Strong Encryption:** Uses AES-256-GCM to keep your files safe.
- **Hardware Randomness:** Pulls entropy directly from your CPU.
- **Secure Passwords:** Uses Argon2id to protect against brute-force attacks.
- **Optional Compression:** Uses Zstandard to make files smaller before encrypting.
- **Privacy First:** Wipes sensitive data from memory as soon as it's done.

---

## Quick Start

### Building from Source

If you're on **Linux (Ubuntu/Debian)**:
```bash
sudo apt install build-essential cmake qt6-base-dev qt6-declarative-dev libsodium-dev libzstd-dev
```

If you're on **macOS**:
```bash
brew install cmake qt@6 libsodium zstd
```

**To build:**
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Windows
You'll need Visual Studio 2022 and Qt6. I've included a script to help:
```batch
scripts\build_windows.bat
```

---

## How to Use

### Using the GUI
The easiest way is to use the graphical interface. You can just drag and drop a file, type in a password, and you're good to go.

- **Linux & macOS:** Download the latest version from [Releases](https://github.com/AdhamKhalidShbeb/True-Random-Encryption/releases), extract it, and run `tre-gui`.
- **Windows:** Use the installer from the Releases page.

### Using the CLI
If you prefer the terminal, you can use the `tre` command:

```bash
# To encrypt a file
./tre encrypt my_file.pdf

# To decrypt a file
./tre decrypt my_file.tre

# To use compression (makes the file smaller)
./tre encrypt my_file.pdf --compress-ultra
```

**Common Options:**
- `-h, --help`: Show all commands
- `-v, --version`: Show version info
- `--verbose`: Show detailed progress

---

## Security Details

I've tried to follow best practices to keep things secure:
1. **Authenticated Encryption:** I use AEAD (AES-GCM) so the tool can tell if a file has been tampered with.
2. **Memory Safety:** I use `sodium_memzero` to clear passwords from RAM immediately.
3. **Hardened Passwords:** Argon2id is used with 64MB of RAM to make it very difficult for hackers to guess passwords using specialized hardware.

---

## Design Philosophy

This project is an exploration of applied cryptography. The goal isn't to invent new math, but to implement existing, trusted standards in a way that is fast, secure, and easy for anyone to use.

## License

MIT License. Feel free to use it, study it, or improve it!
