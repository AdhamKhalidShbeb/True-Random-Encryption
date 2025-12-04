# Quantum Random Encryption (QRE) - Version 3.0

> **Military-Grade File Encryption with Hardware True-Randomness**



---

## 🎯 What's New in V3.0

### 🔒 **Security Hardening**
- Fixed **6 critical security bugs** discovered during exhaustive audit
- Eliminated timing attack vulnerabilities
- Enhanced memory safety with proper mlock/munlock tracking
- Improved input validation and error handling

### 📁 **Universal File Support**
- **ANY file type** encryption (images, videos, documents, PDFs, archives, etc.)
- Automatic file extension preservation
- Smart output filename generation

### 🐧 **Cross-Distribution Linux Support**
- **Universal installer** for all major distros (Ubuntu, Debian, Fedora, Arch, openSUSE, etc.)
- One-command setup with automatic dependency resolution
- CMake-based build system for maximum compatibility

### ⚡ **Developer Experience**
- Clean project structure (`src/`, `include/`, `scripts/`, `tests/`)
- IDE configuration included (VS Code ready)
- Quick start guide for immediate usage

---

## 🚀 Quick Start

### Installation (Any Linux Distro)

```bash
# 1. Install dependencies (auto-detects your distro)
chmod +x scripts/install_dependencies.sh
sudo ./scripts/install_dependencies.sh

# 2. Build
mkdir -p build && cd build
cmake ..
make

# 3. Done! Binary is ready
./qre encrypt myfile.pdf
```

---

## 💎 Features

### Core Security
- **Hardware True Random Number Generation** (CPU thermal noise, RDRAND, /dev/random) for entropy
- **Argon2id** key derivation (OWASP recommended, 64MB memory, 3 iterations)
- **AES-256-GCM** encryption (NIST approved, hardware accelerated)
- **Built-in authentication** (GCM authenticated encryption)
- **Single-pass encryption** with constant memory usage

### User Protection
- Strong password requirements (16+ chars, mixed case, digits, symbols)
- **1,000 common password blacklist**
- Constant-time validation (timing attack resistant)
- Secure memory handling (mlock + sodium_memzero)
- Automatic secure file deletion after encryption

### File Handling
- Input/output symlink protection
- Path traversal prevention with canonical path checking
- Automatic extension preservation (decrypt to original format)
- Progress bars for large files (>128KB)

---

## 📖 Usage

### Encrypt
```bash
./qre encrypt document.pdf
# Creates: document.qre (original extension preserved internally)
```

### Decrypt
```bash
./qre decrypt document.qre
# Creates: document.pdf (original extension restored!)
```

### With Custom Output
```bash
./qre encrypt photo.jpg encrypted_photo.qre
./qre decrypt encrypted_photo.qre restored_photo.jpg
```

### Verbose Mode
```bash
./qre encrypt file.zip --verbose
```

---

## 🏗️ Project Structure

```
QRE-V3/
├── src/
│   └── Quantum_Random_Encryption.cpp    # Main source
├── include/
│   └── password_blacklist.hpp           # Password blacklist
├── scripts/
│   └── install_dependencies.sh          # Universal installer
├── tests/
│   ├── test_symlink.sh                  # Security tests
│   └── test_output_symlink.sh
├── CMakeLists.txt                       # Build configuration
├── README.md                            # This file
└── QUICKSTART.md                        # Quick reference
```

---

## 🔐 Security Design

### Encryption Process
```
Password + Salt → Argon2id(64MB, 3 iter) → 256-bit AES Key
                  ↓
            Hardware Random Nonce (12 bytes)
                  ↓
         AES-256-GCM Encryption (Hardware Accelerated)
                  ↓
         Ciphertext + Authentication Tag (16 bytes)
```

### File Format V3
```
[Version:1][ExtLen:1][Extension:N][Salt:128][Nonce:12][Ciphertext+GCMTag:N+16]
```

### Hardening Features
- ✅ Compile-time safety checks (`static_assert`)
- ✅ RAII for resource cleanup
- ✅ Constant-time password validation
- ✅ Integer overflow protection
- ✅ Hardware-accelerated encryption (AES-NI)

---

## 🐛 Bug Fixes (V2 → V3)

1. **Critical:** `/dev/urandom` short-read vulnerability
2. **High:** Timing attack in password validation
3. **Medium:** Argument parsing (--verbose treated as filename)
4. **Critical:** nullptr munlock crash in SecurePassword destructor
5. **Low:** Missing stdin error handling
6. **Low:** munlock called after failed mlock

---

## 🌍 Supported Distributions

- ✅ Ubuntu / Debian / Linux Mint
- ✅ Fedora / RHEL / CentOS
- ✅ Arch Linux / Manjaro
- ✅ openSUSE / SUSE
- ✅ Alpine Linux
- ✅ Gentoo
- ✅ Any distro with g++, cmake, libsodium

---

## 📊 Benchmarks

| File Size | Encryption Time | RAM Usage |
|-----------|----------------|-----------|
| 1 MB      | ~0.5s          | Constant  |
| 100 MB    | ~8s            | Constant  |
| 1 GB      | ~80s           | Constant  |

*Constant RAM usage thanks to streaming architecture*

---

## 🤝 Contributing

Found a bug? Have a feature request? Please open an issue!

---

## 📜 License

MIT License - See LICENSE file for details

---

## 🙏 Credits

- **Entropy:** CPU hardware RNG (RDRAND), /dev/hwrng, /dev/random (thermal noise)
- **Crypto:** libsodium (Argon2id, HMAC-SHA256)
- **Security Audit:** Comprehensive review by Antigravity AI

---

**⚠️ Security Disclaimer:** While QRE uses strong cryptography, no encryption is unbreakable. Use strong, unique passwords and keep backups of important data.
