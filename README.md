# Quantum Random Encryption (QRE) - Version 4.0

> **Military-Grade File Encryption with Hardware True-Randomness**



---

## 🎯 What's New in V4.0

### 📦 **Compression Support** (NEW!)
- **4-tier compression** system using Zstandard (zstd)
- **40-50% file size reduction** on text, logs, and code
- Fast, Balanced, Maximum, and Ultra compression levels
- Transparent compression/decompression on encrypt/decrypt
- **Backward compatible** with V3 files

### ✨ **Previous Features (V3.0)**
- ✅ AES-256-GCM encryption (hardware accelerated)
- ✅ Hardware true-randomness (RDRAND, /dev/hwrng, /dev/random)
- ✅ Argon2id key derivation (64MB, 3 iterations)
- ✅ Universal Linux support (all major distros)
- ✅ Any file type encryption with extension preservation

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

### Basic Encryption
```bash
./qre encrypt document.pdf
# Creates: document.qre
```

### Encryption with Compression (NEW!)
```bash
# Fast compression (optimal for speed)
./qre encrypt document.pdf --compress-fast

# Balanced compression (recommended)
./qre encrypt largefile.txt --compress

# Maximum compression (best ratio)
./qre encrypt archive.tar --compress-max

# Ultra compression (maximum ratio, slower)
./qre encrypt database.sql --compress-ultra
```

### Decryption (automatic decompression)
```bash
./qre decrypt document.qre
# Automatically detects and decompresses if needed
```

### With Custom Output & Verbose
```bash
./qre encrypt data.json backup.qre --compress --verbose
./qre decrypt backup.qre restored.json -v
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

### File Format V3 (Enhanced)
```
[Version:1][ExtLen:1][Extension:N][Salt:128][Nonce:12][Ciphertext+GCMTag:N+16][CompFlag:1]
```
*Compression Flag (1 byte) appended at the end. Auto-detected during decryption.*

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
