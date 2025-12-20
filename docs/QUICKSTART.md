# TRE V4.0 - Quick Start Guide

**Get started in 60 seconds!**

---

## GUI Quick Start (V4.0)

### Launch GUI
```bash
cd build
./tre-gui
```

### Encrypt a File
1. **Select File**: Drag & drop or click "Browse"
2. **Enter Password**: Must meet requirements (16+ chars, mixed case, digits, symbols)
3. **Click "ENCRYPT"**: Wait for success message
4. **Output**: `filename.tre` created in same directory

### Decrypt a File
1. **Select `.tre` File**: Drag & drop or browse
2. **Enter Password**: Same password used for encryption
3. **Click "DECRYPT"**: Original file restored
4. **Output**: Original file with original extension

---

## Installation

### Step 1: Install Dependencies
```bash
chmod +x scripts/install_dependencies.sh
sudo ./scripts/install_dependencies.sh
```

### Step 2: Build
```bash
mkdir -p build && cd build
cmake ..
make
# Binary is now at: build/tre
```

### Step 3: Move Binary (Optional)
```bash
sudo cp tre /usr/local/bin/
```

---

## Basic Usage

### Encrypt Any File
```bash
tre encrypt photo.jpg
# Creates: photo.tre
```

### Encrypt with Compression (NEW in V4.0!)
```bash
# Balanced compression (recommended)
tre encrypt document.pdf --compress

# Fast compression
tre encrypt video.mp4 --compress-fast

# Maximum compression (smaller files)
tre encrypt logs.txt --compress-max

# Ultra compression (best ratio)
tre encrypt database.sql --compress-ultra
```

### Decrypt (automatic decompression)
```bash
tre decrypt photo.tre
# Restores: photo.jpg (auto-detects compression)
```

### Custom Output
```bash
tre encrypt video.mp4 secure.tre --compress
tre decrypt secure.tre restored.mp4
```

---

## Password Requirements

- Minimum 16 characters
- At least 2 uppercase letters
- At least 2 lowercase letters
- At least 2 digits
- At least 2 symbols
- Not in common password blacklist

**Example:** `MyUltraS3cur3P@ssw0rd!!`

---

## Supported File Types

**ALL file types supported:**
- Documents: PDF, DOCX, TXT, MD
- Images: JPG, PNG, GIF, SVG
- Videos: MP4, AVI, MKV
- Archives: ZIP, TAR, GZ
- And literally any other file!

---

## Troubleshooting

### Build fails?
```bash
# Make sure dependencies are installed
sudo ./scripts/install_dependencies.sh

# Try clean build
rm -rf build && mkdir build && cd build
cmake .. && make
```

### Permission denied?
```bash
chmod +x tre
# Or move to system path
sudo cp tre /usr/local/bin/
```

---

## Advanced

### Verbose Output
```bash
tre encrypt file.zip --compress --verbose
```

### Compression Comparison
```bash
# Create copies to compare
cp data.txt test1.txt test2.txt test3.txt

# Encrypt with different levels
tre encrypt test1.txt out1.tre                 # No compression
tre encrypt test2.txt out2.tre --compress-fast # Fast
tre encrypt test3.txt out3.tre --compress-max  # Maximum

# Compare sizes
ls -lh out*.tre
```

### Batch Encryption
```bash
for file in *.pdf; do
    tre encrypt "$file" --compress
done
```

---

**Need help?** Check the full README.md
