# QRE V4.0 - Quick Start Guide

**Get started in 60 seconds!**

---

## 🎨 GUI Quick Start (V4.0)

### Launch GUI
```bash
cd build
./qre-gui
```

### Encrypt a File
1. **Select File**: Drag & drop or click "Browse"
2. **Enter Password**: Must meet requirements (16+ chars, mixed case, digits, symbols)
3. **Click "ENCRYPT"**: Wait for success message
4. **Output**: `filename.qre` created in same directory

### Decrypt a File
1. **Select `.qre` File**: Drag & drop or browse
2. **Enter Password**: Same password used for encryption
3. **Click "DECRYPT"**: Original file restored
4. **Output**: Original file with original extension

---

## ⚡ Installation

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
# Binary is now at: build/qre
```

### Step 3: Move Binary (Optional)
```bash
sudo cp qre /usr/local/bin/
```

---

## 🎯 Basic Usage

### Encrypt Any File
```bash
qre encrypt photo.jpg
# Creates: photo.qre
```

### Encrypt with Compression (NEW in V4.0!)
```bash
# Balanced compression (recommended)
qre encrypt document.pdf --compress

# Fast compression
qre encrypt video.mp4 --compress-fast

# Maximum compression (smaller files)
qre encrypt logs.txt --compress-max

# Ultra compression (best ratio)
qre encrypt database.sql --compress-ultra
```

### Decrypt (automatic decompression)
```bash
qre decrypt photo.qre
# Restores: photo.jpg (auto-detects compression)
```

### Custom Output
```bash
qre encrypt video.mp4 secure.qre --compress
qre decrypt secure.qre restored.mp4
```

---

## 🔒 Password Requirements

- Minimum 16 characters
- At least 2 uppercase letters
- At least 2 lowercase letters
- At least 2 digits
- At least 2 symbols
- Not in common password blacklist

**Example:** `MyUltraS3cur3P@ssw0rd!!`

---

## 📁 Supported File Types

**ALL file types supported:**
- Documents: PDF, DOCX, TXT, MD
- Images: JPG, PNG, GIF, SVG
- Videos: MP4, AVI, MKV
- Archives: ZIP, TAR, GZ
- And literally any other file!

---

## 🛠️ Troubleshooting

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
chmod +x qre
# Or move to system path
sudo cp qre /usr/local/bin/
```

---

## 🚀 Advanced

### Verbose Output
```bash
qre encrypt file.zip --compress --verbose
```

### Compression Comparison
```bash
# Create copies to compare
cp data.txt test1.txt test2.txt test3.txt

# Encrypt with different levels
qre encrypt test1.txt out1.qre                 # No compression
qre encrypt test2.txt out2.qre --compress-fast # Fast
qre encrypt test3.txt out3.qre --compress-max  # Maximum

# Compare sizes
ls -lh out*.qre
```

### Batch Encryption
```bash
for file in *.pdf; do
    qre encrypt "$file" --compress
done
```

---

**Need help?** Check the full README.md
