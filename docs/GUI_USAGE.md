# TRE GUI - Usage Guide

## Quick Start

### Build the Application
```bash
cd "/mnt/VMDrive/Programming Projects/True Random Encryption (TRE)"
cmake .
make -j$(nproc)
```

### Run the GUI
```bash
./tre-gui
```

---

## How to Use

### Encrypting a File

1.  **Launch the GUI**
    ```bash
    ./tre-gui
    ```

2.  **Select Input File**
    - **Option A**: Drag & drop a file into the window
    - **Option B**: Click the "Browse" button and select a file

3.  **Enter Password**
    - Type a strong password in the password field
    - Password must meet these requirements:
      - Minimum 16 characters
      - At least 2 uppercase letters (A-Z)
      - At least 2 lowercase letters (a-z)
      - At least 2 digits (0-9)
      - At least 2 symbols (!@#$%^&*)
    - **Example**: `MySecurePass123!@#`

4.  **Toggle Password Visibility (Optional)**
    - Click the Show button to show/hide your password

5.  **Click "ENCRYPT"**
    - The "ENCRYPT" button will process your file
    - A progress bar will appear
    - Wait for the success message

6.  **Find Your Encrypted File**
    - Output file: `original_filename.tre`
    - Located in the same directory as the input file

---

### Decrypting a File

1.  **Launch the GUI**
    ```bash
    ./tre-gui
    ```

2.  **Select Encrypted File**
    - Browse or drag & drop the `.tre` file

3.  **Enter Password**
    - Type the SAME password used during encryption

4.  **Click "DECRYPT"**
    - The "DECRYPT" button will restore your file
    - Wait for the success message

5.  **Find Your Decrypted File**
    - Original file is restored with its original extension
    - Example: `document.tre` → `document.pdf`

---

## GUI Features

### Modern Enterprise Theme
- **Dark background** for comfortable viewing
- **Blue accents** for primary actions
- **High contrast** text for readability

### User-Friendly Design
- **Drag & Drop**: Simply drag files into the window
- **Password Visibility Toggle**: Show/hide password with Show button
- **Real-time Feedback**: Status messages and progress indicators
- **Error Handling**: Clear error messages for invalid passwords or corrupted files

---

## Common Issues

### "Password is too weak" Error
**Solution**: Make sure your password meets ALL requirements:
- At least 16 characters long
- Contains 2+ uppercase, 2+ lowercase, 2+ digits, 2+ symbols

### "Decryption failed" Error
**Possible causes**:
1. Wrong password
2. Corrupted `.tre` file
3. File is not a valid TRE encrypted file

**Solution**: Double-check your password and ensure the file wasn't modified

### GUI doesn't launch
**Solution**:
```bash
# Install Qt6 if not already installed
# Ubuntu/Debian:
sudo apt install qt6-base-dev

# Rebuild
cmake .
make -j$(nproc)
./tre-gui
```

---

## Tips for Best Security

1.  **Use Strong, Unique Passwords**
    - Don't reuse passwords
    - Use a password manager
    - Example good password: `Tr0ub4dor&3_SecureFile!`

2.  **Keep Encrypted Files Safe**
    - Store `.tre` files securely
    - Don't lose your password (it CANNOT be recovered!)

3.  **Verify After Decryption**
    - Always check that decrypted files open correctly
    - Compare file sizes to ensure integrity

4.  **Use Compression for Large Files** (CLI only for now)
    ```bash
    ./tre encrypt largefile.tar --compress
    ```

---

## CLI Alternative

If you prefer command-line usage:

```bash
# Encrypt
./tre encrypt photo.jpg

# Decrypt
./tre decrypt photo.jpg.tre

# With compression
./tre encrypt document.pdf --compress
```

---

## Screenshot Guide

When you launch `./tre-gui`, you'll see:

```
┌─────────────────────────────────────────────┐
│     True Random Encryption                  │
├─────────────────────────────────────────────┤
│                                             │
│  Input File                                 │
│  ┌─────────────────────────┐  ┌─────────┐ │
│  │ Drag & drop or browse...│  │ Browse  │ │
│  └─────────────────────────┘  └─────────┘ │
│                                             │
│  Password                                   │
│  ┌─────────────────────────┐  ┌──────┐    │
│  │ Enter secure password    │  │ Show │    │
│  └─────────────────────────┘  └──────┘    │
│                                             │
│  ┌──────────────┐  ┌──────────────┐       │
│  │   ENCRYPT    │  │   DECRYPT    │       │
│  │              │  │              │       │
│  └──────────────┘  └──────────────┘       │
│                                             │
│  Status: Ready                              │
└─────────────────────────────────────────────┘
```

---

**Need More Help?** Check `README.md` or `QUICKSTART.md`
