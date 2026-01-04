#!/bin/bash
# Linux Build Script for True Random Encryption
# Requires: CMake, GCC/Clang, libsodium, zstd, Qt6

set -e

echo "============================================"
echo " True Random Encryption - Linux Build"
echo "============================================"

# Check for CMake
if ! command -v cmake &> /dev/null; then
    echo "ERROR: CMake not found. Please install cmake."
    echo "       Run: ./install_dependencies.sh"
    exit 1
fi

# Create build directory
mkdir -p build
cd build

# Configure
echo ""
echo "Configuring with CMake..."
cmake -DCMAKE_BUILD_TYPE=Release ..

# Build
echo ""
echo "Building..."
make -j$(nproc)

cd ..

echo ""
echo "============================================"
echo " Build complete!"
echo " Output: bin/linux/"
echo "============================================"
echo ""
ls -la bin/linux/
