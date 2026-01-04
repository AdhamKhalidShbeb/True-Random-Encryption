#!/bin/bash
# macOS Build Script for True Random Encryption
# Requires: Xcode Command Line Tools, CMake, Qt6 (via Homebrew)

set -e

echo "============================================"
echo " True Random Encryption - macOS Build"
echo "============================================"

# Check for required tools
if ! command -v cmake &> /dev/null; then
    echo "ERROR: CMake not found. Install with: brew install cmake"
    exit 1
fi

if ! command -v clang++ &> /dev/null; then
    echo "ERROR: Xcode Command Line Tools not found."
    echo "Install with: xcode-select --install"
    exit 1
fi

# Install dependencies via Homebrew if not present
echo ""
echo "Checking dependencies..."
if ! brew list libsodium &> /dev/null; then
    echo "Installing libsodium..."
    brew install libsodium
fi

if ! brew list zstd &> /dev/null; then
    echo "Installing zstd..."
    brew install zstd
fi

if ! brew list qt@6 &> /dev/null; then
    echo "Installing Qt6..."
    brew install qt@6
fi

# Set Qt6 path for CMake
export Qt6_DIR="$(brew --prefix qt@6)/lib/cmake/Qt6"
export CMAKE_PREFIX_PATH="$(brew --prefix qt@6)"

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
make -j$(sysctl -n hw.ncpu)

cd ..

echo ""
echo "============================================"
echo " Build complete!"
echo " Output: bin/macos/"
echo "============================================"
echo ""
ls -la bin/macos/
