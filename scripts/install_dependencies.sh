#!/bin/bash

# Universal Dependency Installer for TRE
# Supports: Debian/Ubuntu, Fedora/RHEL, Arch/Manjaro, openSUSE, Alpine, macOS

set -e

echo "🔍 Detecting Operating System..."

# Check for macOS
if [[ "$(uname)" == "Darwin" ]]; then
    echo "✅ Detected: macOS"
    
    if ! command -v brew &> /dev/null; then
        echo "❌ Homebrew not found. Please install Homebrew first:"
        echo "   /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
        exit 1
    fi
    
    echo "📦 Installing dependencies via Homebrew..."
    brew install cmake libsodium zstd qt@6
    
    echo ""
    echo "✅ Dependencies installed successfully!"
    echo "   Set Qt6 path with:"
    echo "   export CMAKE_PREFIX_PATH=\"\$(brew --prefix qt@6)\""
    echo ""
    echo "   Then build with:"
    echo "   ./scripts/build_macos.sh"
    exit 0
fi

# Linux detection
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    ID=$ID
else
    echo "❌ Cannot detect OS. Please install dependencies manually."
    exit 1
fi

echo "✅ Detected: $OS ($ID)"

install_debian() {
    echo "📦 Installing dependencies for Debian/Ubuntu..."
    sudo apt-get update
    sudo apt-get install -y build-essential cmake libsodium-dev libzstd-dev qt6-base-dev libqt6svg6-dev git
}

install_fedora() {
    echo "📦 Installing dependencies for Fedora/RHEL..."
    sudo dnf install -y gcc-c++ cmake libsodium-devel libzstd-devel qt6-qtbase-devel qt6-qtsvg-devel git
}

install_arch() {
    echo "📦 Installing dependencies for Arch Linux..."
    sudo pacman -S --noconfirm base-devel cmake libsodium zstd qt6-base qt6-svg git
}

install_suse() {
    echo "📦 Installing dependencies for openSUSE..."
    sudo zypper install -y gcc-c++ cmake libsodium-devel libzstd-devel qt6-base-devel qt6-svg-devel git
}

install_alpine() {
    echo "📦 Installing dependencies for Alpine Linux..."
    sudo apk add build-base cmake libsodium-dev zstd-dev qt6-qtbase-dev qt6-qtsvg-dev git
}

case "$ID" in
    ubuntu|debian|kali|pop|linuxmint)
        install_debian
        ;;
    fedora|rhel|centos|almalinux|rocky)
        install_fedora
        ;;
    arch|manjaro|endeavouros)
        install_arch
        ;;
    opensuse*|sles)
        install_suse
        ;;
    alpine)
        install_alpine
        ;;
    *)
        echo "⚠️  Unknown distribution: $ID"
        echo "   Please manually install: g++, cmake, libsodium, zstd, Qt6"
        exit 1
        ;;
esac

echo ""
echo "✅ Dependencies installed successfully!"
echo "   You can now build TRE with:"
echo "   ./scripts/build_linux.sh"
