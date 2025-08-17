#!/bin/bash
# RustMapV3 One-Line Installation Script
# This script installs RustMapV3 and ensures ~/.cargo/bin is on PATH

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    error "Rust/Cargo not found. Please install Rust first:"
    echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
    exit 1
fi

info "Found Rust $(rustc --version)"

# Check if git is available
if ! command -v git &> /dev/null; then
    error "Git not found. Please install git first."
    exit 1
fi

# Create temporary directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"

info "Cloning RustMapV3 repository..."
git clone https://github.com/Wael-Rd/RustMapV3.git
cd RustMapV3

info "Building RustMapV3..."
cargo build --release

info "Installing RustMapV3..."
cargo install --path .

# Ensure ~/.cargo/bin is in PATH
CARGO_BIN="$HOME/.cargo/bin"
if [[ ":$PATH:" != *":$CARGO_BIN:"* ]]; then
    warn "~/.cargo/bin is not in PATH. Adding to shell profile..."
    
    # Detect shell and add to appropriate profile
    if [[ "$SHELL" == *"zsh"* ]]; then
        echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.zshrc
        info "Added to ~/.zshrc"
    elif [[ "$SHELL" == *"bash"* ]]; then
        echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc
        info "Added to ~/.bashrc"
    else
        echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.profile
        info "Added to ~/.profile"
    fi
    
    # Export for current session
    export PATH="$CARGO_BIN:$PATH"
fi

# Clean up
cd /
rm -rf "$TEMP_DIR"

info "Installation complete!"
info "Run: RustMapV3 --help"

# Test installation
if command -v RustMapV3 &> /dev/null; then
    info "✓ RustMapV3 successfully installed and available"
    echo ""
    echo "Quick test:"
    echo "  RustMapV3 127.0.0.1 --preset fast --top 10 --no-nmap"
else
    warn "RustMapV3 installed but not found in PATH"
    echo "Please restart your shell or run: source ~/.bashrc (or ~/.zshrc)"
fi