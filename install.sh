#!/bin/bash
set -e

# RustRay Installation Script
# This script builds and installs the RustRay binary.

echo "Starting RustRay installation..."

# Check for Rust toolchain
if ! command -v cargo &> /dev/null; then
    echo "Error: Rust toolchain (cargo) is not installed."
    echo "Please install Rust from https://rustup.rs/"
    exit 1
fi

# Build the project in release mode
echo "Building RustRay in release mode..."
cargo build --release

# Define installation paths
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="rustray"
SOURCE_BINARY="target/release/$BINARY_NAME"

# Check if build was successful
if [ ! -f "$SOURCE_BINARY" ]; then
    echo "Error: Build failed. Binary not found at $SOURCE_BINARY"
    exit 1
fi

# Install the binary
echo "Installing $BINARY_NAME to $INSTALL_DIR..."
if [ -w "$INSTALL_DIR" ]; then
    cp "$SOURCE_BINARY" "$INSTALL_DIR/"
else
    echo "Requesting sudo permissions to copy binary to $INSTALL_DIR"
    sudo cp "$SOURCE_BINARY" "$INSTALL_DIR/"
fi

# Verify installation
if command -v $BINARY_NAME &> /dev/null; then
    echo "RustRay successfully installed!"
    echo "Version: $($BINARY_NAME --version 2>/dev/null || echo 'Unknown')"
else
    echo "Warning: Installation completed, but $BINARY_NAME is not in your PATH."
fi

echo "Installation complete."
