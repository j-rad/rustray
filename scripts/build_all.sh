#!/bin/bash
set -e

# Define targets supported by 'cross' (Linux, Android, Windows-GNU)
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-unknown-linux-musl"
    "i686-unknown-linux-gnu"
    "i686-unknown-linux-musl"
    "x86_64-pc-windows-gnu"
    "i686-pc-windows-gnu"
    "aarch64-linux-android"
    "armv7-linux-androideabi"
    "x86_64-linux-android"
    "i686-linux-android"
)

# Check for cross
if ! command -v cross &> /dev/null; then
    echo "Error: 'cross' is not installed. Please install specific version or use cargo install cross."
    echo "Building natively if possible..."
    BUILD_CMD="cargo"
else
    BUILD_CMD="cross"
fi

echo "Starting generic build matrix using $BUILD_CMD..."

for target in "${TARGETS[@]}"; do
    echo "------------------------------------------------"
    echo "Building target: $target"
    echo "------------------------------------------------"
    $BUILD_CMD build --release --target "$target"
done

# macOS Host Detection for Apple targets
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "------------------------------------------------"
    echo "macOS detected. Building Apple targets..."
    echo "------------------------------------------------"
    cargo build --release --target x86_64-apple-darwin
    cargo build --release --target aarch64-apple-darwin
    cargo build --release --target aarch64-apple-ios
    
    # Create Universal Binary
    echo "Creating Universal Binary (x86_64 + arm64)..."
    mkdir -p target/universal-apple-darwin/release
    lipo -create -output target/universal-apple-darwin/release/rustray \
        target/x86_64-apple-darwin/release/rustray \
        target/aarch64-apple-darwin/release/rustray
fi

echo "Build All verify complete."
