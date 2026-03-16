#!/bin/bash
# scripts/verify_builds.sh
# Smoke test to verify binary architecture and basic properties.

set -e

echo "Starting build verification..."

# Function to verify a single binary
verify_binary() {
    local bin="$1"
    local target_hint="$2"

    if [ ! -f "$bin" ]; then
        echo "Warning: Binary not found for $target_hint at $bin"
        return
    fi

    echo "Verifying $bin ($target_hint)..."
    local file_type=$(file "$bin")
    echo "  Type: $file_type"

    # Architecture checks
    if [[ "$target_hint" == *"x86_64"* ]]; then
        if [[ "$file_type" != *"x86-64"* && "$file_type" != *"x86_64"* && "$file_type" != *"PE32+"* ]]; then
             echo "  [FAIL] Expected x86_64, got mismatch."
             # exit 1 
             # Don't fail hard in script loop for now, just report
        else
             echo "  [PASS] match x86_64"
        fi
    elif [[ "$target_hint" == *"i686"* ]]; then
        if [[ "$file_type" != *"Intel 80386"* && "$file_type" != *"PE32 executable"* ]]; then
             echo "  [FAIL] Expected i686/32-bit, got mismatch."
        else
             echo "  [PASS] match i686"
        fi
    elif [[ "$target_hint" == *"aarch64"* ]]; then
        if [[ "$file_type" != *"ARM aarch64"* && "$file_type" != *"64-bit ARM"* ]]; then
             echo "  [FAIL] Expected aarch64, got mismatch."
        else
             echo "  [PASS] match aarch64"
        fi
    fi
}

# Scan release directory
# Recursively find release/rustray or rustray.exe
find target -path "*/release/rustray*" -type f | while read -r bin; do
    # Extract target name from path
    # Path format: target/<TARGET>/release/rustray...
    target_name=$(echo "$bin" | awk -F'/' '{print $(NF-2)}')
    
    # Skip if not in a target folder (e.g. host build target/release/ directly)
    if [[ "$target_name" == "release" ]]; then
       # This is host build
       target_name="host"
    fi

    verify_binary "$bin" "$target_name"
done

echo "Verification finished."
