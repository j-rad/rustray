#!/usr/bin/env bash
# scripts/check_large_files.sh
# Fails if any file larger than 5MB is staged or tracked in the repository.

set -e

MAX_SIZE=5242880 # 5MB in bytes

echo "Checking for files larger than 5MB..."

# Find all tracked files larger than 5MB
LARGE_FILES=$(git ls-files | xargs ls -l | awk '$5 > '$MAX_SIZE' {print $9}')

if [ -n "$LARGE_FILES" ]; then
    echo "ERROR: The following files exceed the 5MB size limit:"
    for file in $LARGE_FILES; do
        echo "  - $file"
    done
    echo "Please remove these files or add them to .gitignore."
    exit 1
fi

echo "All files are within the size limit."
exit 0
