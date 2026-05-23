#!/usr/bin/env bash
# scripts/git_scrub.sh
# Wipes 'surrealkv' and binary logs from the repository history using git-filter-repo.

set -e

if ! command -v git-filter-repo &> /dev/null; then
    echo "git-filter-repo is required. Please install it: pip install git-filter-repo"
    exit 1
fi

echo "Scrubbing 'surrealkv' and binary logs from git history..."

# Warning: This is a destructive operation.
# We strip paths containing 'surrealkv' and *.log files.
git filter-repo \
  --path surrealkv/ \
  --path-glob '*.log' \
  --path-glob '*.bin' \
  --path-glob '*.dat' \
  --invert-paths \
  --force

echo "History scrub complete. You will need to force-push the repository."
