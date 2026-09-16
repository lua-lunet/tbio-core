#!/bin/sh
# Print the reproducible identity of the vendored TigerBeetle AOF source.
# Paths are sorted and each file's SHA-256 is hashed again, so the result is
# independent of filesystem order and file mtimes.
set -eu

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
root=${1:-"$script_dir/../zig/src"}
test -d "$root" || {
    echo "aof source directory does not exist: $root" >&2
    exit 2
}

(cd "$root" && find . -type f -print | LC_ALL=C sort | while IFS= read -r path; do
    printf '%s  %s\n' "$(sha256sum "$path" | awk '{print $1}')" "$path"
done) | sha256sum | awk '{print $1}'
