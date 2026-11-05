#!/usr/bin/env bash
# The SaBRe/e9patch physical inputs and thin core-Tool counter2 frontend.
# Preparing them is not a benchmark or a correctness result.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
requested=${1:-sabre,e9patch}
IFS=, read -r -a backends <<<"$requested"
for backend in "${backends[@]}"; do
    case $backend in
        sabre|e9patch) ;;
        *) printf 'unknown patching producer %s\n' "$backend" >&2; exit 2 ;;
    esac
done

cargo build --locked --manifest-path "$root/Cargo.toml" --release \
    -p reverie-patching-examples --bin patching-counter2 --lib

for backend in "${backends[@]}"; do
    case $backend in
        sabre)
            cargo build --locked --manifest-path "$root/Cargo.toml" --release \
                -p reverie-sabre-strace --bin reverie-sabre-strace --lib
            ;;
        e9patch)
            cargo build --locked --manifest-path "$root/Cargo.toml" --release \
                -p reverie-e9patch
            ;;
        *) printf 'unknown patching producer %s\n' "$backend" >&2; exit 2 ;;
    esac
done
