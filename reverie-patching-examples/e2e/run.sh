#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# Prepare this repository's recorder and physical inputs. All comparison,
# timeout, alignment and ledger-staleness policy stays in the core comparator.
set -uo pipefail

usage() {
    cat <<'EOF'
usage: reverie-patching-examples/e2e/run.sh
         --core-comparator ELF --core-e2e-dir DIR
         [--backends e9patch,sabre] [--environment NAME] [--artifacts DIR]
         [--report-only] [--write-ledger FILE]

ELF is the actual core reverie-e2e-compare artifact. DIR is the exact core
reverie-examples/e2e data directory. Both are required; no PATH, sibling or
source-name fallback selects them. The caller must bind the actual source and
artifact identities before execution. Normal Cargo environment applies.

Without a matching ledger the results are reported, not qualified. A named
refused backend is not a passed cell, even when another backend can run.
EOF
}

E2E_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$E2E_DIR/../.." && pwd)"
core_comparator=
core_e2e_dir=
backends=e9patch,sabre
environment=
artifacts=
report_only=0
write_ledger=
while (($#)); do
    case $1 in
        --core-comparator) core_comparator=${2:?--core-comparator needs an ELF}; shift 2 ;;
        --core-e2e-dir) core_e2e_dir=${2:?--core-e2e-dir needs a directory}; shift 2 ;;
        --backends) backends=${2:?--backends needs a list}; shift 2 ;;
        --environment) environment=${2:?--environment needs a name}; shift 2 ;;
        --artifacts) artifacts=${2:?--artifacts needs a directory}; shift 2 ;;
        --report-only) report_only=1; shift ;;
        --write-ledger) write_ledger=${2:?--write-ledger needs a file}; shift 2 ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
if [[ -z $core_comparator || ! -f $core_comparator || ! -x $core_comparator ||
      -z $core_e2e_dir || ! -f $core_e2e_dir/corpus.tsv ]]; then
    usage >&2
    exit 2
fi
# Resolve explicit inputs while still in the caller's directory. Later chdir
# must not select a different relative comparator, corpus, target or ledger.
core_comparator=$(realpath -e -- "$core_comparator") || exit 2
core_e2e_dir=$(realpath -e -- "$core_e2e_dir") || exit 2
target_dir=$(realpath -m -- "${CARGO_TARGET_DIR:-$ROOT_DIR/target}") || exit 2
artifacts=$(realpath -m -- "${artifacts:-$target_dir/e2e}") || exit 2
if [[ -n $write_ledger ]]; then
    write_ledger=$(realpath -m -- "$write_ledger") || exit 2
fi
IFS=, read -r -a requested <<<"$backends"
for backend in "${requested[@]}"; do
    case $backend in
        e9patch | sabre) ;;
        *) printf 'unknown patching backend %s\n' "$backend" >&2; exit 2 ;;
    esac
done
if ((${#requested[@]} == 0)); then
    usage >&2
    exit 2
fi

if [[ -z $environment ]]; then
    os_id=unknown
    os_version=unknown
    if [[ -r /etc/os-release ]]; then
        os_id=$(. /etc/os-release && printf '%s' "${ID:-unknown}")
        os_version=$(. /etc/os-release && printf '%s' "${VERSION_ID:-unknown}")
    fi
    glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null | awk '{ print $2 }')
    environment="$os_id-$os_version-glibc${glibc:-unknown}"
fi

binaries=$target_dir/debug
mkdir -p "$artifacts" || exit 2
say() { printf 'reverie patching e2e: %s\n' "$*"; }
say "environment $environment; backends requested: $backends"
if ! CARGO_TARGET_DIR=$target_dir cargo build --locked --manifest-path "$ROOT_DIR/Cargo.toml" \
    -p reverie-patching-examples -p reverie-sabre-strace --lib --bins; then
    say "build failed"
    exit 2
fi

run_backends=()
refused=()
for backend in "${requested[@]}"; do
    case $backend in
        e9patch) run_backends+=(e9patch) ;;
        sabre)
            loader=$("$binaries/reverie-sabre-strace" --print-sabre 2>/dev/null)
            if [[ -n $loader && -x $loader ]]; then
                export SABRE_BINARY=$loader
                run_backends+=(sabre)
            else
                refused+=("sabre: the SaBRe loader reverie-sabre builds was not found")
            fi
            ;;
    esac
done
for refusal in "${refused[@]}"; do
    say "REFUSED $refusal"
done
if ((${#run_backends[@]} == 0)); then
    say "no requested backend can run on this host"
    exit 1
fi

ledger=$E2E_DIR/ledgers/$environment.tsv
compare=(
    "$core_comparator"
    --recorder "$binaries/patching-recorder"
    --backends "$(IFS=,; printf '%s' "${run_backends[*]}")"
    --corpus "$core_e2e_dir/corpus.tsv"
    --artifacts "$artifacts"
)
if [[ -n $write_ledger ]]; then
    compare+=(--write-ledger "$write_ledger")
fi
if ((report_only == 0)) && [[ -f $ledger ]]; then
    say "judging against ledgers/$environment.tsv"
    compare+=(--expected "$ledger")
else
    if ((report_only == 0)); then
        say "NO LEDGER for environment $environment: verdicts are reported, not judged. Measure one with --write-ledger."
    fi
    compare+=(--report-only)
fi
cd "$ROOT_DIR" || exit 2
"${compare[@]}"
