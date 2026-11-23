#!/usr/bin/env bash
# Local route: the same validate the hosted workflow runs
# (.github/workflows/validate.yml), step for step, in the same order:
#   1. ptrace/syscall probe (same Python probe as the hosted-probe job)
#   2. pinned core + Reverie checkouts (dependency only)
#   3. Cargo pin grep
#   4. unit tests (hosted scope and skips), then the namespace test
#   5. Python tests, rustfmt, clippy (hosted scope)
# Deliberate local differences, and only these:
#   - The namespace-dependent cache test runs via sudo here exactly as
#     hosted runs it as root, and the 9 overlay_* fixtures are run
#     locally (the hosted sandbox refuses their unshare child exec even
#     as root; that is the recorded hosted residual in validate.yml).
#   - The retained owned-Nextest lane is NOT part of this route: it
#     needs explicit prepared-project inputs (HERMIT_CORE_SOURCE,
#     HERMIT_EXTENSION_ROOT, HERMIT_NEXTEST_PROJECT) that this script
#     does not generate. Run ci/run-owned-nextest.sh directly with
#     those set when that lane is wanted.
#   - Python collection differs deliberately: this route uses find
#     and runs the 10-test tests/e9patch subdirectory corpus, while
#     hosted keeps its top-level tests/*.py guard and installs no
#     pytest, so that corpus does not run hosted.
# This script invokes no hermit binary, so there is no safehermit
# routing to wire; the core checkouts are used only for the pin grep
# and as build sources, exactly as in the hosted workflow.
#
# Usage: bash ci/validate-local.sh
# Isolated core clones are kept under .core/ (owned by this script).
set -euo pipefail
cd "$(dirname "$0")/.."

HERMIT_PIN=${HERMIT_PIN:-795e4d9a7ebf9ed79ef90db40e5cd2a0acdf0126}
REVERIE_PIN=${REVERIE_PIN:-3271496c72233bf5310905a40431ae83e18c1bd9}
CORE_HERMIT=.core/hermit
CORE_REVERIE=.core/reverie

# --- 1. ptrace/syscall probe (mirrors the hosted-probe job) ---
python3 - <<'PY'
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
PTRACE_TRACEME = 0
pid = os.fork()
if pid == 0:
    if libc.ptrace(PTRACE_TRACEME, 0, 0, 0) != 0:
        os._exit(42)
    os._exit(0)
_, status, rusage = os.wait4(pid, 0)
try:
    scope = open("/proc/sys/kernel/yama/ptrace_scope").read().strip()
except FileNotFoundError:
    scope = "(no yama)"
print(f"yama ptrace_scope: {scope}")
if os.WEXITSTATUS(status) == 42:
    print("PTRACE_TRACEME REFUSED on this machine", file=sys.stderr)
    sys.exit(1)
print("ptrace probe: OK")
PY

# --- 2. pinned core checkouts (dependency only, fail-closed) ---
checkout_pin() {
    local path=$1 url=$2 pin=$3 repo=$4
    if [[ -d "$path/.git" ]]; then
        # Compare by repository name: a URL rewrite (e.g. a local mirror)
        # may make the same repository's origin string differ from $url.
        local origin origin_repo
        origin=$(git -C "$path" remote get-url origin)
        origin_repo=$(basename "${origin%.git}")
        if [[ "$origin_repo" != "$repo" ]]; then
            echo "validate-local: $path is a checkout of $origin, expected the $repo repository ($url); refusing" >&2
            exit 2
        fi
        if [[ -n "$(git -C "$path" status --porcelain)" ]]; then
            echo "validate-local: $path is dirty; refusing to mutate it" >&2
            exit 2
        fi
        git -C "$path" fetch --quiet origin "$pin"
        git -C "$path" checkout --quiet "$pin"
    elif [[ -e "$path" ]]; then
        echo "validate-local: $path exists and is not a git checkout; refusing" >&2
        exit 2
    else
        mkdir -p .core
        git clone --quiet "$url" "$path"
        git -C "$path" checkout --quiet "$pin"
    fi
    local head
    head=$(git -C "$path" rev-parse HEAD)
    if [[ "$head" != "$pin" ]]; then
        echo "validate-local: $path is at $head, expected pin $pin" >&2
        exit 2
    fi
}
checkout_pin "$CORE_HERMIT" https://github.com/rrnewton/hermit.git "$HERMIT_PIN" hermit
checkout_pin "$CORE_REVERIE" https://github.com/rrnewton/reverie.git "$REVERIE_PIN" reverie

# --- 3. Cargo pin grep (mirrors hosted) ---
grep -rq "$HERMIT_PIN" --include=Cargo.toml .
grep -rq "$REVERIE_PIN" --include=Cargo.toml .

# --- 4/5. Tests, Python, rustfmt, clippy. Each step is recorded by name
# and the script exits non-zero at the END if any failed, so one red
# crate (e.g. reverie-e9patch not compiling) cannot hide another crate's
# results behind set -e's early exit. Failing steps are reported by name.
FAILURES=()
run_step() {
    local name="$1"; shift
    echo "validate-local: step: $name"
    "$@" || FAILURES+=("$name")
}

run_step "unit tests (cli/e9patch/examples)" cargo test --locked --lib --bins -p hermit-patching-cli -p reverie-e9patch -p reverie-patching-examples -- --skip cache_directory_is_private_and_not_a_symlink --skip overlay_
run_step "reverie-sabre tests" cargo test --locked -p reverie-sabre --lib

CACHE_TEST=e9patch::tests::cache_directory_is_private_and_not_a_symlink
if [[ "$(id -u)" -eq 0 ]]; then
    run_step "namespace cache test" cargo test --locked -p hermit-patching-cli --lib -- --exact "$CACHE_TEST"
    # Local-only: the overlay_* fixtures pass where unshare child exec
    # is permitted (the hosted sandbox refuses it even as root).
    run_step "overlay fixtures" cargo test --locked -p reverie-e9patch --lib -- overlay_
elif sudo -n true 2>/dev/null; then
    run_step "namespace cache test" sudo env "PATH=$PATH" "CARGO_HOME=${CARGO_HOME:-$HOME/.cargo}" "RUSTUP_HOME=${RUSTUP_HOME:-$HOME/.rustup}" cargo test --locked -p hermit-patching-cli --lib -- --exact "$CACHE_TEST"
    run_step "overlay fixtures" cargo test --locked -p reverie-e9patch --lib -- overlay_
else
    echo "validate-local: the namespace test needs root or passwordless sudo (hosted runs it as root)" >&2
    FAILURES+=("namespace cache test (needs root or passwordless sudo)")
fi

if find tests -name '*.py' -print -quit 2>/dev/null | grep -q .; then run_step "python tests" python3 -m pytest tests/ -x -q; fi
# Local-only: this route's own regression tests live in ci/ (the hosted
# runner has no pytest for a tests/ placement; see the file header).
run_step "ci python tests" python3 -m pytest ci/test_validate_local.py -q
run_step "rustfmt" cargo fmt --all -- --check
run_step "clippy (cli/e9patch/examples)" cargo clippy --locked -p hermit-patching-cli -p reverie-e9patch -p reverie-patching-examples -- -D warnings
run_step "reverie-sabre clippy" cargo clippy --locked -p reverie-sabre -- -D warnings

if ((${#FAILURES[@]})); then
    echo "validate-local: FAILED steps:" >&2
    printf '  - %s\n' "${FAILURES[@]}" >&2
    exit 1
fi
echo "validate-local: OK (hosted-mirrored steps; owned-Nextest retained lane not included)"
