# Ordinary SaBRe shim

`sabre-shim.c` contains only the native saved-frame adapter. Detcore, the
concrete ToolHost, futures, allocator, Tool TLS and runtime services live in the
core `hermit-inguest-engine` DSO. The genuine pinned loader invokes `sbr_init`,
then the post-load entry, then its routed trampoline. The adapter retains the
frame/layout, installer-TID, route, argument and unsupported-IP/SP refusals.

The pinned loader maps and checks its actual statistics page before plugin
initialization, then forwards `REVERIE_SABRE_BACKEND_STATS_FD` to the plugin.
The shim requires exactly one canonical descriptor in the maintained range
101 and above, verifies the real page size/header through that descriptor,
and removes only this loader-owned setting from the engine argument list.
The engine still parses its four settings and refuses unknown, malformed or
duplicate engine keys. No statistics counter or page is manufactured here.

The Makefile consumes the matching engine DSO and `hermit-engine-v1.h` from the
core producer. It does not copy another implementation or build Rust. The
maintained artifact producer still needs to bind and install the engine/header/
shim/loader as one exact cohort; this source staging has not been compiled.
The shim links the engine's exact absolute installed path, without RPATH or
RUNPATH. The engine and shim are checked together against the existing glibc
2.34 floor and glibc-only system dependency policy before publication.

This is ordinary entry only. It exports no private initial/successor/native-exec
authority. Existing private containers and finalizers require separate current
source integration and qualification. The legacy `detcore-sabre` Rust DSO was
removed after its maintained controls moved to their actual owners. See
[the interface dispositions](LEGACY_PLUGIN_RETIREMENT.md); runtime qualification
remains pending.

# Ordinary loader state transport

The shim exports the pinned loader's separate initial-bootstrap and continuation
setters and forwards the loader-owned callback to the common engine before
`sbr_init`. Neither setter parses an address or creates a Rust object. The
loader consumes its bootstrap option before plugin argument parsing; the
engine's four-key parser remains strict. The common engine validates and applies
the existing authenticated state before its shared Tool host is published.

This source port has not been built or exercised. Final qualification must bind
the emitted engine/header/shim/loader cohort, the actual loader negotiation and
the real root callbacks/RPC/finalizer. The legacy Rust plugin's deferred
post-load hash-seed handling is not a substitute for proving this eager,
fixed-allocator engine's initialization and private-entropy boundary. No
private-image or native authority is added here.

# Artifact producer

`produce.py` consumes the explicit neutral core `engine-artifact.json`, its
matching committed core source, completed loader Cargo metadata/JSON events,
and the exact committed patching revision. It selects the actual
`reverie-sabre` build-script output `sabre-build-v4/sabre`, checks the emitted
source identity, and links this C-only shim through this Makefile into a fresh
directory inside the same declared target. It never builds the legacy
`detcore-sabre` Rust DSO, searches PATH for a loader, or executes a guest.

Every argument is required: `--core-source`, `--engine-artifact`,
`--patching-revision`, `--cargo-metadata`, `--loader-events`, `--target-dir`,
`--native-output`, and `--destination`. The loader-producing Cargo selection
is `cargo build --locked --offline --release -p reverie-sabre --lib
--message-format=json-render-diagnostics`; the normal lease, configured-width
budget wrapper, completed raw status and bounded cleanup belong to the caller.
No command is authorized by these source instructions alone.

The installed cohort contains the exact engine, matching header, linked shim,
loader, a source/build provenance record and the last-written `cohort.json`
already required by `HERMIT_SABRE_COHORT`. All input/output copies and source
identities are rechecked; existing or partial destinations refuse. The core
manifest retains its exact three-role schema and exact H/R pins. Actual ELF
dependency/constructor/symbol and loader/Tool/finalizer/resource qualification
remains required; artifact presence is not a runtime result.
