# Common engine input for SaBRe

The native producer consumes the core package's installed schema2
`engine-artifact.json`. Required core roles are exactly `engine`, `header` and
`native_header`: one `libhermit_inguest_engine.so` and both matching headers.
The core manifest binds the real Cargo units, profile/features and signed H
commit/tree plus R commit. The frontend compares these with its measured core
compatibility stamp and exact dependency pins. Neither a pathname nor an ABI
version supplies source identity.

`produce.py` requires explicit core source, engine artifact, patching revision,
Cargo metadata, actual loader build events, sole target, fresh native output
and fresh installation destination. Run it only within the project's normal
allocated build/resource wrapper. It refuses dirty/uncommitted source or a
partial existing destination. It copies/rechecks the same engine manifest and
all three core roles before linking the C-only shim against the engine's final
absolute installed path, then installs the actual pinned loader and writes
`cohort.json` last. No second Rust Detcore/runtime is built into the shim.

Set `HERMIT_SABRE_COHORT` to that exact absolute canonical `cohort.json` for
`hermit-sabre`. The runtime requires envelope schema2, hashes/holds all files,
checks the shim's exact engine `DT_NEEDED` and required saved-frame exports,
and rechecks visible/held identity after both successful and failed teardown.
A completed cohort must stay at its installed path; relocation is not an
implicit new admission. Old schema1 envelopes and legacy Rust runtime links
refuse. Installation does not qualify loader behavior, Tool callbacks, private
phases or native lifecycle.

Publication checks the engine and shim as one dependency closure. Both must
record no RPATH or RUNPATH, require only glibc symbol versions through 2.34,
and depend only on libraries glibc provides. The shim additionally needs the
exact absolute held engine path once; that edge does not excuse dependencies
of the engine itself. `libgcc_s.so.1` remains a refusal.

The installed source/role checks and loader contract can be repeated with:

```sh
python3 hermit-patching-cli/native/verify.py --core-source /path/to/core \
    --cohort /path/to/installed/cohort.json
```

The explicit core and patching sources must be the committed revisions that
produced the cohort. The verifier checks the actual role hashes, source
records and held engine/shim ELF objects; it does not execute a guest.

`hermit-e9patch` continues preprocessing followed by the same core ptrace
runtime; it does not preload this DSO. Both static frontends now connect
SavedVerification to the existing core-owned capture/publication/comparison
path. Real Saved, native and CLI qualification remains UNRUN.
