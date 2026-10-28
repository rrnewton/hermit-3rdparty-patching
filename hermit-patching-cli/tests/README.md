# SaBRe qualification inputs

`sabre_examples` retains the transferred test IDs, assertions, 45-second
per-attempt wall bound and typed skid-only retry policy. The extension is
`CARGO_BIN_EXE_hermit-sabre` (or explicitly verified
`HERMIT_SABRE_TEST_BINARY`). Every ptrace reference instead requires the
explicit verified core `HERMIT_BIN`; the helper refuses the same canonical
executable for both sides.

`HERMIT_SABRE_COHORT` must name the installed engine/shim/loader cohort. Tests
use the same strict consumer as the production adapter, including source
revisions, content hashes and held file identities. Missing or invalid inputs
refuse rather than making parity tests pass without executing. If the legacy
`HERMIT_SABRE_BINARY` override is present, it must identify that cohort's loader.
No adjacent `libdetcore_sabre.so` or root `target/sabre` fallback is accepted.

The test bodies and real guest work have not run in the source-transfer task.
Compilation needs the final exact core API pins and normal allocated build
route; physical execution needs its separately bounded runner and resources.
