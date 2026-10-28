# Patching cross-backend corpus ownership

This extension owns the existing `e9patch` and `sabre` rows of the Reverie
example corpus. The core retains the single generic `reverie-e2e-compare`
implementation and full `reverie-examples/e2e/corpus.tsv`; it already accepts an
explicit recorder path and backend names. This extension supplies
`patching-recorder` and the two backend-specific expected-mismatch records.

The 23-program R882 corpus gives 46 backend/program identities here. None was
executed during source transfer. The saved CentOS 9/glibc 2.34 rows are frozen
prior measurements, not evidence that a new source or artifact cohort passes.
All source row fields and issue URLs remain exact.

The maintained `run.sh` requires both `--core-comparator ELF` and
`--core-e2e-dir DIR`, with no PATH or sibling fallback. They identify the actual
core comparator and its complete corpus directory. The caller must bind their
source/artifact identities, along with the extension, before execution. The
script builds this repository's `patching-recorder` and normal SaBRe example
plugin/loader. A refused backend remains a refusal, and an environment without
a matching ledger is explicitly report-only.

Final exact source pins and normal build/loader qualification are still
required; the baseline pin does not yet expose the new core APIs. No copied
comparator, shorter corpus, changed 300-second per-record deadline, widened
alignment or freshly invented ledger is introduced by this transfer. The
core comparator's existing late-start classification and stale-row rejection
continue to own these two backend names. No current corpus cell has run.
