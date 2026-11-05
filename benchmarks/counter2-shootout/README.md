# Counter2 Tool frontend and physical-input ownership

The generic counter2 Tool and benchmark driver remain in Reverie core. This
directory owns the SaBRe/e9patch preparation fragments and physical command /
environment adapters. `prepare.sh` selects their maintained Cargo producers over the complete tracked vendor
sources. Their build scripts validate `REVISION` and use Cargo `OUT_DIR`.
No root `third-party/*` submodule is activated or fetched by this script.

The former root-submodule commands at Reverie
`882c91c02b981f56370a2912f0832b04fefc46ec` were:

```bash
"$root/scripts/backend-submodule.sh" activate sabre
cmake -S "$root/third-party/sabre" -B "$root/target/sabre" \
  -DCMAKE_BUILD_TYPE=Release
cmake --build "$root/target/sabre" --parallel "$jobs"
cargo build --manifest-path "$root/Cargo.toml" --release \
  -p reverie-sabre-strace

"$root/scripts/backend-submodule.sh" activate e9patch
make -C "$root/third-party/e9patch" -j"$jobs" release
```

Those are frozen source history, not commands for the split layout. The
replacement prepares SaBRe through `reverie-sabre-strace` and e9patch through
`reverie-e9patch`, which own the actual vendor build scripts. It also builds
`patching-counter2` and `libreverie_patching_examples.so`. The thin frontend uses
the existing `reverie_examples::tools::counter2::CounterLocal`, prints its real
coordinator totals, and propagates the real process status. SaBRe selects
`counter2-exact`, which embeds that same Tool; its older `counter2` selector is a
different process-local adaptation. The e9patch sealed preload selector remains
`counter2`. `patching-recorder` is a separate frontend.

`run.py` requires an explicit `--core-driver` and its complete
`--core-driver-sha256`; that core script must expose physical-adapter API 1.
It delegates to the single core driver for the unchanged known-green workload
intersection, workload compiler, native calibration, every exit/stdout/nonzero
counter probe, warmups, measurements, and reports. It does not copy or
monkeypatch those algorithms. Pass its normal `--backends`, `--workloads`,
`--target-seconds`, `--repetitions`, `--warmups`, `--timeout-seconds`, `--profile`,
`--output`, and `--seed` options unchanged after the extension inputs.

All physical inputs are explicit absolute paths: `--counter2-bin` names the
actual `patching-counter2` ELF and `--preload` its actual example DSO. Selected
SaBRe additionally requires `--sabre-loader` and `--sabre-plugin`; selected
e9patch requires `--e9tool` and `--e9patch-backend`. Obtain these paths from the
completed maintained Cargo producers and their real build-script/artifact
events, not a guessed `target/third-party` layout. No sibling/PATH or ambient
backend override supplies a missing input. Held regular-file identities and
hashes are recorded as adapter metadata and metadata is rechecked around each
physical command and on completion. The existing core source SHA and manifest
digest remain in the core report. Caller build receipts must still bind the
actual source graph, features and emitted artifacts.

The core Tool API and driver API are source-ready changes; the baseline R882
manifest pins here do not yet expose them. Final signed core pins, real builds,
artifact/loader checks and the full fresh benchmark probes remain required.
The historical known-green manifest is not a result for the split artifacts.
This source port has not run a benchmark or established a performance or
qualification result. It does not qualify the common Detcore engine, its thin
shim, private phases, or a missing/failed cell.
