# Retiring the legacy SaBRe Rust Plugin

The maintained SaBRe executable uses a thin C shim and the shared in-guest
engine. It does not load `libdetcore_sabre.so` or construct the old Rust
`Plugin`. The old interface tests must therefore have an explicit disposition.
This source record does not qualify the new runtime.

The original source is `detcore-sabre/src/lib.rs` at
`1a52541080c50457cbd3b691709885827908d5a6`, SHA256
`ed28c9ec6144554b56b5a255164648ef68bf98643a15243a9d40d9ead8cd6c33`.
It can be regenerated with:

```sh
git show 1a52541080c50457cbd3b691709885827908d5a6:detcore-sabre/src/lib.rs
```

## Controls with maintained production owners

| Original control | Current owner | Qualification |
| --- | --- | --- |
| `initial_generation_accepts_raw_worker_comm_and_rejects_invalid_identity` | Shared `loader_state` parser, including the raw kernel task name and final delimiter | Applied source; next-head test pending |
| `guest_comm_uses_target_basename_and_linux_limit` | Generic SaBRe loader restores the real guest basename through `PR_SET_NAME` before Tool initialization | The maintained C header and real kernel task-name control passed; complete loader/guest build pending |
| `detlog_forwarding_follows_the_coordinators_per_target_policy` | Shared ordinary loader policy decoder, used by the actual install path | Six original assertions retained in the actual shared decoder; next-head test pending |

## Explicitly retired interfaces

### `rpc_socket_uses_sabre_private_environment_namespace`

Legacy private environment namespace. The selected C shim receives loader-owned arguments. The actual common engine admits only its four HERMIT_ENGINE_* settings; the C shim consumes its real statistics descriptor separately. No selected adapter depends on the old Rust Plugin RPC_SOCKET_ENV or DETLOG_FORWARD_ENV keys.

### `registers_libc_getrandom_detour`

Legacy Rust Tool detour registry and C ABI wrapper. The selected sbr_init does not register a Rust Plugin or libc detour. Rewritten guest syscalls enter the common SavedFrames dispatcher. The old registry/function-signature/canary/errno oracle is explicitly retired with that wrapper; actual libc and syscall random behavior still requires the maintained guest tests at a built cohort.

### `rpc_socket_survives_plugin_reinitialization`

Legacy Plugin reconstruction memo. The ordinary engine installs one Tool host per image; begin_installation refuses a repeated initializer and fork inherits the real host/services. There is no selected Rust Plugin constructor that consumes and then reacquires the old private socket environment.

### `coordinator_fingerprint_survives_plugin_reinitialization`

Legacy Plugin reconstruction memo. Fingerprint admission is owned by the actual common engine before configuration decoding. A fork inherits the engine installation and an exec receives fresh loader inputs; no selected Rust Plugin rereads an erased environment variable. The old once-only getter/boolean-return oracle is explicitly retired, without claiming fork or exec qualification.

### `virtual_rdtsc_returns_coordinator_value`

Legacy Result-return wrapper. The C shim emits its real RDTSC instruction under the common engine trap mechanism; current Tool RDTSC handling owns the logical-clock result. The removed require_virtual_rdtsc(Ok(42)) helper test did not execute that mechanism, and is not counted as replacement runtime coverage.

### `recognizes_only_sabre_post_load_bootstrap_random_shape`

Legacy RemoteReverieAdapter post-load hash-seed workaround. The selected C shim initializes the one shared engine while its installer TID is armed, before admitting guest callbacks. Its pre-arm installer route refuses other threads and process creation; the obsolete Plugin no longer classifies the first guest syscall by the 32-byte GRND_NONBLOCK shape. This retires that old discriminator, not the obligation to keep tool-private random draws outside the guest stream.

### `virtual_rdtsc_error_fails_closed`

Legacy Result-return wrapper panic interface. The old expect/panic message belongs only to require_virtual_rdtsc. The maintained engine terminates real Tool/trap failures through its fatal path. No new helper is created solely to reproduce the old panic string; actual failure handling remains a cohort qualification obligation.

## Remaining qualification

No retired helper or exported symbol is recreated solely to preserve a test
name. The actual selected cohort still needs the normal build, ABI and ELF
checks, random and clock behavior, genuine Detcore engagement, and fork/exec
controls. The source dispositions do not turn any pending runtime check green.
