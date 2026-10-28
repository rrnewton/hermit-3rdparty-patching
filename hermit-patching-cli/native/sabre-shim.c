/* C-only adapter for the actual pinned SaBRe routed trampoline ABI.
 * Based on reverie-sabre/{shared_runtime,shared_entry}.rs; the relevant
 * ABI sources are byte-identical at R882c91c0 and the measured prototype.
 * Detcore, Guest, RPC, allocator, futures and the runtime globals live only in
 * libhermit_inguest_engine.so, not in this DSO. */
#define _GNU_SOURCE
#include <hermit-engine-v1.h>
#include "sbr_api_defs.h"
#include "loader/backend_stats.h"
#include <limits.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#ifndef __NX_INTERCEPT_RDTSC
#error "the pinned loader's actual sbr_init ABI includes its RDTSC handler"
#endif

/* vendor/sabre/arch/x86_64/handle_syscall.S push order. The 128-byte red zone
 * is above both returns, not part of this saved block. */
struct sabre_frame {
  uint64_t rbp_stackalign;
  uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
  uint64_t rdi, rsi, rdx, rcx, rbx, rbp_prologue, rflags;
  uint64_t fake_ret, ret;
};

#define OFFSET(field, value) \
  _Static_assert(offsetof(struct sabre_frame, field) == (value), #field)
OFFSET(rbp_stackalign, 0x00);
OFFSET(r15, 0x08); OFFSET(r14, 0x10); OFFSET(r13, 0x18);
OFFSET(r12, 0x20); OFFSET(r11, 0x28); OFFSET(r10, 0x30);
OFFSET(r9, 0x38); OFFSET(r8, 0x40); OFFSET(rdi, 0x48);
OFFSET(rsi, 0x50); OFFSET(rdx, 0x58); OFFSET(rcx, 0x60);
OFFSET(rbx, 0x68); OFFSET(rbp_prologue, 0x70); OFFSET(rflags, 0x78);
OFFSET(fake_ret, 0x80); OFFSET(ret, 0x88);
_Static_assert(sizeof(struct sabre_frame) == 0x90, "native frame size");

static atomic_bool armed = false;
static atomic_long installer_tid = 0;
static int plugin_argc;
static char **plugin_argv;
static char *engine_arguments[65];

/* The pinned loader looks up these two exact, separate entry points before
 * sbr_init. It supplies its own lifetime-stable callback; there is no getenv,
 * address parsing, Rust state or readiness event in this C-only bridge. */
int reverie_sabre_install_loader_bootstrap_v1(engine_take_loader_state_v1 callback) {
  return hermit_engine_install_loader_state_v1(callback);
}

int reverie_sabre_install_loader_continuation_v1(engine_take_loader_state_v1 callback) {
  return hermit_engine_install_loader_state_v1(callback);
}

static long raw(long number, long a0, long a1, long a2,
                long a3, long a4, long a5) {
  return hermit_engine_raw_syscall_v1(number, a0, a1, a2, a3, a4, a5);
}

__attribute__((noreturn))
static void refuse(const char *message, size_t length) {
  (void)raw(SYS_write, 2, (long)message, length, 0, 0, 0);
  (void)raw(SYS_exit_group, 122, 0, 0, 0, 0, 0);
  __builtin_trap();
}

#define REFUSE(message) refuse((message), sizeof(message) - 1)

/* The pinned loader validates/maps its statistics page before plugin init,
 * but deliberately also passes this loader-owned setting to the plugin.
 * Consume only that setting here: the common engine's four-key parser still
 * owns every engine setting and refuses unknown, malformed or duplicate keys.
 * This boundary neither owns statistics counters nor changes the page. */
static bool stats_setting(const char *argument, const char **value) {
  static const char prefix[] = SBR_BACKEND_STATS_ENV "=";
  for (size_t i = 0; i < sizeof(prefix) - 1; ++i) {
    if (argument[i] == '\0' || argument[i] != prefix[i])
      return false;
  }
  *value = argument + sizeof(prefix) - 1;
  return true;
}

static void validate_stats_descriptor(const char *value) {
  /* SabreStats::create emits a canonical decimal descriptor at or above 101,
   * leaving both the guest's low descriptors and fixed RPC slot unchanged. */
  unsigned descriptor = 0;
  if (value[0] < '1' || value[0] > '9')
    REFUSE("common engine SaBRe: invalid statistics descriptor setting\n");
  for (size_t i = 0; value[i] != '\0'; ++i) {
    if (i >= 10 || value[i] < '0' || value[i] > '9' ||
        descriptor > ((unsigned)INT_MAX - (unsigned)(value[i] - '0')) / 10)
      REFUSE("common engine SaBRe: invalid statistics descriptor setting\n");
    descriptor = descriptor * 10 + (unsigned)(value[i] - '0');
  }
  if (descriptor < 101)
    REFUSE("common engine SaBRe: statistics descriptor occupies a reserved slot\n");
  struct stat info;
  if (raw(SYS_fstat, descriptor, (long)&info, 0, 0, 0, 0) != 0 ||
      info.st_size != (off_t)sizeof(struct sbr_backend_stats))
    REFUSE("common engine SaBRe: invalid statistics page descriptor\n");
  struct {
    uint64_t magic;
    uint32_t version;
    uint32_t size;
  } header;
  _Static_assert(sizeof(header) == offsetof(struct sbr_backend_stats, candidate_rips),
                 "statistics header layout");
  if (raw(SYS_pread64, descriptor, (long)&header, sizeof(header), 0, 0, 0) !=
          (long)sizeof(header) ||
      header.magic != SBR_BACKEND_STATS_MAGIC ||
      header.version != SBR_BACKEND_STATS_VERSION ||
      header.size != sizeof(struct sbr_backend_stats))
    REFUSE("common engine SaBRe: incompatible statistics page\n");
}

static void prepare_engine_arguments(int argc, char **argv) {
  bool saw_stats = false;
  engine_arguments[0] = argv[0];
  plugin_argc = 1;
  for (int i = 1; i < argc; ++i) {
    if (argv[i] == NULL)
      REFUSE("common engine SaBRe: missing loader setting\n");
    size_t length = 0;
    while (length < 16384 && argv[i][length] != '\0')
      ++length;
    if (length == 16384)
      REFUSE("common engine SaBRe: oversized loader setting\n");
    const char *value = NULL;
    if (stats_setting(argv[i], &value)) {
      if (saw_stats)
        REFUSE("common engine SaBRe: duplicate statistics descriptor\n");
      validate_stats_descriptor(value);
      saw_stats = true;
    } else {
      engine_arguments[plugin_argc++] = argv[i];
    }
  }
  if (!saw_stats)
    REFUSE("common engine SaBRe: required statistics descriptor is missing\n");
  engine_arguments[plugin_argc] = NULL;
  plugin_argv = engine_arguments;
}

static bool is_installer(void) {
  long installer = atomic_load_explicit(&installer_tid, memory_order_acquire);
  return installer != 0 && raw(SYS_gettid, 0, 0, 0, 0, 0, 0) == installer;
}

static long installer_syscall(long number, long a0, long a1, long a2,
                              long a3, long a4, long a5) {
  if (!is_installer())
    REFUSE("common engine SaBRe: syscall before arming outside installer\n");
  switch (number) {
    case SYS_clone: case SYS_clone3: case SYS_fork: case SYS_vfork:
    case SYS_execve: case SYS_execveat:
      REFUSE("common engine SaBRe: process creation/exec during installation\n");
    default:
      return raw(number, a0, a1, a2, a3, a4, a5);
  }
}

/* Loader report: post_load installs the shared trap path before returning.
 * This is ordinary routing selection, not a private lifecycle capability. */
int reverie_sabre_post_arm_routing_v1(void) { return 1; }

static void arm(bool is_static) {
  if (is_static)
    REFUSE("common engine SaBRe: static client is unsupported\n");
  if (atomic_load_explicit(&armed, memory_order_acquire))
    return;
  atomic_store_explicit(&installer_tid,
                        raw(SYS_gettid, 0, 0, 0, 0, 0, 0), memory_order_release);
  hermit_engine_loader_initialize_v1(plugin_argc, (const char *const *)plugin_argv);
  /* The engine has published its genuine Tool host and armed the filter.
   * Nothing can report success solely by setting an input flag. */
  plugin_argv = NULL;
  plugin_argc = 0;
  atomic_store_explicit(&armed, true, memory_order_release);
}

static long rdtsc(void) {
  if (!atomic_load_explicit(&armed, memory_order_acquire) && !is_installer())
    REFUSE("common engine SaBRe: RDTSC before arming outside installer\n");
  unsigned low, high;
  /* Same inherited caveat as shared_runtime.rs: loader conflates RDTSC and
   * RDTSCP, TSC_AUX is 0, and LFENCE strengthens plain RDTSC ordering. */
  __asm__ volatile("lfence; rdtsc" : "=a"(low), "=d"(high) : : "memory");
  return (long)(((uint64_t)high << 32) | low);
}

static long unrouted(long number, long a0, long a1, long a2,
                     long a3, long a4, long a5, void *frame) {
  (void)number; (void)a0; (void)a1; (void)a2;
  (void)a3; (void)a4; (void)a5; (void)frame;
  REFUSE("common engine SaBRe: loader failed to use post-arm routing\n");
}

long reverie_sabre_routed_syscall_v1(long route, long number,
                                    long a0, long a1, long a2,
                                    long a3, long a4, long a5, void *saved) {
  if (!atomic_load_explicit(&armed, memory_order_acquire))
    return installer_syscall(number, a0, a1, a2, a3, a4, a5);
  /* Check route BEFORE dereferencing saved: SIGILL markers have only a
   * stand-in frame. They cannot manufacture saved-register authority. */
  if (route != 0)
    REFUSE("common engine SaBRe: entry is not a rewritten trampoline route\n");
  if (saved == NULL || ((uintptr_t)saved & 7) != 0)
    REFUSE("common engine SaBRe: invalid native frame address\n");
  struct sabre_frame *frame = saved;
  if (frame->rcx != frame->fake_ret || frame->r11 != frame->rflags ||
      frame->rdi != (uint64_t)a0 || frame->rsi != (uint64_t)a1 ||
      frame->rdx != (uint64_t)a2 || frame->r10 != (uint64_t)a3 ||
      frame->r8 != (uint64_t)a4 || frame->r9 != (uint64_t)a5)
    REFUSE("common engine SaBRe: native frame does not match routed arguments\n");

  struct engine_register_context context = {0};
  context.instruction_pointer = frame->fake_ret - 2;
  context.stack_pointer = (uintptr_t)frame + sizeof(*frame) + 0x80;
  context.r15 = frame->r15; context.r14 = frame->r14;
  context.r13 = frame->r13; context.r12 = frame->r12;
  context.r11 = frame->r11; context.r10 = frame->r10;
  context.r9 = frame->r9; context.r8 = frame->r8;
  context.rdi = frame->rdi; context.rsi = frame->rsi;
  context.rbp = frame->rbp_prologue; context.rbx = frame->rbx;
  context.rdx = frame->rdx; context.rcx = frame->rcx;
  context.rax = number; context.rflags = frame->rflags;
  uint64_t saved_ip = context.instruction_pointer;
  uint64_t saved_sp = context.stack_pointer;
  hermit_engine_saved_syscall_v1(&context, number);

  /* Refuse before ANY writeback when the native trampoline cannot carry
   * the result. Preserve every represented GPR and RFLAGS otherwise. */
  if (context.stack_pointer != saved_sp || context.instruction_pointer != saved_ip)
    REFUSE("common engine SaBRe: Tool changed unrepresentable IP/SP\n");
  frame->r15 = context.r15; frame->r14 = context.r14;
  frame->r13 = context.r13; frame->r12 = context.r12;
  frame->r11 = context.r11; frame->r10 = context.r10;
  frame->r9 = context.r9; frame->r8 = context.r8;
  frame->rdi = context.rdi; frame->rsi = context.rsi;
  frame->rbp_prologue = context.rbp; frame->rbx = context.rbx;
  frame->rdx = context.rdx; frame->rcx = context.rcx;
  frame->rflags = context.rflags;
  return (long)context.rax;
}

void sbr_init(int *argc, char ***argv, sbr_icept_reg_fn reg,
              sbr_icept_vdso_callback_fn *vdso, sbr_sc_handler_fn *syscall_handler,
              sbr_rdtsc_handler_fn *rdtsc_handler, sbr_post_load_fn *post_load,
              char *loader, char *client) {
  (void)reg; (void)loader; (void)client;
  if (argc == NULL || argv == NULL || *argv == NULL || *argc < 1 || *argc > 64)
    REFUSE("common engine SaBRe: invalid loader arguments\n");
  prepare_engine_arguments(*argc, *argv);
  *vdso = NULL;
  *syscall_handler = unrouted;
  *rdtsc_handler = rdtsc;
  *post_load = arm;
}
