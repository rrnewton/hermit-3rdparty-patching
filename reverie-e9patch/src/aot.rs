/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 * All rights reserved.
 *
 * This source code is licensed under the BSD-style license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! Direct-dispatch bridge for e9patch's ahead-of-time syscall trampolines.

use std::cell::Cell;
use std::io;
use std::ptr;

use reverie_ptrace::InjectedSyscallFrame;

include!(concat!(env!("OUT_DIR"), "/aot_dispatch_constants.rs"));

const PAGE_SIZE: usize = 4096;

// TODO-HUMAN-REVIEW(PR-269): Review thread-local AOT
// frame ownership and nested-dispatch restoration for generic Guest access.
thread_local! {
    /// The innermost e9tool frame currently being serviced on this thread.
    static CURRENT_FRAME: Cell<*mut InjectedSyscallFrame> = const { Cell::new(ptr::null_mut()) };
    static CURRENT_RFLAGS: Cell<u64> = const { Cell::new(0) };
    static DISPATCH_DEPTH: Cell<usize> = const { Cell::new(0) };
}

struct CurrentFrameScope {
    previous_frame: *mut InjectedSyscallFrame,
    previous_rflags: u64,
}

impl CurrentFrameScope {
    fn enter(frame: *mut InjectedSyscallFrame, trap_rflags: u64) -> Self {
        let previous_frame = CURRENT_FRAME.with(|slot| slot.replace(frame));
        let previous_rflags = CURRENT_RFLAGS.with(|slot| slot.replace(trap_rflags));
        DISPATCH_DEPTH.with(|depth| depth.set(depth.get() + 1));
        Self {
            previous_frame,
            previous_rflags,
        }
    }
}

impl Drop for CurrentFrameScope {
    fn drop(&mut self) {
        CURRENT_FRAME.with(|slot| slot.set(self.previous_frame));
        CURRENT_RFLAGS.with(|slot| slot.set(self.previous_rflags));
        DISPATCH_DEPTH.with(|depth| depth.set(depth.get() - 1));
    }
}

pub(crate) fn dispatch_is_active() -> bool {
    DISPATCH_DEPTH.with(|depth| depth.get() != 0)
}

pub(crate) fn dispatch_is_nested() -> bool {
    DISPATCH_DEPTH.with(|depth| depth.get() > 1)
}

pub(crate) fn current_regs() -> Option<libc::user_regs_struct> {
    let frame = CURRENT_FRAME.with(Cell::get);
    if frame.is_null() {
        return None;
    }
    let rflags = CURRENT_RFLAGS.with(Cell::get);
    // SAFETY: the AOT callback owns this frame for the enclosing scope.
    Some(unsafe { (&*frame).user_regs(rflags) })
}

pub(crate) fn update_current_regs(regs: &libc::user_regs_struct) -> Result<(), reverie::Errno> {
    let frame = CURRENT_FRAME.with(Cell::get);
    if frame.is_null() {
        return Err(reverie::Errno::ENOSYS);
    }
    let rflags = CURRENT_RFLAGS.with(Cell::get);
    // SAFETY: the AOT callback owns this frame uniquely for the enclosing
    // scope; nested callbacks replace CURRENT_FRAME until they return.
    unsafe { (&mut *frame).update_user_regs(regs, rflags) }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DispatchPage {
    magic: u64,
    callback: usize,
}

/// A pending callback handoff for the AOT payload's post-map init hook.
// AUTONOMOUS-BOT-IMPLEMENTED
pub(crate) struct PendingDispatchPage {
    address: *mut libc::c_void,
    committed: bool,
}

impl PendingDispatchPage {
    /// Publish the callback for the e9patch post-map initialization hook.
    pub(crate) fn prepare() -> io::Result<Self> {
        let requested = AOT_HANDOFF_PAGE_ADDRESS as usize as *mut libc::c_void;
        let address = unsafe {
            libc::mmap(
                requested,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE,
                -1,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        if address != requested {
            unsafe {
                libc::munmap(address, PAGE_SIZE);
            }
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "kernel ignored fixed e9patch handoff-page address",
            ));
        }

        let page = DispatchPage {
            magic: AOT_DISPATCH_MAGIC,
            callback: reverie_e9patch_dispatch_aot as *const () as usize,
        };
        unsafe {
            address.cast::<DispatchPage>().write(page);
        }
        if unsafe { libc::mprotect(address, PAGE_SIZE, libc::PROT_READ) } != 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::munmap(address, PAGE_SIZE);
            }
            return Err(error);
        }

        Ok(Self {
            address,
            committed: false,
        })
    }

    /// Keep the page mapped for the lifetime of the installed runtime.
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PendingDispatchPage {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                libc::munmap(self.address, PAGE_SIZE);
            }
        }
    }
}

// AUTONOMOUS-BOT-IMPLEMENTED
// TODO-HUMAN-REVIEW(PR-264): Review the AOT callback and shared e9tool frame
// mutation.
/// Routes one e9tool state frame through the registered shared dispatcher.
///
/// # Safety
///
/// `frame` must point to the writable e9tool `state` frame for the duration of
/// this call. The AOT trampoline is the intended caller.
unsafe extern "C" fn reverie_e9patch_dispatch_aot(
    frame: *mut InjectedSyscallFrame,
    trap_rflags: u64,
) -> u64 {
    unsafe { dispatch_frame(frame, trap_rflags, reverie_inguest::trap::dispatch_direct) }
}

/// Dispatch body, parameterized on the dispatch function so tests can
/// capture the exact number handed to the host.
///
/// # Safety
/// Same contract as the callback: `frame` must point to the writable
/// e9tool `state` frame for the duration of this call.
unsafe fn dispatch_frame(
    frame: *mut InjectedSyscallFrame,
    trap_rflags: u64,
    dispatch: fn(i64, [u64; 6], u64) -> i64,
) -> u64 {
    // The tail check and the dispatched number use the kernel's number
    // (the low 32 bits of rax, sign-extended): Linux ignores the upper
    // bits, so a high-bit rt_sigreturn is still a tail return and a
    // high-bit getpid still names getpid. The full register stays in
    // the frame for the Guest; only this local classification narrows.
    // Numbers the table cannot name are answered ENOSYS by the
    // registered ToolHost itself (its own decode), matching Linux's
    // sys_ni_syscall. (The pre-check Sysno::from conversion could
    // panic in this callback.)
    let number = unsafe { (&*frame).raw_syscall_number() };
    if reverie_inguest::trap::is_rt_sigreturn(number) {
        return 2;
    }
    let (args, instruction_pointer) = {
        // SAFETY: the AOT trampoline lends this unique frame for the duration
        // of the callback. End the reference before dispatch so the Tool host
        // can reborrow the raw frame for Guest register access.
        let frame = unsafe { &mut *frame };
        let args = frame.raw_args();
        let instruction_pointer = frame.instruction_pointer();
        frame.emulate_syscall_entry(trap_rflags);
        (args, instruction_pointer)
    };
    let _scope = CurrentFrameScope::enter(frame, trap_rflags);
    let result = dispatch(i64::from(number as i32), args, instruction_pointer);
    // SAFETY: dispatch has returned and no Tool borrow of the current frame is
    // live; the trampoline still owns the same unique frame.
    unsafe { (&mut *frame).set_result(result) };
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_page_abi_matches_the_payload() {
        assert_eq!(AOT_HANDOFF_PAGE_ADDRESS % PAGE_SIZE as u64, 0);
        assert_eq!(AOT_DISPATCH_PAGE_ADDRESS % PAGE_SIZE as u64, 0);
        assert_ne!(AOT_HANDOFF_PAGE_ADDRESS, AOT_DISPATCH_PAGE_ADDRESS);
        assert_ne!(AOT_DISPATCH_MAGIC, 0);
        assert_eq!(
            AOT_FALLBACK_TRAP_ENTRY,
            crate::E9PATCH_SYSCALL_TRAP_RIP - 11
        );
        assert_eq!(core::mem::offset_of!(DispatchPage, callback), 8);
        assert!(core::mem::size_of::<DispatchPage>() <= PAGE_SIZE);
    }

    #[test]
    fn prepared_handoff_publishes_the_exact_callback_and_unmaps_on_drop() {
        let page = PendingDispatchPage::prepare().unwrap();
        let published = unsafe { &*page.address.cast::<DispatchPage>() };
        assert_eq!(published.magic, AOT_DISPATCH_MAGIC);
        assert_eq!(
            published.callback,
            reverie_e9patch_dispatch_aot as *const () as usize
        );

        let address = page.address;
        drop(page);
        let mut residency = 0_u8;
        let result = unsafe { libc::mincore(address, PAGE_SIZE, &mut residency) };
        assert_eq!(result, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::ENOMEM)
        );
    }

    #[test]
    fn callback_fails_closed_without_a_registered_dispatcher() {
        let rip = 0x401000;
        let mut words = [0_u64; 18];
        words[15] = libc::SYS_getpid as u64;
        words[17] = rip;

        unsafe {
            assert_eq!(
                reverie_e9patch_dispatch_aot(words.as_mut_ptr().cast(), 0x202),
                1
            );
        }

        assert_eq!(words[15] as i64, -i64::from(libc::ENOSYS));
        assert_eq!(words[14], rip + 2);
        assert_eq!(words[5], 0x202);
    }

    #[test]
    fn high_bit_rt_sigreturn_requests_direct_tail_execution_without_mutation() {
        // Linux reads (int)rax: 0x1_0000_000f IS rt_sigreturn and must take
        // the tail path, exactly like the plain number above.
        let mut words = [0xfeed_face_u64; 18];
        words[15] = 0x1_0000_0000 | libc::SYS_rt_sigreturn as u64;
        let original = words;

        unsafe {
            assert_eq!(
                reverie_e9patch_dispatch_aot(words.as_mut_ptr().cast(), 0x202),
                2
            );
        }

        assert_eq!(words, original);
    }

    #[test]
    fn high_bit_getpid_dispatches_the_kernel_number() {
        // Capture the number actually handed to the host: with raw
        // dispatch this captures 0x1_0000_0000|SYS_getpid and FAILS,
        // which is the regression this test exists to catch (Reverie's
        // docs tell bridges to pass the raw value).
        use std::sync::atomic::{AtomicI64, Ordering};
        static CAPTURED: AtomicI64 = AtomicI64::new(i64::MIN);
        fn capture(number: i64, _args: [u64; 6], _ip: u64) -> i64 {
            CAPTURED.store(number, Ordering::SeqCst);
            4242
        }
        let rip = 0x401000;
        let mut words = [0_u64; 18];
        words[15] = 0x1_0000_0000 | libc::SYS_getpid as u64;
        words[17] = rip;

        unsafe {
            assert_eq!(dispatch_frame(words.as_mut_ptr().cast(), 0x202, capture), 1);
        }

        assert_eq!(CAPTURED.load(Ordering::SeqCst), i64::from(libc::SYS_getpid));
        assert_eq!(words[15] as i64, 4242);
        assert_eq!(words[14], rip + 2);
    }

    #[test]
    fn rt_sigreturn_requests_direct_tail_execution_without_mutation() {
        let mut words = [0xfeed_face_u64; 18];
        words[15] = libc::SYS_rt_sigreturn as u64;
        let original = words;

        unsafe {
            assert_eq!(
                reverie_e9patch_dispatch_aot(words.as_mut_ptr().cast(), 0x202),
                2
            );
        }

        assert_eq!(words, original);
    }
}
