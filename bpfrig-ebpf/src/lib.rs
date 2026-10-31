// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! Helpers for the BPF side of an aya tool (no_std, bpfel-unknown-none).

    - [`read_at`] / [`deref_at`]: kernel reads at a loader-patched offset.
      Declare the offsets as `aya_ebpf::Global<u32>` statics; `load()` is a
      volatile read, so the placeholder zero is never const-folded.
    - [`bump`]: count into a per-CPU `u64` array.
    - [`atomic_inc_u64`] / [`atomic_inc_u32`]: for counters several CPUs
      write.
    - [`prev_verdict`]: the previous LSM program's verdict.
    - [`consts`]: socket, errno, signal and TC constants (no libc here).
    - [`program!`]: the `license` section and the panic handler.

    Use the same aya-ebpf version as this crate (see its Cargo.toml).
*/

#![no_std]
/* Only the BPF build is nightly. Gated so a stable host check of this
   crate (and of a tool's BPF crate) does not reject the attribute. */
#![cfg_attr(target_arch = "bpf", feature(core_intrinsics))]
#![cfg_attr(target_arch = "bpf", allow(internal_features))]

pub mod consts;

#[cfg(target_arch = "bpf")]
use core::intrinsics::{AtomicOrdering, atomic_xadd};
#[cfg(not(target_arch = "bpf"))]
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use aya_ebpf::helpers::bpf_probe_read_kernel;
use aya_ebpf::maps::PerCpuArray;
use aya_ebpf::programs::LsmContext;

/** Read a `T` from kernel memory at `base + off`, or None if unreadable.

    # Safety
    `base` must be a kernel pointer the program obtained from the kernel;
    `bpf_probe_read_kernel` makes a bad address an error, not a fault.
*/
#[inline(always)]
pub unsafe fn read_at<T>(base: *const u8, off: u32) -> Option<T> {
    unsafe { bpf_probe_read_kernel(base.add(off as usize).cast::<T>()).ok() }
}

/** Follow one pointer field at `base + off`, or None if unreadable.

    # Safety
    As for [`read_at`].
*/
#[inline(always)]
pub unsafe fn deref_at(base: *const u8, off: u32) -> Option<*const u8> {
    unsafe { read_at::<*const u8>(base, off) }
}

/** Add one to a slot of a per-CPU `u64` array. Per-CPU, so the
    read-modify-write needs no atomics; userspace sums the CPUs.
*/
#[inline(always)]
pub fn bump(map: &PerCpuArray<u64>, slot: u32) {
    if let Some(counter) = map.get_ptr_mut(slot) {
        unsafe { *counter += 1 };
    }
}

/** The verdict of the previous LSM program, which the kernel passes after
    the hook's own arguments: `prev_verdict(&ctx, 4)` for
    `socket_recvmsg(sock, msg, size, flags)`. Non-zero means an earlier
    program already denied, and a program should return it unchanged.
*/
#[inline(always)]
pub fn prev_verdict(ctx: &LsmContext, hook_args: usize) -> i32 {
    ctx.arg(hook_args)
}

/** Atomically add one to a counter other CPUs also write.

    The bpfel target's `core` has no atomic read-modify-write methods, so
    the BPF build uses the intrinsic. The result is discarded so it
    compiles to a plain `lock +=` with no fetch, which every kernel with
    BPF atomics accepts. The host variant only exists so a stable check of
    the crate builds.

    # Safety
    `counter` must point into a map value the program holds.
*/
#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn atomic_inc_u64(counter: *mut u64) {
    unsafe { atomic_xadd::<u64, u64, { AtomicOrdering::Relaxed }>(counter, 1) };
}

/** [`atomic_inc_u64`] for a `u32`.

    # Safety
    As for [`atomic_inc_u64`].
*/
#[cfg(target_arch = "bpf")]
#[inline(always)]
pub unsafe fn atomic_inc_u32(counter: *mut u32) {
    unsafe { atomic_xadd::<u32, u32, { AtomicOrdering::Relaxed }>(counter, 1) };
}

/** Host stand-in for the BPF [`atomic_inc_u64`]; see there.

    # Safety
    `counter` must be valid and aligned for an atomic access.
*/
#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn atomic_inc_u64(counter: *mut u64) {
    unsafe { AtomicU64::from_ptr(counter) }.fetch_add(1, Ordering::Relaxed);
}

/** Host stand-in for the BPF [`atomic_inc_u32`]; see there.

    # Safety
    `counter` must be valid and aligned for an atomic access.
*/
#[cfg(not(target_arch = "bpf"))]
#[inline(always)]
pub unsafe fn atomic_inc_u32(counter: *mut u32) {
    unsafe { AtomicU32::from_ptr(counter) }.fetch_add(1, Ordering::Relaxed);
}

/** Emit what every BPF program crate needs once: the `license` section
    and the panic handler.

    The kernel reads the license string before it allows GPL-only helpers
    such as `bpf_probe_read_kernel` and `bpf_send_signal`. It is separate
    from the crate's own license. `program!()` uses `"GPL"`; pass another
    string with `program!("Dual MIT/GPL")`.
*/
#[macro_export]
macro_rules! program {
    () => {
        $crate::program!("GPL");
    };
    ($license:literal) => {
        #[unsafe(link_section = "license")]
        #[unsafe(no_mangle)]
        static LICENSE: [u8; $crate::license_len($license)] = $crate::license_bytes($license);

        #[cfg(not(test))]
        #[panic_handler]
        fn panic(_info: &::core::panic::PanicInfo) -> ! {
            unsafe { ::core::hint::unreachable_unchecked() }
        }
    };
}

/// The license string's length with its NUL terminator.
#[doc(hidden)]
pub const fn license_len(license: &str) -> usize {
    license.len() + 1
}

/// The license string as a NUL-terminated byte array.
#[doc(hidden)]
pub const fn license_bytes<const N: usize>(license: &str) -> [u8; N] {
    let bytes = license.as_bytes();
    assert!(N == bytes.len() + 1, "license array length must be the string length plus NUL");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < bytes.len() {
        out[i] = bytes[i];
        i += 1;
    }
    out
}
