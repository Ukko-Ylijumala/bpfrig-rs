// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! `BPF_MAP_*_BATCH` (kernel 5.6 and later): whole-map reads, drains,
    updates and deletes in a few syscalls. aya has no batch API, so these
    drive the syscall directly on the map's fd.

    One lookup call returns up to 4096 entries, per-CPU values included,
    where a per-key walk costs a syscall per key (two for a hash map, which
    also needs `GET_NEXT_KEY`). For a hash map the resume token is a
    bucket index, so the walk only ever moves forward: unlike a
    `GET_NEXT_KEY` walk it cannot restart from the first bucket when the
    key it stands on is evicted, and it finishes however hard an LRU map
    churns.

    The calls take a map fd ([`map_fd`] gets one from an aya `Map`), so a
    map held by a loaded object and one opened from its pin go the same
    way. A caller keeps a per-key path as the fallback and asks a [`Gate`]
    which one to take.

    Layout contract (UAPI, stable): keys come back packed at the key size.
    A plain map's values come back packed at the value size; a per-CPU
    map's at `nr_possible_cpus` consecutive slots of
    `round_up(value_size, 8)` bytes each ([`percpu_slot`]).
*/

use std::cell::RefCell;
use std::io;
use std::mem::{self, size_of};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use aya::Pod;
use aya::maps::Map;
use aya::util::nr_cpus;
use libc::{c_long, c_uint, c_void};

/// The kernel's internal `ENOTSUPP` (not in libc): a map type without the op.
const ENOTSUPP: i32 = 524;

/** Entries per lookup call. Grown (bounded) on ENOSPC, which the kernel
    returns when a single hash bucket holds more than the buffer.
*/
const CHUNK: u32 = 4096;
const CHUNK_MAX: u32 = 1 << 16;

const BPF_MAP_LOOKUP_BATCH: c_long = 24;
const BPF_MAP_LOOKUP_AND_DELETE_BATCH: c_long = 25;
const BPF_MAP_UPDATE_BATCH: c_long = 26;
const BPF_MAP_DELETE_BATCH: c_long = 27;

/// The `batch` member of `union bpf_attr` (every member sits at offset 0).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BatchAttr {
    in_batch: u64,  // opaque resume token from the previous call (0 = start)
    out_batch: u64, // token to resume the next call from
    keys: u64,
    values: u64,
    count: u32, // in: buffer capacity (entries); out: entries processed
    map_fd: u32,
    elem_flags: u64,
    flags: u64,
}

thread_local! {
    /** The lookup buffers, kept (grow-only) across calls on one thread. A
        full chunk of a per-CPU map is 4096 x value slot x nCPU, megabytes
        on a big host, and would otherwise be allocated and zeroed on every
        call. Only the entries the kernel reports are read back, so a stale
        tail is harmless. A `visit` callback must not start another lookup.
    */
    static BUFS: RefCell<(Vec<u8>, Vec<u8>)> = const { RefCell::new((Vec::new(), Vec::new())) };
}

/// Which lookup command to run over the map.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// `BPF_MAP_LOOKUP_BATCH`: read every entry.
    Read,
    /** `BPF_MAP_LOOKUP_AND_DELETE_BATCH`: read every entry and delete it
        in the same pass. The kernel copies and deletes each bucket under
        its lock, so an update racing the drain is lost only for the bucket
        being copied.
    */
    Drain,
}

impl Lookup {
    const fn cmd(self) -> c_long {
        match self {
            Self::Read => BPF_MAP_LOOKUP_BATCH,
            Self::Drain => BPF_MAP_LOOKUP_AND_DELETE_BATCH,
        }
    }
}

/** Whether batch ops are worth trying, and what a failure means for the
    next call. One per process, normally a `static`.

    Only an "unsupported" answer (EINVAL from a kernel without the
    command, ENOTSUPP or EOPNOTSUPP for a map type without the op) turns
    the batch path off for good. Any other error falls back for that one
    call, so a single failure does not demote every later read to the
    per-key walk.

    A kill switch (an environment variable, say) stays with the caller:
    check it next to [`enabled`](Self::enabled).
*/
pub struct Gate {
    supported: AtomicBool,
    transient_seen: AtomicBool,
}

/// What a failed batch op means, from [`Gate::fallback`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {
    /** The kernel cannot do it: the gate is now off. `first` is true for
        the answer that turned it off, so the caller logs it once.
    */
    Unsupported { first: bool },
    /** A one-off failure: fall back for this call only. `first` is true
        for the first one seen.
    */
    Transient { first: bool },
}

impl Fallback {
    /// True the first time this kind of fallback happens: the one to log.
    pub const fn first(self) -> bool {
        match self {
            Self::Unsupported { first } | Self::Transient { first } => first,
        }
    }
}

impl Gate {
    pub const fn new() -> Self {
        Self { supported: AtomicBool::new(true), transient_seen: AtomicBool::new(false) }
    }

    /// False once the kernel has said batch ops are unsupported.
    pub fn enabled(&self) -> bool {
        self.supported.load(Ordering::Relaxed)
    }

    /// Classify a failed batch op; the caller then takes the per-key path.
    pub fn fallback(&self, err: &io::Error) -> Fallback {
        let errno = err.raw_os_error();
        if matches!(errno, Some(libc::EINVAL | libc::EOPNOTSUPP | ENOTSUPP)) {
            Fallback::Unsupported { first: self.supported.swap(false, Ordering::Relaxed) }
        } else {
            Fallback::Transient { first: !self.transient_seen.swap(true, Ordering::Relaxed) }
        }
    }
}

impl Default for Gate {
    fn default() -> Self {
        Self::new()
    }
}

/// The fd behind a `Map` of a type with batch ops (the array and hash kinds).
pub fn map_fd(map: &Map) -> io::Result<BorrowedFd<'_>> {
    let data = match map {
        Map::Array(data)
        | Map::PerCpuArray(data)
        | Map::HashMap(data)
        | Map::LruHashMap(data)
        | Map::PerCpuHashMap(data)
        | Map::PerCpuLruHashMap(data) => data,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "map type has no batch ops",
            ));
        }
    };
    Ok(data.fd().as_fd())
}

/// The number of possible CPUs, the slot count of a per-CPU value. Cached.
pub fn possible_cpus() -> io::Result<usize> {
    static N: OnceLock<usize> = OnceLock::new();
    if let Some(n) = N.get() {
        return Ok(*n);
    }
    let n = nr_cpus().map_err(|(_, err)| err)?;
    Ok(*N.get_or_init(|| n))
}

/** The bytes one CPU's copy of a `V` takes in a per-CPU batch buffer:
    `size_of::<V>()` rounded up to 8. An entry's value is `ncpus` of these.
*/
pub const fn percpu_slot<V>() -> usize {
    size_of::<V>().next_multiple_of(8)
}

/** Entry `i` of a buffer of packed `T`s, as a lookup hands to its
    `visit` callback. Panics when the buffer is too short.
*/
pub fn pod_at<T: Pod>(buf: &[u8], i: usize) -> T {
    let size = size_of::<T>();
    let bytes = &buf[i * size..(i + 1) * size];
    /* Safety: the slice holds exactly one T's bytes, and `Pod` makes any
       byte pattern a valid T. The read is unaligned-safe. */
    unsafe { bytes.as_ptr().cast::<T>().read_unaligned() }
}

/** Run `op` over the whole map, calling `visit(keys, values, n)` once per
    returned chunk with the raw bytes of `n` entries: keys at `key_size`
    each, values at `stride` each. For a per-CPU map `stride` is
    `percpu_slot::<V>() * possible_cpus()`; for a plain one, the value
    size.

    This is the form for decoders that fold per-CPU values straight out of
    the buffer; [`lookup`] is the typed one for plain maps.
*/
pub fn lookup_raw(
    fd: BorrowedFd<'_>,
    op: Lookup,
    key_size: usize,
    stride: usize,
    mut visit: impl FnMut(&[u8], &[u8], usize),
) -> io::Result<()> {
    BUFS.with_borrow_mut(|(keys, vals)| {
        lookup_in(fd, op.cmd(), key_size, stride, keys, vals, &mut visit)
    })
}

/// [`lookup_raw`] over a plain (not per-CPU) map, one typed pair at a time.
pub fn lookup<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    op: Lookup,
    mut f: impl FnMut(K, V),
) -> io::Result<()> {
    lookup_raw(fd, op, size_of::<K>(), size_of::<V>(), |keys, vals, n| {
        for i in 0..n {
            f(pod_at(keys, i), pod_at(vals, i));
        }
    })
}

/// The loop of [`lookup_raw`], over the caller's reusable buffers.
fn lookup_in(
    fd: BorrowedFd<'_>,
    cmd: c_long,
    key_size: usize,
    stride: usize,
    keys: &mut Vec<u8>,
    vals: &mut Vec<u8>,
    visit: &mut impl FnMut(&[u8], &[u8], usize),
) -> io::Result<()> {
    let mut chunk = CHUNK;
    ensure_len(keys, chunk as usize * key_size);
    ensure_len(vals, chunk as usize * stride);
    /* Opaque resume tokens. The generic implementation (arrays) stores a
       key here, the hash one a u32 bucket index; size for both. */
    let mut tok_in = vec![0u8; key_size.max(8)];
    let mut tok_out = vec![0u8; key_size.max(8)];
    let mut have_token = false;

    loop {
        let mut attr = BatchAttr {
            in_batch: if have_token { tok_in.as_ptr() as u64 } else { 0 },
            out_batch: tok_out.as_mut_ptr() as u64,
            keys: keys.as_mut_ptr() as u64,
            values: vals.as_mut_ptr() as u64,
            count: chunk,
            map_fd: fd.as_raw_fd() as u32,
            ..Default::default()
        };
        let done = match bpf(cmd, &mut attr) {
            Ok(()) => false,
            /* The end of the map, possibly with final entries: count and
               out_batch are written back for this one too. */
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => true,
            /* One hash bucket larger than the buffer: grow and retry from
               the same position (out_batch was set to that bucket). */
            Err(err) if err.raw_os_error() == Some(libc::ENOSPC) && chunk < CHUNK_MAX => {
                chunk = (chunk * 2).min(CHUNK_MAX);
                ensure_len(keys, chunk as usize * key_size);
                ensure_len(vals, chunk as usize * stride);
                mem::swap(&mut tok_in, &mut tok_out);
                continue;
            }
            Err(err) => return Err(err),
        };
        let got = attr.count as usize;
        if got > 0 {
            visit(&keys[..got * key_size], &vals[..got * stride], got);
        }
        /* A success with nothing returned would otherwise loop forever. */
        if done || got == 0 {
            return Ok(());
        }
        mem::swap(&mut tok_in, &mut tok_out);
        have_token = true;
    }
}

/** Write `vals[i]` under `keys[i]` for every `i` in one
    `BPF_MAP_UPDATE_BATCH` call (flags 0, `BPF_ANY`). Returns how many
    entries were written: the kernel processes the keys in order and stops
    at the first failure, so a short count means `keys[..n]` are in and the
    map filled up at `keys[n]`. Panics when the slices differ in length.
*/
pub fn update<K: Pod, V: Pod>(fd: BorrowedFd<'_>, keys: &[K], vals: &[V]) -> io::Result<usize> {
    assert_eq!(keys.len(), vals.len(), "batch update: one value per key");
    if keys.is_empty() {
        return Ok(0);
    }
    let mut attr = BatchAttr {
        keys: keys.as_ptr() as u64,
        values: vals.as_ptr() as u64,
        count: keys.len() as u32,
        map_fd: fd.as_raw_fd() as u32,
        ..Default::default()
    };
    match bpf(BPF_MAP_UPDATE_BATCH, &mut attr) {
        Ok(()) => Ok(keys.len()),
        /* Map full mid-way (E2BIG for a preallocated hash, ENOMEM
           otherwise): the kernel wrote back how far it got, and a partial
           write is a result. Any other errno leaves `count` untouched, so
           it cannot be trusted and the error goes to the caller. */
        Err(err) if matches!(err.raw_os_error(), Some(libc::E2BIG | libc::ENOMEM)) => {
            Ok(attr.count as usize)
        }
        Err(err) => Err(err),
    }
}

/** Delete `keys` with `BPF_MAP_DELETE_BATCH`. Returns how many were
    deleted. The kernel stops at the first failure; a key that is already
    gone (ENOENT: a concurrent delete, an LRU eviction) is skipped and the
    call resumed after it, so one missing key never leaves the rest in
    place. Other errnos leave `count` untouched and go to the caller.
*/
pub fn delete<K: Pod>(fd: BorrowedFd<'_>, keys: &[K]) -> io::Result<usize> {
    let mut keys = keys;
    let mut deleted = 0;
    while !keys.is_empty() {
        let mut attr = BatchAttr {
            keys: keys.as_ptr() as u64,
            count: keys.len() as u32,
            map_fd: fd.as_raw_fd() as u32,
            ..Default::default()
        };
        match bpf(BPF_MAP_DELETE_BATCH, &mut attr) {
            Ok(()) => return Ok(deleted + keys.len()),
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                /* keys[..done] are gone and keys[done] was the missing one. */
                let done = (attr.count as usize).min(keys.len());
                deleted += done;
                keys = &keys[(done + 1).min(keys.len())..];
            }
            Err(err) => return Err(err),
        }
    }
    Ok(deleted)
}

/// One `bpf(2)` batch command.
fn bpf(cmd: c_long, attr: &mut BatchAttr) -> io::Result<()> {
    /* Safety: attr, and every buffer it points into, outlive the call. */
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            cmd,
            (attr as *mut BatchAttr).cast::<c_void>(),
            size_of::<BatchAttr>() as c_uint,
        )
    };
    if rc == 0 { Ok(()) } else { Err(io::Error::last_os_error()) }
}

/// Grow `buf` to at least `len` bytes; never shrinks, zero-fills only growth.
fn ensure_len(buf: &mut Vec<u8>, len: usize) {
    if buf.len() < len {
        buf.resize(len, 0);
    }
}

/* ===== tests ===== */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_turns_off_only_on_unsupported() {
        let gate = Gate::new();
        let transient = io::Error::from_raw_os_error(libc::EFAULT);
        assert_eq!(gate.fallback(&transient), Fallback::Transient { first: true });
        assert_eq!(gate.fallback(&transient), Fallback::Transient { first: false });
        assert!(gate.enabled());
        let unsupported = io::Error::from_raw_os_error(ENOTSUPP);
        assert_eq!(gate.fallback(&unsupported), Fallback::Unsupported { first: true });
        assert!(!gate.enabled());
        let einval = io::Error::from_raw_os_error(libc::EINVAL);
        assert!(!gate.fallback(&einval).first());
    }

    #[test]
    fn percpu_slots_round_up_to_eight() {
        assert_eq!(percpu_slot::<u64>(), 8);
        assert_eq!(percpu_slot::<u32>(), 8);
        assert_eq!(percpu_slot::<[u8; 12]>(), 16);
        assert_eq!(percpu_slot::<[u64; 4]>(), 32);
    }

    #[test]
    fn pod_at_reads_packed_entries() {
        let mut buf = Vec::new();
        for v in [7u32, 0xdead_beef, 42] {
            buf.extend_from_slice(&v.to_ne_bytes());
        }
        /* Unaligned: start one byte in. */
        let mut shifted = vec![0u8];
        shifted.extend_from_slice(&buf);
        assert_eq!(pod_at::<u32>(&buf, 1), 0xdead_beef);
        assert_eq!(pod_at::<u32>(&shifted[1..], 2), 42);
    }

    #[test]
    #[should_panic]
    fn pod_at_panics_past_the_end() {
        pod_at::<u64>(&[0u8; 12], 1);
    }
}
