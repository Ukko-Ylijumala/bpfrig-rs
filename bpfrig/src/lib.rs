// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! Shared loading plumbing for aya-based eBPF tools.

    The tools keep using aya directly; this crate fills the gaps they each
    used to fill by hand:

    - [`btf`]: struct member offsets from the running kernel's BTF, for
      loader-patched `OFF_*` globals.
    - [`ObjectLoader`]: load an embedded object with patched globals and
      map sizes.
    - [`pins`]: bpffs, the per-tool pin directory, and a pin transaction
      that removes everything unless committed.
    - [`probes`]: kprobe tables and their attach loop.
    - [`lsm`]: the `bpf` LSM gate, LSM attach, and the boot persistence
      check.
    - [`maps`]: pinned maps opened by their kernel type, the stale-pin
      test, and per-CPU counters.
    - [`batch`]: `BPF_MAP_*_BATCH` reads, drains, updates and deletes.
    - [`progs`]: the root gate and the live-program listing.
    - [`host`]: small kernel facts (the monotonic clock, the running
      kernel's config).
    - `net` (feature `net`): interface facts, the XDP mode check, and a
      TC hook that cleans up the clsact qdisc it added.

    `aya` is re-exported so the macros here can name it, and so a tool's
    `aya` and this crate's are always the same version.
*/

pub mod batch;
pub mod btf;
pub mod host;
pub mod loader;
pub mod lsm;
pub mod maps;
#[cfg(feature = "net")]
pub mod net;
pub mod pins;
pub mod probes;
pub mod progs;

mod attached;

pub use attached::Attached;
pub use aya;
pub use loader::ObjectLoader;

/** The bytes of an eBPF object that `bpfrig-build` (or aya-build) left in
    the calling crate's `OUT_DIR`, aligned for the ELF parser.

    `env!` expands in the calling crate, so `OUT_DIR` is the tool's own.
    The name is the eBPF crate's `[[bin]]` name.
*/
#[macro_export]
macro_rules! embed {
    ($name:literal) => {
        $crate::aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/", $name))
    };
}
