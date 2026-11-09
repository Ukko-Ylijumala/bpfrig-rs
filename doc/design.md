# bpfrig: shared eBPF loading library — design

Status: the CVE-tool part of phase 1 is implemented as v0.1.0
(2026-10-31): `bpfrig-build`, `bpfrig-ebpf`, and `bpfrig` except the
flood-only pieces. The four CVE tools are ported onto it as git
dependencies on the `v0.1.0` tag; see "Ports". The flood-only pieces
(`batch`, `net`, `map_in_use` and the replace-stale pin policy) followed
the same day as v0.1.1, with edge-xdp-flood ported onto them on a
`bpfrig` branch.
Proposal written 2026-10-22, revised 2026-10-31 after edge-xdp-flood moved
to aya 0.14. Based on a read-through of the five aya-based tools listed
under "Consumers". Each inventory entry names the functions it replaces.

## Why

Each tool that loads eBPF has grown its own copy of the same plumbing: the
BTF offset reader, bpffs and pin bookkeeping, the kprobe table and its
attach loop, the `bpf` LSM checks, the stats map readers, and the
`build.rs` that drives aya-build. Most of it was copied from the previous
tool, and the copies have since drifted apart. A shared crate gives one
place to fix a bug or add a feature and have it land in every tool, and
it makes the next tool mostly policy rather than plumbing.

## Consumers

| Tool (repository) | BPF programs | Lifecycle | aya / aya-ebpf / aya-build |
|---|---|---|---|
| edge-xdp-flood | XDP, TC egress classifier | resident process; map pins removed on exit | 0.14 / 0.2 / 0.2 |
| deny-sctp (cve-2026-sctp) | `lsm/socket_create` or `cgroup/sock_create` | pin the link and exit | 0.14 / 0.1 / 0.1 |
| unix-gc-guard (cve-2026-53361-af_unix_gc) | kprobes, `lsm/socket_recvmsg` | pin and exit, self-test | 0.14 / 0.1 / 0.1 |
| vsock-zc-guard (cve-2026-53365-vsock-zerocopy) | kprobes, `lsm/socket_sendmsg`, `lsm/socket_create` | pin and exit, self-test | 0.14 / 0.1 / 0.1 |
| btr-tripwire (cve-2026-64508-btr) | kprobes, kill-mode maps | pin and exit, self-test | 0.14 / 0.1 / 0.1 |

The three guard tools (unix-gc, vsock, btr) share the most. They have the
same CLI shape (`--load`, `--unload`, `--status`, `--stats`, `--check`) and
the same pin-and-exit model. They also share the same self-test idea:
drive the hooked operation once and require a counter to move. deny-sctp
shares a subset. edge-xdp-flood is mostly its own datapath, policy and TUI
code, but it has a few generic pieces.

## Goals and non-goals

Goals:

- One copy of every piece of loading plumbing in the inventory below, with
  the drift between the copies resolved (see "Drift the merge resolves").
- CVE-specific and datapath-specific code stays in the tools.
- Migrating a tool changes no user-visible behavior unless this document
  says so.

Non-goals:

- A framework that owns `main()` or the CLI. Phase 2 considers a
  load-sequence skeleton, but only after the helpers have settled.
- Compatibility with aya 0.13.
- Hiding aya. Tools keep using aya types directly; bpfrig fills the gaps.

## Workspace layout

```
bpfrig-rs/
  Cargo.toml        workspace
  bpfrig/           userspace library (aya 0.14)
  bpfrig-ebpf/      no_std helpers for the BPF side (aya-ebpf 0.2)
  bpfrig-build/     build-dependency wrapping aya-build 0.2
  doc/
```

`bpfrig` re-exports `aya` (`pub use aya;`) so its macros can name it as
`$crate::aya`. Tools still depend on `aya = "0.14"` themselves, and Cargo
unifies the two.

## bpfrig (userspace)

The API shapes below are sketches, not final signatures.

### btf: struct offsets from vmlinux BTF

Replaces `src/btf.rs` in unix-gc, vsock and btr, which are identical
apart from the module doc. Also replaces the `OFFSETS` table and resolve
loop in each tool's `load_object`, and the
`offsets_resolve_against_running_kernel` test.

It is still needed with aya 0.14. aya parses BTF but keeps `type_by_id`
and the member accessors crate-private (aya-obj 0.3), and aya-ebpf has no
CO-RE read helpers, so nothing relocates a field access at load time.
Instead, the loader resolves the offsets and patches them into `OFF_*`
globals.

```rust
/// Struct layouts from the running kernel's BTF.
pub struct Layouts { .. }

impl Layouts {
    pub fn from_sys_fs() -> Result<Self>;
    pub fn parse(raw: &[u8]) -> Result<Self>;
    pub fn offset_of(&self, root: &str, path: &[&str]) -> Result<u32>;
}

/// One loader-patched offset: the global it fills and the member path.
pub struct Offset {
    pub global: &'static str,
    pub root: &'static str,
    pub path: &'static [&'static str],
}
```

It is named `Layouts` rather than `Btf` because the LSM attach path needs
`aya::Btf` in the same files. Today unix-gc and vsock work around the name
clash with a qualified `btf::Btf`.

Changes from the copied reader:

- `offset_of` rejects a member that is a bitfield or not byte-aligned.
  Today it adds `bit_offset / 8`, which truncates and returns a wrong
  offset instead of an error. No current path reads a bitfield.
- A path that runs into a non-struct type (a pointer, say) names the
  member it stopped at.
- The parser gets unit tests against a small synthetic BTF blob, so it is
  tested without a kernel. `bpfrig::btf::check_offsets(OFFSETS)` replaces
  the per-tool resolve test. As today, it skips when vmlinux BTF is
  missing.

### ObjectLoader: load with patched globals

Replaces `load_object` in unix-gc, vsock and btr, and flood's
`EbpfLoader::new().map_max_entries(..)`.

```rust
let ebpf = ObjectLoader::new(bpfrig::embed!("unix_gc_guard_ebpf"))
    .offsets(&layouts, OFFSETS)?
    .global("DENY_ERRNO", mode.deny_errno())
    .load()?;

let ebpf = ObjectLoader::new(bpfrig::embed!("floodprog"))
    .max_entries("SYNACK", args.protect_synack_entries)
    .load()?;
```

- The loader owns the patched values, stored as bytes.
  `EbpfLoader::override_global` borrows them until `load()` returns, which
  is why btr has a comment about keeping the offsets alive. With a builder
  that owns them, that cannot go wrong.
- Every override uses `must_exist = true`. A renamed or optimised-away
  global is a load error, never a program that reads at offset zero.
- `embed!(name)` expands to
  `$crate::aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/", name))`.
  `env!` expands in the calling crate, so it sees the tool's `OUT_DIR`.
- `max_entries(map, n)` passes through to `EbpfLoader::map_max_entries`.
  aya 0.14 deprecates the old `set_max_entries`.

### pins: bpffs and pin-directory bookkeeping

Replaces:

- `ensure_bpffs` (4 copies);
- `pinned_files`, `remove_pins`, the "already loaded: <dir> exists" check
  and the `link_` prefix (3 copies each);
- the "remove every pin if the self-test fails" step in `load()`;
- flood's `PinGuard`.

```rust
pub fn ensure_bpffs() -> Result<()>;

pub struct PinDir { .. }   // /sys/fs/bpf/<tool>, or under flood's --bpffs

impl PinDir {
    pub fn new(tool: &str) -> Self;                   // panics on a bad name
    pub fn under(bpffs: &Path, tool: &str) -> Self;
    pub fn exists(&self) -> bool;
    pub fn path(&self, name: &str) -> Result<PathBuf>;     // rejects '.' and '/'
    pub fn link_path(&self, sym: &str) -> Result<PathBuf>; // link_<sym>
    pub fn has(&self, name: &str) -> bool;
    pub fn files(&self) -> Vec<String>;
    pub fn remove_all(&self) -> Result<()>;
    pub fn claim(&self) -> Result<PinTxn<'_>>;
}

/// Removes every pin in the directory on drop unless committed.
/// Derefs to the PinDir.
pub struct PinTxn<'a> { .. }

impl PinTxn<'_> {
    pub fn commit(self);
    pub fn pin_link(&self, link: FdLink, name: &str) -> Result<PathBuf>;
}
```

- `PinDir::new` panics rather than returning an error, because the tool
  name is always a constant: an invalid one is a bug. Pin names stay
  fallible; a kprobe link's name comes from kallsyms, where names such as
  `foo.cold` exist.
- Because `path` refuses a `.`, a known bpffs pitfall can no longer happen:
  `bpf_lookup()` returns EPERM for a path component containing a dot,
  and the error only appears at `BPF_OBJ_PIN`, after the attach has
  already succeeded.
- `claim` runs `ensure_bpffs`, refuses when the directory exists (the
  guard tools' "already loaded"), creates it and returns the transaction.
  `claim_with(Existing::ReplaceStale)` is flood's version: it refuses if a
  loaded program still uses a pinned map (`map_in_use`), or if the
  directory holds anything that is not a map (a pinned link or program is
  live by definition), and otherwise clears the pins. A map whose users
  cannot be listed counts as stale, as flood had it.
- `ensure_bpffs` decides by `statfs` whether the path is already on a
  bpffs, the mount point or a directory inside one, rather than by
  looking the path up in `/proc/self/mounts`. flood's `--bpffs` may name a
  directory inside `/sys/fs/bpf`, which is not a mount point; the mounts
  lookup would have stacked a new bpffs on it.
- The guard tools call `commit()` after the self-test passes. flood holds
  the transaction for the whole of `run` and never commits it, so its pins
  are removed on any exit, including a panic unwind. That is what
  `PinGuard` does now.

### probes: kprobe tables

Replaces `Probe`, the table-driven `attach_tripwire` and `ksyms()` in
unix-gc, vsock and btr, plus btr's `jit_probe_attached` and
`clone_probe_attached`.

```rust
pub struct Probe {
    pub prog: &'static str,
    pub syms: &'static [&'static str],
    pub first_only: bool,   // the same call site under several names
    pub required: bool,     // absence fails the load
}

pub fn ksyms() -> Result<BTreeSet<String>>;

pub fn attach_kprobes<'p>(
    ebpf: &mut Ebpf,
    probes: impl IntoIterator<Item = &'p Probe>,
    pins: &PinTxn,
) -> Result<Vec<Attached>>;

pub fn probe_attached(pins: &PinDir, probe: &Probe) -> bool;

/// One line of the load report.
pub enum Attached { Kprobe { .. }, Missing { .. }, Lsm { .. } }
```

- The caller decides which probes run by passing them in. Neither a flag
  in the table nor a program name in the loop decides it. Optional probes
  become named consts:
  - btr chains `CLONE_PROBE` in kill mode, and
    `probe_attached(&CLONE_PROBE)` reads the same const, so its symbol
    list exists only once;
  - unix-gc chains `GC_WAIT_PROBE` under `--gc-wait-probe`.
- A missing optional probe is reported as `Attached::Missing`. A missing
  required probe fails the load, and so does attaching nothing at all.
- A link that fell back to legacy debugfs cannot be pinned, and that stays
  an explicit error, as now.

### lsm: the bpf LSM

Replaces:

- `bpf_lsm_active` in deny-sctp, unix-gc and vsock;
- `attach_lsm` and its pin, in the same three tools (vsock's `LsmTarget`
  version is the general one);
- the "bpf is not in the active LSM list" refusal, in the same three
  tools;
- `BootLsm`, `boot_lsm`, `lsm_from_boot_file` and
  `warn_unless_persistent`, which are identical in unix-gc and vsock.

```rust
pub fn bpf_lsm_active() -> bool;
pub fn require_bpf_lsm(instead: &str) -> Result<()>;

pub struct LsmTarget {
    pub prog: &'static str,
    pub hook: &'static str,
    pub pin: &'static str,
}

pub fn attach_lsm(ebpf: &mut Ebpf, target: &LsmTarget, pins: &PinTxn) -> Result<Attached>;

pub enum BootLsm { Enabled, Missing, Unknown }
pub struct BootLsmVerdict { pub state: BootLsm, pub source: String }

pub fn boot_lsm() -> BootLsmVerdict;
pub fn warn_unless_persistent();
```

`boot_lsm` keeps its rules, in this order:

1. The persistent cmdline files: `/etc/kernel/cmdline`, then
   `/etc/default/grub`. Comments and non-`GRUB_CMDLINE_LINUX*` lines are
   ignored, and the last `lsm=` wins.
2. The running kernel's `CONFIG_LSM`.
3. Otherwise `Unknown`, rather than a guess.

The comments drop their fleet-specific detail on the way in. The technical
warning stays: `lsm=` replaces the built-in list, so leaving out apparmor
silently disables LXC confinement.

### maps: pinned maps and counters

Replaces:

- `open_stats` and `counter` (3 copies);
- btr's `open_loaders`, `open_config`, `open_kills`, `open_parents` and
  `open_exempt`;
- flood's `open_policy`, `enable_policy_kinds_pinned` and
  `pinned_allow_exempts`;
- btr's `pin_maps`, and the STATS pin in the other guard tools.

```rust
pub fn open_pinned<T>(path: &Path) -> Result<T>
where
    T: TryFrom<Map, Error = MapError>;

pub fn open_pinned_data(path: &Path) -> Result<MapData>;
pub fn pin_maps(ebpf: &mut Ebpf, maps: &[(&str, &str)], pins: &PinTxn) -> Result<()>;
pub fn map_in_use(map: &MapData) -> Option<bool>;

/// A per-CPU u64 array indexed by a slot enum.
pub struct Counters<S> { .. }

impl<S: Copy + Display + Into<u32>> Counters<S> {
    pub fn open(path: &Path) -> Result<Self>;
    pub fn get(&self, slot: S) -> Result<u64>;   // summed over CPUs
    pub fn moved<R>(&self, slot: S, f: impl FnOnce() -> R) -> Result<(u64, R)>;
}
```

- `open_pinned` runs `MapData::from_pin`, then `Map::from_map_data`, then
  `T::try_from`. In aya 0.14, `from_map_data` takes the map variant from
  the kernel's map type. Today every call site picks the variant by hand
  (`Map::LruHashMap(data)`), and aya checks only the key and value sizes
  against the kernel, so a wrong variant is not caught. The error keeps
  the "(not loaded?)" hint.
- `open_pinned_data` is the untyped first half, for a caller that checks
  `map_in_use` before picking its view: flood's `open_policy` refuses a
  stale pin, then takes `Map::from_map_data` for its batch helpers.
- `map_in_use` returns None when it cannot tell (no CAP_SYS_ADMIN, an
  unreadable program list). It never passes for "nothing uses it"; the
  caller decides what None means.
- `moved` is the self-test step that all three guard tools write by hand:
  read a slot, run the trigger, read the slot again, then return the
  difference and the trigger's result. The triggers stay in the tools.

### progs: privileges and live programs

Replaces the root check (4 copies) and the "live programs" block in
`status()` (4 identical copies, including the reduced output without
root).

```rust
pub fn require_root() -> Result<()>;

/// Implements Display for the status report.
pub enum LivePrograms { Found(Vec<(String, u32)>), NoneLoaded, NeedsRoot }

pub fn live_programs(names: &[&str]) -> LivePrograms;
```

### batch: BPF_MAP_*_BATCH

Replaces the generic core of flood's `batch.rs`. aya 0.14 still has no
batch API.

```rust
pub enum Lookup { Read, Drain }        // LOOKUP_BATCH, LOOKUP_AND_DELETE_BATCH

pub fn map_fd(map: &Map) -> io::Result<BorrowedFd<'_>>;
pub fn possible_cpus() -> io::Result<usize>;
pub const fn percpu_slot<V>() -> usize;          // round_up(size_of::<V>(), 8)
pub fn pod_at<T: Pod>(buf: &[u8], i: usize) -> T;

pub fn lookup_raw(fd: BorrowedFd<'_>, op: Lookup, key_size: usize, stride: usize,
                  visit: impl FnMut(&[u8], &[u8], usize)) -> io::Result<()>;
pub fn lookup<K: Pod, V: Pod>(fd: BorrowedFd<'_>, op: Lookup,
                              f: impl FnMut(K, V)) -> io::Result<()>;
pub fn update<K: Pod, V: Pod>(fd: BorrowedFd<'_>, keys: &[K], vals: &[V]) -> io::Result<usize>;
pub fn delete<K: Pod>(fd: BorrowedFd<'_>, keys: &[K]) -> io::Result<usize>;

pub struct Gate { .. }
impl Gate {
    pub const fn new() -> Self;
    pub fn enabled(&self) -> bool;
    pub fn fallback(&self, err: &io::Error) -> Fallback;
}
pub enum Fallback { Unsupported { first: bool }, Transient { first: bool } }
```

- The lookup loop resumes from the kernel's bucket token, so unlike a
  `GET_NEXT_KEY` walk it finishes even while an LRU map churns. It grows
  its chunk on ENOSPC and keeps per-thread buffers across calls. A call
  asks for 4096 entries, or for as many as fit an 8 MiB value buffer: a
  per-CPU map of large values (flood's `UDP_SPORT`, 8 KiB a CPU) would
  otherwise get hundreds of megabytes for a few dozen entries.
- `update` returns the partial count on E2BIG/ENOMEM (map full), and
  `delete` skips a key that is already gone and carries on after it.
- The calls take the map's fd, not `&Ebpf` plus a map name, so a map
  opened from its pin goes the same way as one the loaded object holds.
- `Gate` holds the fallback rule: when the kernel says batch ops are
  unsupported, use per-key access for good; after any other error, fall
  back for that call only. It returns what happened instead of logging,
  with `first` set once per kind, so the caller logs in its own way.
  bpfrig has no `log` dependency. The kill switch stays with the caller:
  flood keeps `FLOOD_NO_BATCH` next to `Gate::enabled`.
- `lookup_raw` hands over raw chunk bytes, because flood's per-CPU folds
  read slots of a constant size straight out of the buffer, which is what
  lets them compile without bounds checks. `pod_at` replaces the hand
  `read_unaligned` calls for keys. `lookup` is the typed form for plain
  maps. flood keeps its decoders for its own types and its `walk_cap`
  policy for the per-key fallback.

### host: small kernel facts

Replaces:

- btr's `monotonic_ns` and flood's `now_ktime_ns`. They are the same
  function, except that flood's ignores a `clock_gettime` failure;
- the three readers of `/boot/config-<release>`: unix-gc and vsock in
  `boot_lsm`, and btr for `CONFIG_BPF_JIT_ALWAYS_ON`.

```rust
pub const NS_PER_SEC: u64 = 1_000_000_000;

/// CLOCK_MONOTONIC, the bpf_ktime_get_ns() basis.
pub fn ktime_ns() -> Result<u64>;
pub fn os_release() -> Result<String>;
/// Mount points of one fstype, from /proc/self/mounts.
pub fn mounts_of(fstype: &str) -> Result<Vec<PathBuf>>;

pub struct KernelConfig { .. }

impl KernelConfig {
    /// /boot/config-<release> of the running kernel. The error names the
    /// missing file, short enough to quote as a verdict's source.
    pub fn running() -> Result<Self>;
    pub fn get(&self, key: &str) -> Option<&str>;   // quotes stripped
    pub fn enabled(&self, key: &str) -> bool;       // =y
}
```

`mounts_of` is deny-sctp's helper; `ensure_bpffs` uses it, and deny-sctp
keeps using it to find the cgroup2 mount.

### net (feature): XDP and TC

Replaces these flood functions:

- `verify_xdp_mode` and `xdp_mode_of`;
- `ifindex_of`, `mtu_of` and `bond_slaves`;
- the TC attach and clsact bookkeeping of `EgressHook`.

```rust
pub fn bond_slaves(iface: &str) -> Vec<String>;
pub fn ifindex_of(iface: &str) -> Option<u32>;
pub fn mtu_of(iface: &str) -> Option<u32>;

pub enum XdpAttach { Native, Generic, Unconfirmed }
pub fn verify_xdp_mode(iface: &str) -> XdpAttach;

pub struct TcHook { .. }
impl TcHook {
    pub fn new(iface: &str, direction: TcAttachType) -> Self;
    pub fn attached(&self) -> bool;
    pub fn attach(&mut self, prog: &mut SchedClassifier) -> Result<()>;
    pub fn detach(&mut self, prog: &mut SchedClassifier) -> Result<()>;
    pub fn release_qdisc(&mut self) -> Result<bool>;
}
```

- `verify_xdp_mode` reports the mode the kernel actually used, from the
  mode word of `ip link show`. It takes no expected mode: the caller
  compares, since a positive `Generic` is fatal only for a native attach.
- `TcHook::attach` tries aya's default first (TCX on 6.6+) and falls back
  to netlink plus a clsact qdisc. aya's `qdisc_add_clsact` uses
  `NLM_F_EXCL`, so a success means the qdisc is new and the hook's to
  remove. `release_qdisc` removes it with `tc qdisc del`, because aya has
  no qdisc delete; it returns whether it did, so the caller can log, and
  `Drop` does it silently as a backstop. A clsact that was there before is
  left alone.
- One fix on the way in: flood recorded the added qdisc only after the
  netlink attach succeeded, so a failed fallback left the clsact behind.
  The hook records it as soon as it is added, and flood now releases it
  when the attach fails.

A note for the BPF side of any TCX program: under TCX, a return of 0 is
`TCX_PASS`, which ends the hook chain and skips later programs and
classic filters. A program that only observes returns `TC_ACT_UNSPEC`.
flood's egress program does this. The constant is in `bpfrig-ebpf`'s
`consts`, with that comment.

flood is the only user today. These go in because the next XDP or TC tool
would otherwise copy them. They sit behind a `net` feature so the guard
tools don't build them.

## bpfrig-ebpf (BPF side, no_std)

| Item | Where it is today |
|---|---|
| `read_at::<T>(base, off)` and `deref_at(base, off)`, both over `bpf_probe_read_kernel` | unix-gc, vsock |
| `bump(map, slot)` for a per-CPU u64 array | 4 copies, each hard-wired to its own `STATS`. flood's `bump_u64` already takes the map as a parameter |
| `prev_verdict(ctx, hook_args)`: the previous LSM verdict, which comes after the hook's own arguments | 3 LSM programs |
| `atomic_inc_u64` / `atomic_inc_u32` via `atomic_xadd`, with a host fallback so a stable `cargo check` still builds. The bpfel `core` has no atomic read-modify-write | btr only. It moves anyway, so nobody has to work it out again |
| `consts`: `AF_*`, `SOCK_*`, `MSG_*`, `IPPROTO_*`, errno and signal numbers | each crate spells out its own subset, with different integer types. Address families become `u16` (`sa_family_t`), widened where they are compared |
| `program!()` / `program!("Dual MIT/GPL")`: emits the `license` section static and the panic handler | 5 copies |

The kernel checks the `license` string before it allows GPL-only helpers
(`bpf_probe_read_kernel`, `bpf_send_signal`). It is separate from the
crates' own license. The macro defaults to today's `"GPL"`.

Loader-patched globals need no helper. aya-ebpf 0.2 has `Global<T>`, and
its `load()` is a `read_volatile`, which is exactly what each tool's
`cfg_u32` does by hand:

```rust
#[unsafe(no_mangle)]
static OFF_SOCKET_SK: Global<u32> = Global::new(0);

let off = OFF_SOCKET_SK.load();
```

That replaces `cfg_u32` in unix-gc, vsock and btr, and settles its
`usize`/`u32` split on `u32`. `Global` is `repr(transparent)`, so
`override_global` patches it exactly as it patches a bare `u32` static.

**aya-ebpf version.** `bpfrig-ebpf` depends on aya-ebpf 0.2, and each
tool's BPF crate has to be on the same version. aya-ebpf's attribute
macros (`#[map]`, `#[kprobe]`, `#[lsm]`) expand to `::aya_ebpf::` paths,
so a tool cannot use a re-export from `bpfrig-ebpf`; it needs its own
`aya-ebpf` dependency. If that dependency were 0.1 while `bpfrig-ebpf` is
on 0.2, the `PerCpuArray<u64>` a tool declares would be a different type
from the one `bump` accepts. On 2026-10-31 the four CVE BPF crates were
checked against aya-ebpf 0.2 and aya-build 0.2 in scratch copies. All four
build unchanged. The only new warning is `unused_unsafe` at deny-sctp's
`ctx.arg()`, because `LsmContext::arg` is safe in 0.2. That check did not
cover loading the objects through the verifier, which needs root.

flood's packet parsing (`ptr_at`, `load`, and the L2/L3/L4 walkers) does
not move. It has one user and is specific to its datapath. Revisit when a
second XDP or TC tool appears.

## bpfrig-build

Replaces the four identical CVE `build.rs` files and flood's extended one.

```rust
fn main() -> anyhow::Result<()> {
    bpfrig_build::build_ebpf("unix-gc-guard-ebpf")
}
```

- It wraps aya-build 0.2. Its `Package` / `Toolchain` / `build_ebpf` API
  is the same as 0.1's, but 0.2.1 needs rustc 1.98.
- It finds the crate and its `[[bin]]` target through the
  `cargo_metadata` crate, which aya-build already depends on, so the call
  only needs the package name.
- The planned check that the bin name differs from the package name is
  not needed. aya-build 0.2 builds in `OUT_DIR/aya-build/target/<package>`
  and copies to `OUT_DIR/<bin>`, so equal names no longer collide. The
  "Must differ from the package name" comment in each eBPF crate's
  `Cargo.toml` can go when the crate moves to aya-build 0.2.
- It emits `rerun-if-changed` for every local package the eBPF crate
  depends on, directly or not: path dependencies, and `[patch]`ed local
  checkouts. Today only flood does this, by hand, for `flood-common`.
  Without it, an edit to the shared ABI types rebuilds userspace against
  the new layout while `OUT_DIR` keeps the old object. It also watches
  `Cargo.lock`, which is where a git or registry dependency (`bpfrig-ebpf`
  from a tag) changes.
- `cargo metadata` runs with `--offline`; the build already resolved
  everything.
- `SKIP_EBPF_BUILD` writes an empty stub at `OUT_DIR/<bin>` and warns, so
  userspace can be checked without nightly and bpf-linker. This is flood's
  workaround, now available to every tool.

## The ABI convention: a `-common` crate per tool

This is not library code, but it is part of the migration. Today the
guard tools keep their userspace and BPF definitions in sync by comment
("Kept in sync with the loader's Stat enum"). btr adds an `offset_of!`
test over three duplicated structs. flood's `flood-common` is the pattern
to copy:

- `no_std`, with every type `#[repr(C)]` and explicit padding;
- a `user` feature that adds the `aya::Pod` impls, and strum derives for
  slot enums, on the userspace side only;
- the slot enum declared `#[repr(u32)]`, so both sides index the stats
  map with the same values;
- map capacities as shared consts;
- the layout tests in the common crate.

Because `bpfrig-build` emits `rerun-if-changed` automatically, this works
without editing each tool's `build.rs`.

## Drift the merge resolves

1. The kprobe table means three different things.
   - unix-gc has `opt_in`, skips missing symbols silently, and fails only
     if nothing attached.
   - vsock and btr have `required`, and report what they skipped.
   - btr also gates `btt_clone` by program name inside the attach loop,
     and `clone_probe_attached` repeats the table's symbol list.

   See "probes" for the unified table.
2. `btf.rs` truncates bitfield offsets (see "btf").
3. When `/proc/self/mounts` cannot be read, deny-sctp's `ensure_bpffs`
   tries to mount bpffs anyway, while the others fail. bpfrig asks
   `statfs` instead, which needs no mount table and also accepts a
   directory inside a bpffs; mounting a second bpffs over a populated one
   would hide every pin.
4. flood's clock read ignores a `clock_gettime` failure; btr's checks for
   it.
5. `cfg_u32` returns `usize` in two crates and `u32` in the third.
   aya-ebpf 0.2's `Global<u32>` replaces it (see "bpfrig-ebpf").
6. The map variant for a pinned map is chosen by hand at every call site
   (see "maps").

## Stays in the tools

- CLIs, modes, and which programs each mode attaches.
- Self-test triggers: the socketpair peek, the vsock sends, the seccomp
  burst and the kill-mode orchestrator.
- Exposure and host checks: vsock's module, autoload and loopback
  reachability, and btr's JIT, retpoline and fix-symbol verdict.
- btr's kill-mode maps, reporting and `--watch`.
- deny-sctp's attach at the cgroup v2 root, with its temporary cgroup2
  mount. It has one user; it is generic enough to move once a second tool
  needs it.
- flood's datapath, policy, auto-actions and TUI.

## Phase 2: a load-sequence skeleton

unix-gc, vsock and btr each have a `load()` of roughly 70 lines that runs
the same sequence:

1. Make sure bpffs is mounted.
2. Claim the pin directory.
3. Load the object with patched globals.
4. btr only: fill in the config maps.
5. Attach the programs.
6. Pin the maps.
7. Run the self-test.
8. Commit the pins, or remove every pin on failure.
9. Print the report.

Once the phase-1 pieces exist, this could become a struct with hooks
(`arm`, `attach`, `verify`). This waits until all three tools use the
helpers, because each tool needs its hooks at different points in the
sequence.

## Constraints and decisions

- **aya 0.14, aya-ebpf 0.2, aya-build 0.2 are the minimum.** There is no
  0.13 compatibility. Every consumer is on aya 0.14 now; edge-xdp-flood
  moved on 2026-10-27 and is also on aya-ebpf and aya-build 0.2. Its
  comment that aya has no `Map::from_map_data` was out of date, and
  `open_policy` picked `Map::HashMap` by hand; the port replaces both
  (see "maps").
- **License: MIT OR Apache-2.0.** edge-xdp-flood is GPL-2.0-only and the
  CVE tools are MIT OR Apache-2.0. The dual permissive license works for
  both, whereas a GPL library would force the CVE tools to relicense.
- **Edition 2024.** edge-xdp-flood's 2021-edition crates can depend on it
  unchanged. The minimum Rust versions come from aya rather than the
  edition: 1.87 for `bpfrig` and `bpfrig-ebpf` (aya 0.14, aya-ebpf 0.2),
  and 1.98 for `bpfrig-build` (aya-build 0.2.1). Each crate declares its
  own `rust-version`.
- **Errors: anyhow.** Every consumer is an anyhow binary, and much of the
  value is in the context strings ("is CONFIG_DEBUG_INFO_BTF set?").
  Revisit if a consumer needs to match on error kinds.
- **Hosting: GitHub.** Consumers use a git dependency pinned to a tag.
  While developing both sides at once, a `[patch]` entry points the tool
  at the local checkout.
- **Public repository.** Code and comments moved into this crate keep the
  technical reasoning but drop host names and fleet-specific detail.

## Migration order

1. `bpfrig-build`, then `btf`, `ObjectLoader`, `pins`, `probes`, `lsm`,
   `maps`, `progs` and `host`. Migrate unix-gc and vsock first. They are
   the closest pair, so an API that fits one and not the other shows up
   immediately. Adopting `bpfrig-build` moves a tool to aya-build 0.2.
2. btr, deny-sctp, and edge-xdp-flood's use of the step-1 pieces:
   `bpfrig-build`, `ObjectLoader`, `pins`, `maps` and `host`. btr tests
   optional probes, several pinned maps, and `Counters` across modes.
   flood is the only user of `Existing::ReplaceStale` and of a `PinTxn`
   that is never committed, so it should migrate before `pins` is called
   settled. Its aya upgrade, which used to block this, is done.
3. `bpfrig-ebpf`, alongside each tool's BPF crate and its new `-common`
   crate. The CVE BPF crates move to aya-ebpf 0.2 in the same step.
4. `batch` and `net`, both flood-only for now. Done with flood's port.

Check each migrated tool as root on a test machine. Run the full
`--load` / `--check` / `--stats` / `--unload` cycle in every mode, and
make sure its self-test passes unchanged.

### Ports (2026-10-31)

Before v0.1.0 was tagged, all four CVE tools were ported to it in scratch
copies; after the tag the same ports went into the repositories, on a
`bpfrig` branch each. Userspace moved onto
`bpfrig`, `build.rs` onto `bpfrig-build`, and the BPF crates onto aya-ebpf
0.2 and `bpfrig-ebpf` (`Global<u32>` offsets, `bump(&STATS, ..)`,
`read_at`/`deref_at`, `prev_verdict`, `consts`, `program!()`).

- All four build, their unit tests pass (btr's nine, and the offset test
  in unix-gc, vsock and btr through `check_offsets`), and `--status` runs
  unprivileged.
- btr's kprobe section is the same size as before, 0x2658 bytes, so the
  shared atomics and `bump` inline exactly like the hand-written ones.
  unix-gc's LSM program is one instruction longer (0x310 against 0x308
  bytes), from adding `u32` offsets before widening them. vsock's
  `lsm/socket_sendmsg` is nine longer (0x2e8 against 0x2a0): LLVM packs
  the `Option<u32>` from `read_at` into one register and unpacks it again.
  Harmless scalar shuffling, but a `Result`-returning `read_at` might fold
  it away if it ever matters. Baselines are the unported tools rebuilt on
  aya-ebpf 0.2.
- `SKIP_EBPF_BUILD=1` writes the stub; an edit in `bpfrig-ebpf` re-runs
  the eBPF build, and one in `bpfrig` does not.
- Not done: loading through the verifier and the root-only cycle above.

edge-xdp-flood followed on its own `bpfrig` branch, against v0.1.1:

- `build.rs` is `bpfrig_build::build_ebpf("flood-ebpf")`; its hand-written
  `flood-common` rerun line and `SKIP_EBPF_BUILD` stub are gone.
- `run` claims `<bpffs>/flood` with `Existing::ReplaceStale` before it
  touches the NIC and holds the `PinTxn` for the whole run (it replaces
  `PinGuard`); the three map pins go through `pin_maps`. The object loads
  through `ObjectLoader` with `max_entries("SYNACK", ..)`.
- `open_policy` and the pinned config and allow maps open by the kernel's
  map type (`open_pinned_data` + `Map::from_map_data`, `open_pinned`).
- `batch.rs` keeps its readers and per-CPU decoders over `bpfrig::batch`;
  `EgressHook` keeps its protect-mode policy and logging over `TcHook`;
  the interface helpers come from `bpfrig::net`; the clock reads are
  `host::ktime_ns()?`, so a `clock_gettime` failure is an error now.
- The BPF crate uses `program!()` and `consts::TC_ACT_UNSPEC`. Its
  `.text`, `xdp`, `classifier`, `license` and `maps` sections are
  byte-identical to master's build.
- flood's 79 tests pass. Not done: a root run on a test machine.

Behavior changes a real port brings, on top of the open questions:

- unix-gc's probes stay optional, but a missing one is now listed in the
  load report (`-> not attached (... absent from /proc/kallsyms)`), where
  it used to be skipped silently.
- The LSM refusal now always explains that `lsm=` replaces the built-in
  list; deny-sctp's version did not.
- With aya-ebpf 0.2, `LsmContext::arg` is safe, so `unsafe` blocks that
  only wrapped `ctx.arg()` (deny-sctp, vsock's `create_verdict`) became
  unnecessary; the ports drop them.

## Open questions

1. Under the unified table, unix-gc's probes become `required`. `unix_gc`
   and the `unix_*_recvmsg` family exist on every 6.x kernel checked, so
   unix-gc would start failing where it now skips. Is that acceptable?
2. ~~Should the `net` helpers go behind a feature or into their own
   crate?~~ A feature, `net`, which flood enables.
3. Should the default BPF license string stay `"GPL"`, or become
   `"Dual MIT/GPL"` to match the crates' own license?
4. The four `build-dist.sh` scripts differ only in the binary name. Should
   they be shared (as a script in this repo, or an xtask), or left alone?
