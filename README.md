# bpfrig

Shared loading plumbing for [aya](https://aya-rs.dev)-based eBPF tools.
It covers the parts every tool needs: struct offsets from kernel BTF, bpffs
and pin bookkeeping, kprobe tables, `bpf` LSM checks, pinned maps, and the
`build.rs` that compiles the BPF crate. Tools keep using aya directly;
bpfrig fills the gaps around it.

| Crate | Side | What it gives a tool |
|---|---|---|
| `bpfrig` | userspace | `btf::Layouts` offsets, `ObjectLoader`, `pins::PinDir` / `PinTxn`, `probes::attach_kprobes`, `lsm::*`, `maps::open_pinned` / `Counters`, `progs::*`, `host::*` |
| `bpfrig-ebpf` | BPF, `no_std` | `read_at` / `deref_at`, `bump`, atomic increments, `prev_verdict`, `consts`, `program!()` |
| `bpfrig-build` | `build.rs` | `build_ebpf("<pkg>")` over aya-build, with rebuild tracking and `SKIP_EBPF_BUILD` |

Requires aya 0.14, aya-ebpf 0.2 and aya-build 0.2. The BPF build needs a
nightly toolchain with `rust-src` and `bpf-linker`, as for any aya
project. `bpfrig-build` needs rustc 1.98 (aya-build 0.2.1's floor).

## Using it

```toml
[dependencies]
bpfrig = { git = "<this repository>", tag = "v0.1.0" }

[build-dependencies]
bpfrig-build = { git = "<this repository>", tag = "v0.1.0" }
```

The tool's BPF crate depends on `bpfrig-ebpf` from the same tag, and on
`aya-ebpf = "0.2"` itself. aya-ebpf's macros name `::aya_ebpf` directly,
so the version has to match the one `bpfrig-ebpf` uses.

`build.rs`:

```rust
fn main() -> anyhow::Result<()> {
    bpfrig_build::build_ebpf("my-tool-ebpf")
}
```

A pin-and-exit load:

```rust
const OFFSETS: &[Offset] = &[Offset::new("OFF_SOCKET_SK", "socket", &["sk"])];
const TRIPWIRE: &[Probe] =
    &[Probe { prog: "my_probe", syms: &["unix_gc"], first_only: true, required: true }];

let pins = PinDir::new("my-tool");
let txn = pins.claim()?; // mounts bpffs, refuses if already loaded
let mut ebpf = ObjectLoader::new(bpfrig::embed!("my_tool_ebpf"))
    .offsets(&Layouts::from_sys_fs()?, OFFSETS)?
    .load()?;
let report = attach_kprobes(&mut ebpf, TRIPWIRE, &txn)?;
pin_maps(&mut ebpf, &[("STATS", "stats")], &txn)?;
// self-test here; returning early drops the transaction and removes every pin
txn.commit();
```

On the BPF side:

```rust
#[unsafe(no_mangle)]
static OFF_SOCKET_SK: Global<u32> = Global::new(0);

#[map]
static STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(4, 0);

bpfrig_ebpf::program!(); // license section + panic handler
```

[doc/design.md](doc/design.md) has the reasoning, the inventory of what
each piece replaces, and the migration plan.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
