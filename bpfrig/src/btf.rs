// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! Struct member byte offsets from the running kernel's BTF.

    A program that walks kernel structs needs their member offsets, and
    those differ between kernels. Neither aya crate can supply them: aya
    parses BTF but keeps `type_by_id` and the member accessors
    crate-private, and aya-ebpf has no CO-RE read helpers, so nothing
    relocates a field access at load time.

    So the loader resolves the offsets here and patches them into the
    program's `OFF_*` globals (see [`crate::ObjectLoader::offsets`]). One
    binary then stays correct across kernels with different layouts, and a
    layout it cannot resolve is a load error rather than a wild read.

    Only what that needs is implemented: enough of the type section to find
    a struct or union by name and add up member offsets along a path.
*/

use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result, bail};
use strum::{Display, FromRepr};

pub const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

const BTF_MAGIC: u16 = 0xeb9f;
const HEADER_LEN: usize = 24;
/* The common `struct btf_type` header every type entry starts with. */
const TYPE_HEADER_LEN: usize = 12;
/* Modifier chains in real kernels are a handful deep; this only bounds a
   corrupt blob that loops. */
const MAX_MODIFIER_DEPTH: usize = 16;

/* Trailing per-entry record sizes, in bytes. */
const SZ_MEMBER: usize = 12; /* struct btf_member */
const SZ_ENUM: usize = 8; /* struct btf_enum */
const SZ_PARAM: usize = 8; /* struct btf_param */
const SZ_VAR_SECINFO: usize = 12; /* struct btf_var_secinfo */
const SZ_ENUM64: usize = 12; /* struct btf_enum64 */

/** BTF_KIND_* (linux/btf.h). A kind outside this list is a parse error:
    without its trailing record size the rest of the section cannot be
    walked.
*/
#[derive(Clone, Copy, Debug, Display, FromRepr, PartialEq, Eq)]
#[strum(serialize_all = "snake_case")]
#[repr(u32)]
enum Kind {
    Void = 0,
    Int = 1,
    Ptr = 2,
    Array = 3,
    Struct = 4,
    Union = 5,
    Enum = 6,
    Fwd = 7,
    Typedef = 8,
    Volatile = 9,
    Const = 10,
    Restrict = 11,
    Func = 12,
    FuncProto = 13,
    Var = 14,
    Datasec = 15,
    Float = 16,
    DeclTag = 17,
    TypeTag = 18,
    Enum64 = 19,
}

impl Kind {
    const fn has_members(self) -> bool {
        matches!(self, Self::Struct | Self::Union)
    }

    const fn is_modifier(self) -> bool {
        matches!(
            self,
            Self::Typedef | Self::Volatile | Self::Const | Self::Restrict | Self::TypeTag
        )
    }

    /// Trailing bytes after the common header for one entry of this kind.
    const fn trailer_len(self, vlen: usize) -> usize {
        match self {
            Self::Int | Self::Var | Self::DeclTag => 4,
            Self::Array => 12,
            Self::Struct | Self::Union => vlen * SZ_MEMBER,
            Self::Enum => vlen * SZ_ENUM,
            Self::FuncProto => vlen * SZ_PARAM,
            Self::Datasec => vlen * SZ_VAR_SECINFO,
            Self::Enum64 => vlen * SZ_ENUM64,
            _ => 0,
        }
    }
}

struct Member {
    name: String,
    type_id: u32,
    bit_offset: u32,
    /// Non-zero for a bitfield member.
    bitfield_size: u32,
}

struct Type {
    kind: Kind,
    /// `size` for struct/union, `type` for the reference kinds.
    size_or_type: u32,
    members: Vec<Member>,
}

/** Struct layouts from a BTF blob, normally the running kernel's.

    Named `Layouts` rather than `Btf` so it does not clash with `aya::Btf`,
    which the LSM attach path needs in the same files.
*/
pub struct Layouts {
    /// Indexed by BTF type id; entry 0 is the void placeholder.
    types: Vec<Type>,
    by_name: HashMap<String, u32>,
}

/** One loader-patched offset: the global it fills, the struct it starts
    from, and the member path, e.g. `OFF_SK_FAMILY` = `sock` →
    `__sk_common.skc_family`.
*/
#[derive(Clone, Copy, Debug)]
pub struct Offset {
    pub global: &'static str,
    pub root: &'static str,
    pub path: &'static [&'static str],
}

impl Offset {
    pub const fn new(
        global: &'static str,
        root: &'static str,
        path: &'static [&'static str],
    ) -> Self {
        Self { global, root, path }
    }
}

impl Layouts {
    /// The running kernel's layouts, from /sys/kernel/btf/vmlinux.
    pub fn from_sys_fs() -> Result<Self> {
        let raw = fs::read(VMLINUX_BTF)
            .with_context(|| format!("reading {VMLINUX_BTF} (is CONFIG_DEBUG_INFO_BTF set?)"))?;
        Self::parse(&raw).with_context(|| format!("parsing {VMLINUX_BTF}"))
    }

    /// Parse a raw little-endian BTF blob.
    pub fn parse(raw: &[u8]) -> Result<Self> {
        if raw.len() < HEADER_LEN {
            bail!("BTF blob is truncated ({} bytes)", raw.len());
        }
        let magic = u16::from_le_bytes([raw[0], raw[1]]);
        if magic != BTF_MAGIC {
            bail!("bad BTF magic {magic:#06x} (big-endian kernel?)");
        }
        let hdr_len = read_u32(raw, 4)? as usize;
        let type_off = read_u32(raw, 8)? as usize;
        let type_len = read_u32(raw, 12)? as usize;
        let str_off = read_u32(raw, 16)? as usize;
        let str_len = read_u32(raw, 20)? as usize;

        /* Section offsets are relative to the end of the header. */
        let types_start = hdr_len + type_off;
        let types_end = types_start + type_len;
        let strs_start = hdr_len + str_off;
        if types_end > raw.len() || strs_start + str_len > raw.len() {
            bail!("BTF sections run past the end of the blob");
        }
        let strings = &raw[strs_start..strs_start + str_len];

        let mut types = vec![Type {
            kind: Kind::Void,
            size_or_type: 0,
            members: Vec::new(),
        }];
        let mut by_name = HashMap::new();

        let mut pos = types_start;
        while pos < types_end {
            let name_off = read_u32(raw, pos)? as usize;
            let info = read_u32(raw, pos + 4)?;
            let size_or_type = read_u32(raw, pos + 8)?;
            let raw_kind = (info >> 24) & 0x1f;
            let kind = Kind::from_repr(raw_kind).with_context(|| {
                format!("unknown BTF kind {raw_kind} at type id {}", types.len())
            })?;
            let vlen = (info & 0xffff) as usize;
            /* With kind_flag set, a member's offset word packs the bitfield
               size into its top byte. */
            let kind_flag = (info >> 31) & 1 == 1;
            let trailer = pos + TYPE_HEADER_LEN;

            let mut members = Vec::new();
            if kind.has_members() {
                for i in 0..vlen {
                    let base = trailer + i * SZ_MEMBER;
                    let raw_offset = read_u32(raw, base + 8)?;
                    let (bit_offset, bitfield_size) = if kind_flag {
                        (raw_offset & 0xff_ffff, raw_offset >> 24)
                    } else {
                        (raw_offset, 0)
                    };
                    members.push(Member {
                        name: string_at(strings, read_u32(raw, base)? as usize)?,
                        type_id: read_u32(raw, base + 4)?,
                        bit_offset,
                        bitfield_size,
                    });
                }
            }

            let name = string_at(strings, name_off)?;
            if kind.has_members() && !name.is_empty() {
                /* First definition wins; later duplicates are usually the
                   same type re-emitted per compilation unit. */
                by_name.entry(name).or_insert(types.len() as u32);
            }
            types.push(Type { kind, size_or_type, members });
            pos = trailer + kind.trailer_len(vlen);
        }

        Ok(Self { types, by_name })
    }

    /** Byte offset of a member path inside a named struct or union, e.g.
        `offset_of("sock", &["__sk_common", "skc_family"])`. A bitfield, or
        any member that does not start on a byte boundary, is an error: its
        byte offset alone would read the wrong bits.
    */
    pub fn offset_of(&self, root: &str, path: &[&str]) -> Result<u32> {
        let mut type_id = *self
            .by_name
            .get(root)
            .with_context(|| format!("struct {root} is not in the kernel BTF"))?;
        let mut total = 0;
        let mut walked = root.to_string();

        for part in path {
            let holder = self.strip_modifiers(type_id)?;
            if !holder.kind.has_members() {
                let kind = holder.kind;
                bail!("{walked} is a {kind}, not a struct or union; cannot look up .{part}");
            }
            let member = holder
                .members
                .iter()
                .find(|m| m.name == *part)
                .with_context(|| format!("{walked}.{part} is not in the kernel BTF"))?;
            walked = format!("{walked}.{part}");
            if member.bitfield_size != 0 {
                let bits = member.bitfield_size;
                bail!("{walked} is a {bits}-bit bitfield; a byte offset cannot address it");
            }
            if member.bit_offset % 8 != 0 {
                bail!("{walked} starts at bit {}, not on a byte boundary", member.bit_offset);
            }
            total += member.bit_offset / 8;
            type_id = member.type_id;
        }
        Ok(total)
    }

    /// Resolve every entry of an offset table, as `(global, offset)`.
    pub fn resolve(&self, table: &[Offset]) -> Result<Vec<(&'static str, u32)>> {
        table
            .iter()
            .map(|off| {
                let offset = self
                    .offset_of(off.root, off.path)
                    .with_context(|| format!("resolving {}", off.global))?;
                Ok((off.global, offset))
            })
            .collect()
    }

    /// Follow typedef/const/volatile/restrict/type_tag to the real type.
    fn strip_modifiers(&self, mut type_id: u32) -> Result<&Type> {
        for _ in 0..MAX_MODIFIER_DEPTH {
            let ty = self
                .types
                .get(type_id as usize)
                .with_context(|| format!("BTF type id {type_id} out of range"))?;
            if !ty.kind.is_modifier() {
                return Ok(ty);
            }
            type_id = ty.size_or_type;
        }
        bail!("BTF modifier chain did not terminate at type id {type_id}")
    }
}

/** Resolve an offset table against the running kernel, printing each
    result. Meant for a tool's unit test, which then needs no privileges:
    /sys/kernel/btf/vmlinux is world-readable. A host without BTF skips
    (prints why and returns Ok) rather than fails.

    ```ignore
    #[test]
    fn offsets_resolve_against_running_kernel() {
        bpfrig::btf::check_offsets(OFFSETS).unwrap();
    }
    ```
*/
pub fn check_offsets(table: &[Offset]) -> Result<()> {
    let Ok(layouts) = Layouts::from_sys_fs() else {
        eprintln!("skipping: no readable {VMLINUX_BTF}");
        return Ok(());
    };
    for (off, (global, offset)) in table.iter().zip(layouts.resolve(table)?) {
        println!("{global:<22} {}.{} = {offset}", off.root, off.path.join("."));
    }
    Ok(())
}

fn read_u32(raw: &[u8], at: usize) -> Result<u32> {
    let bytes = raw
        .get(at..at + 4)
        .with_context(|| format!("BTF read past end of blob at {at}"))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn string_at(strings: &[u8], at: usize) -> Result<String> {
    let tail = strings
        .get(at..)
        .with_context(|| format!("BTF string offset {at} past end of string section"))?;
    let end = tail.iter().position(|b| *b == 0).unwrap_or(tail.len());
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

/* ===== tests ===== */

#[cfg(test)]
mod tests {
    use super::*;

    const KIND_FLAG: u32 = 1 << 31;

    /** Builds a little-endian BTF blob by hand. Type ids are assigned in
        push order starting at 1.
    */
    struct BlobBuilder {
        types: Vec<u8>,
        strings: Vec<u8>,
        next_id: u32,
    }

    impl BlobBuilder {
        fn new() -> Self {
            Self { types: Vec::new(), strings: vec![0], next_id: 1 }
        }

        fn string(&mut self, s: &str) -> u32 {
            if s.is_empty() {
                return 0;
            }
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }

        fn header(&mut self, name: &str, info: u32, size_or_type: u32) -> u32 {
            let name_off = self.string(name);
            for word in [name_off, info, size_or_type] {
                self.types.extend_from_slice(&word.to_le_bytes());
            }
            let id = self.next_id;
            self.next_id += 1;
            id
        }

        fn int(&mut self, name: &str, size: u32) -> u32 {
            let id = self.header(name, (Kind::Int as u32) << 24, size);
            self.types.extend_from_slice(&(size * 8).to_le_bytes());
            id
        }

        fn ptr(&mut self, target: u32) -> u32 {
            self.header("", (Kind::Ptr as u32) << 24, target)
        }

        fn typedef(&mut self, name: &str, target: u32) -> u32 {
            self.header(name, (Kind::Typedef as u32) << 24, target)
        }

        /// `members` are (name, type id, raw offset word).
        fn composite(
            &mut self,
            kind: Kind,
            name: &str,
            size: u32,
            flags: u32,
            members: &[(&str, u32, u32)],
        ) -> u32 {
            let info = flags | ((kind as u32) << 24) | members.len() as u32;
            let id = self.header(name, info, size);
            for (mname, ty, off) in members {
                let name_off = self.string(mname);
                for word in [name_off, *ty, *off] {
                    self.types.extend_from_slice(&word.to_le_bytes());
                }
            }
            id
        }

        fn raw_kind(&mut self, kind: u32) {
            self.header("", kind << 24, 0);
        }

        fn build(&self) -> Vec<u8> {
            let mut blob = Vec::new();
            blob.extend_from_slice(&BTF_MAGIC.to_le_bytes());
            blob.extend_from_slice(&[1, 0]); /* version, flags */
            for word in [
                HEADER_LEN as u32,
                0,
                self.types.len() as u32,
                self.types.len() as u32,
                self.strings.len() as u32,
            ] {
                blob.extend_from_slice(&word.to_le_bytes());
            }
            blob.extend_from_slice(&self.types);
            blob.extend_from_slice(&self.strings);
            blob
        }
    }

    /** struct inner { int a; int b; };
        typedef struct inner inner_t;
        struct outer { long x; inner_t in; struct inner *p;
                       unsigned flag:1 (bitfield); char odd (at bit 3) };
        union u { int i; struct inner s; };
    */
    fn sample() -> Layouts {
        let mut b = BlobBuilder::new();
        let int = b.int("int", 4);
        let long = b.int("long", 8);
        let inner = b.composite(Kind::Struct, "inner", 8, 0, &[("a", int, 0), ("b", int, 32)]);
        let inner_t = b.typedef("inner_t", inner);
        let ptr = b.ptr(inner);
        b.composite(
            Kind::Struct,
            "outer",
            40,
            KIND_FLAG,
            &[
                ("x", long, 0),
                ("in", inner_t, 64),
                ("p", ptr, 128),
                ("flag", int, (1 << 24) | 192),
                ("odd", int, 195),
            ],
        );
        b.composite(Kind::Union, "u", 8, 0, &[("i", int, 0), ("s", inner, 0)]);
        /* A second `inner` with a different layout: must not replace the first. */
        b.composite(Kind::Struct, "inner", 8, 0, &[("a", int, 32), ("b", int, 0)]);
        Layouts::parse(&b.build()).unwrap()
    }

    #[test]
    fn nested_members_add_up_through_a_typedef() {
        let l = sample();
        assert_eq!(l.offset_of("outer", &["x"]).unwrap(), 0);
        assert_eq!(l.offset_of("outer", &["in"]).unwrap(), 8);
        assert_eq!(l.offset_of("outer", &["in", "b"]).unwrap(), 12);
        assert_eq!(l.offset_of("outer", &["p"]).unwrap(), 16);
    }

    #[test]
    fn unions_and_first_definition_wins() {
        let l = sample();
        assert_eq!(l.offset_of("u", &["s", "b"]).unwrap(), 4);
        assert_eq!(l.offset_of("inner", &["b"]).unwrap(), 4);
    }

    #[test]
    fn bitfields_and_unaligned_members_are_errors() {
        let l = sample();
        let err = l.offset_of("outer", &["flag"]).unwrap_err().to_string();
        assert!(err.contains("bitfield"), "{err}");
        let err = l.offset_of("outer", &["odd"]).unwrap_err().to_string();
        assert!(err.contains("byte boundary"), "{err}");
    }

    #[test]
    fn a_path_through_a_pointer_names_where_it_stopped() {
        let err = sample().offset_of("outer", &["p", "a"]).unwrap_err().to_string();
        assert!(err.contains("outer.p is a ptr"), "{err}");
    }

    #[test]
    fn missing_names_are_errors() {
        let l = sample();
        assert!(l.offset_of("nope", &["x"]).is_err());
        let err = l.offset_of("outer", &["in", "c"]).unwrap_err().to_string();
        assert!(err.contains("outer.in.c"), "{err}");
    }

    #[test]
    fn resolve_names_the_global_that_failed() {
        const TABLE: &[Offset] = &[
            Offset::new("OFF_B", "outer", &["in", "b"]),
            Offset::new("OFF_BAD", "outer", &["missing"]),
        ];
        let l = sample();
        assert_eq!(l.resolve(&TABLE[..1]).unwrap(), vec![("OFF_B", 12)]);
        let err = format!("{:#}", l.resolve(TABLE).unwrap_err());
        assert!(err.contains("OFF_BAD"), "{err}");
    }

    #[test]
    fn malformed_blobs_are_rejected() {
        assert!(Layouts::parse(&[0; 8]).is_err());
        let mut bad_magic = BlobBuilder::new().build();
        bad_magic[0] = 0;
        assert!(Layouts::parse(&bad_magic).is_err());

        let mut b = BlobBuilder::new();
        b.raw_kind(27);
        let err = Layouts::parse(&b.build()).err().unwrap().to_string();
        assert!(err.contains("unknown BTF kind 27"), "{err}");
    }

    /** The real kernel's BTF parses and has the structs every current tool
        uses. Skips on a host without BTF.
    */
    #[test]
    fn running_kernel_parses() {
        let Ok(l) = Layouts::from_sys_fs() else {
            eprintln!("skipping: no readable {VMLINUX_BTF}");
            return;
        };
        for (root, path) in [
            ("socket", &["sk"][..]),
            ("sock", &["__sk_common", "skc_family"][..]),
            ("sk_buff", &["cb"][..]),
            ("task_struct", &["real_parent"][..]),
        ] {
            l.offset_of(root, path).unwrap();
        }
    }
}
