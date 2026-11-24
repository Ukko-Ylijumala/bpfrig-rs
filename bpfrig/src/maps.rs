// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! Pinned maps: pinning them at load, opening them from a later
    invocation, telling a live pin from a stale one, checking a pin's
    layout before a new load reuses it, and the per-CPU counter array
    every tool keeps.
*/

use std::fmt::Display;
use std::marker::PhantomData;
use std::mem::size_of;
use std::path::Path;

use anyhow::{Context, Result, bail};
use aya::Ebpf;
use aya::maps::{Map, MapData, MapError, MapInfo, MapType, PerCpuArray};
use aya::programs::{ProgramError, loaded_programs};
use nix::errno::Errno;

use crate::pins::PinTxn;

/** Open a pinned map as a typed aya map, e.g.
    `open_pinned::<HashMap<MapData, u32, Kill>>(&path)`.

    The map variant comes from the kernel's own map type
    (`Map::from_map_data`), not from the caller, so a wrong type is an
    error. aya then checks the key and value sizes against `T`.
*/
pub fn open_pinned<T>(path: &Path) -> Result<T>
where
    T: TryFrom<Map, Error = MapError>,
{
    let shown = path.display();
    let data = open_pinned_data(path)?;
    let map = Map::from_map_data(data).with_context(|| format!("{shown}: unsupported map type"))?;
    T::try_from(map).with_context(|| {
        format!(
            "{shown} does not match this binary's map type or layout \
             (unload and reload after an upgrade?)"
        )
    })
}

/** Open a pinned map without typing it yet, for a caller that inspects
    it first (see [`map_in_use`]) and then picks its view, e.g. with
    `Map::from_map_data`.
*/
pub fn open_pinned_data(path: &Path) -> Result<MapData> {
    let shown = path.display();
    if !path.exists() {
        bail!("no pinned map at {shown} (not loaded?)");
    }
    MapData::from_pin(path).with_context(|| format!("opening {shown}"))
}

/** Does a loaded program still use this map? A pinned map outlives the
    programs that used it, so a pin left by a process that died without
    cleanup looks just like a live one; writing through it reports
    success while nothing reads the map.

    None means it could not be told: the map's info, the program list, or
    a program's map ids were unreadable (without CAP_SYS_ADMIN the list is
    a single error). Callers decide what that means for them; it never
    passes for "nothing uses it".
*/
pub fn map_in_use(map: &MapData) -> Option<bool> {
    let id = map.info().ok()?.id();
    for prog in loaded_programs() {
        let prog = match prog {
            Ok(prog) => prog,
            /* Unloaded between listing and opening: not one using `map`. */
            Err(ProgramError::SyscallError(err))
                if err.io_error.raw_os_error() == Some(Errno::ENOENT as i32) =>
            {
                continue;
            }
            Err(_) => return None,
        };
        if prog.map_ids().ok()??.contains(&id) {
            return Some(true);
        }
    }
    Some(false)
}

/** What a program compiled against a map relies on: the four facts a
    pinned map has to share with this binary's definition before a new
    load may reuse it ([`crate::ObjectLoader::reuse_pinned`]). Neither the
    kernel nor aya compares them: a program loads against whatever map its
    fd names, and then reads values of another size or shape.
*/
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MapLayout {
    pub map_type: MapType,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

impl MapLayout {
    /** The layout this binary expects, from its key and value types. An
        array's key is `u32`; an LPM trie's is aya's `lpm_trie::Key<K>`.
        A per-CPU map's value is one CPU's.
    */
    pub const fn of<K, V>(map_type: MapType, max_entries: u32) -> Self {
        Self {
            map_type,
            key_size: size_of::<K>() as u32,
            value_size: size_of::<V>() as u32,
            max_entries,
        }
    }

    /// The layout the kernel reports for the map pinned at `path`.
    pub fn of_pin(path: &Path) -> Result<Self> {
        let shown = path.display();
        let info = MapInfo::from_pin(path).with_context(|| format!("opening {shown}"))?;
        let map_type = info.map_type().with_context(|| format!("{shown}: unknown map type"))?;
        Ok(Self {
            map_type,
            key_size: info.key_size(),
            value_size: info.value_size(),
            max_entries: info.max_entries(),
        })
    }

    /** How `found` (a pinned map) differs from `self` (what this binary
        expects), as text for a log line; None when a load can reuse it.
    */
    pub fn mismatch(&self, found: &Self) -> Option<String> {
        let mut diffs = Vec::new();
        if self.map_type != found.map_type {
            diffs.push(format!("type {:?}, expected {:?}", found.map_type, self.map_type));
        }
        let sizes = [
            ("key size", found.key_size, self.key_size),
            ("value size", found.value_size, self.value_size),
            ("max entries", found.max_entries, self.max_entries),
        ];
        for (what, found, expected) in sizes {
            if found != expected {
                diffs.push(format!("{what} {found}, expected {expected}"));
            }
        }
        (!diffs.is_empty()).then(|| diffs.join("; "))
    }
}

/** Pin maps of the loaded object, as `(map name, pin name)` pairs. The
    links already keep the programs and their maps alive; these pins exist
    so a later invocation can read the maps back.
*/
pub fn pin_maps(ebpf: &mut Ebpf, maps: &[(&str, &str)], pins: &PinTxn) -> Result<()> {
    for (name, pin) in maps {
        let map =
            ebpf.map_mut(name).with_context(|| format!("map {name} missing from the object"))?;
        pins.pin_with(pin, |path| map.pin(path)).with_context(|| format!("map {name}"))?;
    }
    Ok(())
}

/** A per-CPU `u64` array indexed by a slot enum: the STATS map.

    `S` is the tool's slot enum, `#[repr(u32)]` with the discriminants the
    eBPF side indexes by; `Into<u32>` maps a slot to its index.
*/
pub struct Counters<S> {
    map: PerCpuArray<MapData, u64>,
    slot: PhantomData<S>,
}

impl<S: Copy + Display + Into<u32>> Counters<S> {
    /// Open the pinned map.
    pub fn open(path: &Path) -> Result<Self> {
        Ok(Self { map: open_pinned(path)?, slot: PhantomData })
    }

    /// One slot, summed over all CPUs.
    pub fn get(&self, slot: S) -> Result<u64> {
        let per_cpu = self
            .map
            .get(&slot.into(), 0)
            .with_context(|| format!("reading counter {slot}"))?;
        Ok(per_cpu.iter().sum())
    }

    /** Read a slot, run `trigger`, and read it again: how far the slot
        moved, and the trigger's result. The self-test step that proves a
        program is not just attached but running.
    */
    pub fn moved<R>(&self, slot: S, trigger: impl FnOnce() -> R) -> Result<(u64, R)> {
        let before = self.get(slot)?;
        let result = trigger();
        let after = self.get(slot)?;
        Ok((after.saturating_sub(before), result))
    }
}

/* ===== tests ===== */

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field that differs is named, with both values; an equal
    /// layout is no mismatch.
    #[test]
    fn layout_mismatch_names_each_difference() {
        let expected = MapLayout::of::<[u8; 12], [u8; 24]>(MapType::Hash, 16384);
        assert_eq!(
            expected,
            MapLayout { map_type: MapType::Hash, key_size: 12, value_size: 24, max_entries: 16384 }
        );
        assert_eq!(expected.mismatch(&expected), None);

        let resized = MapLayout { max_entries: 64, ..expected };
        assert_eq!(expected.mismatch(&resized).unwrap(), "max entries 64, expected 16384");

        let other = MapLayout::of::<[u8; 8], [u8; 32]>(MapType::LruHash, 16384);
        assert_eq!(
            expected.mismatch(&other).unwrap(),
            "type LruHash, expected Hash; key size 8, expected 12; value size 32, expected 24"
        );
    }

    #[test]
    fn layout_of_a_missing_pin_is_an_error() {
        assert!(MapLayout::of_pin(Path::new("/nonexistent/bpfrig/policy")).is_err());
    }
}
