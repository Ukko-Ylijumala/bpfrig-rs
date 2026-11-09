// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! Pinned maps: pinning them at load, opening them from a later
    invocation, telling a live pin from a stale one, and the per-CPU
    counter array every tool keeps.
*/

use std::fmt::Display;
use std::marker::PhantomData;
use std::path::Path;

use anyhow::{Context, Result, bail};
use aya::Ebpf;
use aya::maps::{Map, MapData, MapError, PerCpuArray};
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
