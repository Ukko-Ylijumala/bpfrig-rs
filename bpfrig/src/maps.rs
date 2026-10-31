// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! Pinned maps: pinning them at load, opening them from a later
    invocation, and the per-CPU counter array every tool keeps.
*/

use std::fmt::Display;
use std::marker::PhantomData;
use std::path::Path;

use anyhow::{Context, Result, bail};
use aya::Ebpf;
use aya::maps::{Map, MapData, MapError, PerCpuArray};

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
    if !path.exists() {
        bail!("no pinned map at {shown} (not loaded?)");
    }
    let data = MapData::from_pin(path).with_context(|| format!("opening {shown}"))?;
    let map = Map::from_map_data(data).with_context(|| format!("{shown}: unsupported map type"))?;
    T::try_from(map).with_context(|| {
        format!(
            "{shown} does not match this binary's map type or layout \
             (unload and reload after an upgrade?)"
        )
    })
}

/** Pin maps of the loaded object, as `(map name, pin name)` pairs. The
    links already keep the programs and their maps alive; these pins exist
    so a later invocation can read the maps back.
*/
pub fn pin_maps(ebpf: &mut Ebpf, maps: &[(&str, &str)], pins: &PinTxn) -> Result<()> {
    for (name, pin) in maps {
        let path = pins.path(pin)?;
        ebpf.map_mut(name)
            .with_context(|| format!("map {name} missing from the object"))?
            .pin(&path)
            .with_context(|| format!("pinning {name} at {}", path.display()))?;
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
