// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! Load an embedded eBPF object with loader-patched globals and map sizes.

    ```ignore
    let ebpf = ObjectLoader::new(bpfrig::embed!("unix_gc_guard_ebpf"))
        .offsets(&layouts, OFFSETS)?
        .global("DENY_ERRNO", mode.deny_errno())
        .load()?;
    ```
*/

use std::mem::size_of;
use std::slice;

use anyhow::{Context, Result, bail};
use aya::{Ebpf, EbpfLoader, Pod};

use crate::btf::{Layouts, Offset};

/** A builder over `EbpfLoader` that owns the patched values.

    `EbpfLoader::override_global` borrows each value until `load()`
    returns, so a loop that patches temporaries has to keep them alive by
    hand. This builder stores the bytes itself, so that cannot go wrong.

    Every global is patched with `must_exist = true`: a renamed or
    optimised-away global is a load error, never a program that silently
    reads a zero placeholder.
*/
pub struct ObjectLoader<'a> {
    object: &'a [u8],
    globals: Vec<(String, Vec<u8>)>,
    max_entries: Vec<(String, u32)>,
}

impl<'a> ObjectLoader<'a> {
    /// Start from an object's bytes, normally from [`crate::embed!`].
    pub fn new(object: &'a [u8]) -> Self {
        Self { object, globals: Vec::new(), max_entries: Vec::new() }
    }

    /// Patch one global. Setting the same name again replaces the value.
    pub fn global<T: Pod>(mut self, name: &str, value: T) -> Self {
        /* Safety: `Pod` promises plain data with no padding or pointers,
           so its bytes are fully initialised and meaningful as-is. */
        let bytes =
            unsafe { slice::from_raw_parts((&raw const value).cast::<u8>(), size_of::<T>()) };
        match self.globals.iter_mut().find(|(n, _)| n == name) {
            Some((_, slot)) => *slot = bytes.to_vec(),
            None => self.globals.push((name.to_string(), bytes.to_vec())),
        }
        self
    }

    /** Resolve an offset table against `layouts` and patch every entry as
        a `u32` global.
    */
    pub fn offsets(mut self, layouts: &Layouts, table: &[Offset]) -> Result<Self> {
        for (global, offset) in layouts.resolve(table)? {
            self = self.global(global, offset);
        }
        Ok(self)
    }

    /// Size a map at load time (`EbpfLoader::map_max_entries`).
    pub fn max_entries(mut self, map: &str, entries: u32) -> Self {
        match self.max_entries.iter_mut().find(|(n, _)| n == map) {
            Some((_, slot)) => *slot = entries,
            None => self.max_entries.push((map.to_string(), entries)),
        }
        self
    }

    /// Parse the object, apply the patches, and load the maps.
    pub fn load(self) -> Result<Ebpf> {
        if self.object.is_empty() {
            bail!("the embedded eBPF object is empty (built with SKIP_EBPF_BUILD?)");
        }
        let mut loader = EbpfLoader::new();
        for (name, bytes) in &self.globals {
            loader.override_global(name, bytes.as_slice(), true);
        }
        for (name, entries) in &self.max_entries {
            loader.map_max_entries(name, *entries);
        }
        loader.load(self.object).context("loading the embedded eBPF object")
    }
}
