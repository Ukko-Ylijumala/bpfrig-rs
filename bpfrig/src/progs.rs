// Copyright (c) 2026 Mikko Tanner. All rights reserved.

//! Privileges, and which of a tool's programs are live in the kernel.

use std::fmt;

use anyhow::{Result, bail};
use aya::programs::loaded_programs;
use nix::unistd::Uid;

/** Refuse unless running as root.

    Everything that reads or writes bpffs is root-only. Gating up front
    stops an EACCES from being mistaken for "nothing is loaded", which is
    how a check reports all-clear on a host that is not protected at all.
*/
pub fn require_root() -> Result<()> {
    if !Uid::effective().is_root() {
        bail!("this action needs root (CAP_BPF/CAP_SYS_ADMIN)");
    }
    Ok(())
}

/** A tool's programs as the kernel lists them. Listing needs privileges,
    so without root an empty list means "unknown", not "none".
*/
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LivePrograms {
    /// `(name, program id)` of each loaded program with one of the names.
    Found(Vec<(String, u32)>),
    NoneLoaded,
    NeedsRoot,
}

/// The loaded programs whose names are in `names`.
pub fn live_programs(names: &[&str]) -> LivePrograms {
    let found: Vec<(String, u32)> = loaded_programs()
        .flatten()
        .filter_map(|info| {
            let name = info.name_as_str()?;
            names.contains(&name).then(|| (name.to_string(), info.id()))
        })
        .collect();
    match (found.is_empty(), Uid::effective().is_root()) {
        (false, _) => LivePrograms::Found(found),
        (true, true) => LivePrograms::NoneLoaded,
        (true, false) => LivePrograms::NeedsRoot,
    }
}

impl fmt::Display for LivePrograms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Found(progs) => {
                for (i, (name, id)) in progs.iter().enumerate() {
                    if i > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{name} (id {id})")?;
                }
                Ok(())
            }
            Self::NoneLoaded => f.write_str("none"),
            Self::NeedsRoot => f.write_str("unknown (re-run as root)"),
        }
    }
}
