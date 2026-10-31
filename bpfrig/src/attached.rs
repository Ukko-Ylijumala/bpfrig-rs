// Copyright (c) 2026 Mikko Tanner. All rights reserved.

//! One line of a tool's load report.

use std::fmt;

use crate::probes::KALLSYMS;

/** What an attach step did, for the report a tool prints after `--load`.
    `Display` gives the line the tools have always printed.
*/
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attached {
    /// A kprobe program attached to one kernel symbol, link pinned.
    Kprobe { prog: &'static str, sym: String },
    /// An optional probe skipped because none of its symbols exist.
    Missing { prog: &'static str, syms: &'static [&'static str] },
    /// An LSM program attached to its hook, link pinned.
    Lsm { prog: &'static str, hook: &'static str },
}

impl Attached {
    /// True for every outcome that left a program attached.
    pub const fn is_attached(&self) -> bool {
        !matches!(self, Self::Missing { .. })
    }
}

impl fmt::Display for Attached {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kprobe { prog, sym } => write!(f, "{prog} -> kprobe {sym}"),
            Self::Missing { prog, syms } => {
                write!(f, "{prog} -> not attached ({} absent from {KALLSYMS})", syms.join(", "))
            }
            Self::Lsm { prog, hook } => write!(f, "{prog} -> lsm/{hook}"),
        }
    }
}
