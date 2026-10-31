// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! Kprobe tables and their attach loop.

    A tool describes its kprobes as a table of [`Probe`]s and passes the
    ones the current mode wants to [`attach_kprobes`]. Which probes run is
    decided by what the caller passes in, never by a flag in the table or
    a program name inside the loop. An optional probe that only some modes
    attach is best kept as its own named const, so [`probe_attached`] reads
    the same symbol list the attach used.
*/

use std::collections::BTreeSet;
use std::fs;

use anyhow::{Context, Result, anyhow, bail};
use aya::Ebpf;
use aya::programs::KProbe;
use aya::programs::links::FdLink;

use crate::Attached;
use crate::pins::{LINK_PREFIX, PinDir, PinTxn};

pub const KALLSYMS: &str = "/proc/kallsyms";

/** One kprobe program and the kernel symbols it attaches to.

    `first_only` attaches to the first symbol that exists instead of to
    every match, for candidates that are the same call site under
    different names (a function inlined into its caller on some builds, or
    renamed between kernel versions). Attaching to both where both exist
    would count twice.

    `required` makes the load fail when none of the symbols exist. An
    optional probe that finds nothing is reported as [`Attached::Missing`].
*/
#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub prog: &'static str,
    pub syms: &'static [&'static str],
    pub first_only: bool,
    pub required: bool,
}

impl Probe {
    /// The symbols to attach to on a kernel exporting `available`.
    fn targets(&self, available: &BTreeSet<String>) -> Vec<&'static str> {
        self.syms
            .iter()
            .copied()
            .filter(|sym| available.contains(*sym))
            .take(if self.first_only { 1 } else { usize::MAX })
            .collect()
    }
}

/** Every symbol name in /proc/kallsyms. Readable without privileges (the
    addresses are zeroed for non-root, the names are not).
*/
pub fn ksyms() -> Result<BTreeSet<String>> {
    let table = fs::read_to_string(KALLSYMS).with_context(|| format!("reading {KALLSYMS}"))?;
    Ok(table
        .lines()
        .filter_map(|line| line.split_whitespace().nth(2))
        .map(str::to_owned)
        .collect())
}

/** Load and attach each probe on every target symbol that exists, and pin
    each link as `link_<symbol>`.

    Fails when a required probe finds no symbol, and when nothing at all
    was attached, since that would pin an inert directory. A link that fell
    back to legacy debugfs cannot be pinned, which is an error too.
*/
pub fn attach_kprobes<'p>(
    ebpf: &mut Ebpf,
    probes: impl IntoIterator<Item = &'p Probe>,
    pins: &PinTxn,
) -> Result<Vec<Attached>> {
    let available = ksyms()?;
    let mut report = Vec::new();

    for probe in probes {
        let targets = probe.targets(&available);
        if targets.is_empty() {
            if probe.required {
                bail!(
                    "none of the symbols for {} exist in {KALLSYMS} ({})",
                    probe.prog,
                    probe.syms.join(", ")
                );
            }
            report.push(Attached::Missing { prog: probe.prog, syms: probe.syms });
            continue;
        }

        let prog: &mut KProbe = ebpf
            .program_mut(probe.prog)
            .with_context(|| format!("{} not found in the object", probe.prog))?
            .try_into()?;
        prog.load().with_context(|| format!("verifier rejected {}", probe.prog))?;

        for sym in targets {
            let link_id = prog
                .attach(sym, 0)
                .with_context(|| format!("attaching {} to kprobe {sym}", probe.prog))?;
            let link: FdLink = prog.take_link(link_id)?.try_into().map_err(|_| {
                anyhow!("kprobe {sym} attached via legacy debugfs, which cannot be pinned")
            })?;
            pins.pin_link(link, &format!("{LINK_PREFIX}{sym}"))?;
            report.push(Attached::Kprobe { prog: probe.prog, sym: sym.to_string() });
        }
    }

    if !report.iter().any(Attached::is_attached) {
        bail!("none of the probed symbols exist in {KALLSYMS}; nothing was attached");
    }
    Ok(report)
}

/// True when any of the probe's symbols has a pinned link.
pub fn probe_attached(pins: &PinDir, probe: &Probe) -> bool {
    probe
        .syms
        .iter()
        .any(|sym| pins.has(&format!("{LINK_PREFIX}{sym}")))
}

/* ===== tests ===== */

#[cfg(test)]
mod tests {
    use super::*;

    const GC: Probe =
        Probe { prog: "gc", syms: &["unix_gc", "__unix_gc"], first_only: true, required: true };
    const PEEK: Probe = Probe {
        prog: "peek",
        syms: &["unix_stream_recvmsg", "unix_dgram_recvmsg", "unix_seqpacket_recvmsg"],
        first_only: false,
        required: true,
    };

    fn kernel(syms: &[&str]) -> BTreeSet<String> {
        syms.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn first_only_takes_the_first_present_symbol() {
        assert_eq!(GC.targets(&kernel(&["__unix_gc", "unix_gc"])), vec!["unix_gc"]);
        assert_eq!(GC.targets(&kernel(&["__unix_gc"])), vec!["__unix_gc"]);
        assert!(GC.targets(&kernel(&[])).is_empty());
    }

    #[test]
    fn every_present_symbol_otherwise() {
        let k = kernel(&["unix_stream_recvmsg", "unix_seqpacket_recvmsg"]);
        assert_eq!(PEEK.targets(&k), vec!["unix_stream_recvmsg", "unix_seqpacket_recvmsg"]);
    }

    #[test]
    fn missing_probe_report_line() {
        let line = Attached::Missing { prog: GC.prog, syms: GC.syms }.to_string();
        assert_eq!(line, "gc -> not attached (unix_gc, __unix_gc absent from /proc/kallsyms)");
    }
}
