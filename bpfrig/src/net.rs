// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! XDP and TC helpers (feature `net`): interface facts from sysfs, the
    XDP mode an interface actually runs, and a TC hook that leaves the
    interface's qdisc setup as it found it.

    A note for the BPF side of a TCX program: under TCX a return of 0 is
    `TCX_PASS`, which ends the hook chain and skips later programs and
    classic filters. A program that only observes returns `TC_ACT_UNSPEC`
    (in `bpfrig_ebpf::consts`).
*/

use std::fs;
use std::mem;
use std::process::Command;

use anyhow::{Context, Result, bail};
use aya::programs::SchedClassifier;
use aya::programs::tc::{
    NlOptions, SchedClassifierLinkId, TcAttachOptions, TcAttachType, qdisc_add_clsact,
};

/// One attribute of an interface from `/sys/class/net/<iface>/<attr>`.
fn sysfs_net(iface: &str, attr: &str) -> Option<String> {
    fs::read_to_string(format!("/sys/class/net/{iface}/{attr}")).ok()
}

/// The members of a bond, in sysfs order; empty when `iface` is no bond.
pub fn bond_slaves(iface: &str) -> Vec<String> {
    sysfs_net(iface, "bonding/slaves")
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

pub fn ifindex_of(iface: &str) -> Option<u32> {
    sysfs_net(iface, "ifindex")?.trim().parse().ok()
}

pub fn mtu_of(iface: &str) -> Option<u32> {
    sysfs_net(iface, "mtu")?.trim().parse().ok()
}

/// The XDP mode an interface reports, from `ip link show`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XdpAttach {
    /// Native (driver) or hardware-offloaded: not generic.
    Native,
    /// Generic/skb (`xdpgeneric`), alone or next to a native one (`xdpmulti`).
    Generic,
    /** Could not tell: `ip` missing, or no XDP shown for this interface.
        Common for a bond member when the program is attached to, and
        reported on, the master.
    */
    Unconfirmed,
}

/** The XDP mode `iface` actually runs, as the kernel reports it. An attach
    that asked for driver mode and succeeded is already native, so this is
    a diagnostic: a positive `Generic` is worth failing on, `Unconfirmed`
    is not.
*/
pub fn verify_xdp_mode(iface: &str) -> XdpAttach {
    match Command::new("ip").args(["link", "show", iface]).output() {
        Ok(out) => xdp_mode_of(&String::from_utf8_lossy(&out.stdout)),
        Err(_) => XdpAttach::Unconfirmed,
    }
}

/** The attach mode in an `ip link show` dump. It is the mode word on the
    first line: `xdp`, `xdpgeneric`, `xdpoffload` or `xdpmulti` (generic
    and native both). iproute2 leaves it out under `-d`, where every mode
    prints the same `prog/xdp` line. Whole first-line tokens only: the
    interface name could itself start with `xdp`, but it carries a `:`,
    so it never equals a mode word.
*/
fn xdp_mode_of(dump: &str) -> XdpAttach {
    for word in dump.lines().next().unwrap_or("").split_whitespace() {
        match word {
            "xdpgeneric" | "xdpmulti" => return XdpAttach::Generic,
            "xdp" | "xdpoffload" => return XdpAttach::Native,
            _ => {}
        }
    }
    XdpAttach::Unconfirmed
}

/** A TC program's attachment to one interface and direction, and whether
    the clsact qdisc it needed is its own.

    `attach` takes aya's default first, a TCX link on kernel 6.6 and later
    (no qdisc needed), netlink below. If that fails it attaches through
    netlink explicitly, which needs a clsact qdisc, added only then. aya's
    add is exclusive (`NLM_F_EXCL`), so a success means the qdisc is new
    and the hook's to remove; an existing one answers EEXIST and stays
    someone else's. `release_qdisc` removes it again once the program is
    off it, and `Drop` does so silently as a backstop. Removal goes
    through iproute2's `tc`: aya adds a clsact but has no delete.
*/
pub struct TcHook {
    iface: String,
    direction: TcAttachType,
    link: Option<SchedClassifierLinkId>,
    added_clsact: bool,
}

impl TcHook {
    pub fn new(iface: &str, direction: TcAttachType) -> Self {
        Self { iface: iface.to_string(), direction, link: None, added_clsact: false }
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn attached(&self) -> bool {
        self.link.is_some()
    }

    /** Attach `prog` (already loaded). The link lives until `detach`, or
        until the program is dropped with its `Ebpf`.
    */
    pub fn attach(&mut self, prog: &mut SchedClassifier) -> Result<()> {
        if self.link.is_some() {
            bail!("TC program already attached on {}", self.iface);
        }
        let link = match prog.attach(&self.iface, self.direction) {
            Ok(link) => link,
            Err(first) => {
                self.added_clsact |= qdisc_add_clsact(&self.iface).is_ok();
                let netlink = TcAttachOptions::Netlink(NlOptions::default());
                prog.attach_with_options(&self.iface, self.direction, netlink)
                    .with_context(|| format!("attaching TC on {} (first attempt: {first})", self.iface))?
            }
        };
        self.link = Some(link);
        Ok(())
    }

    /** Detach `prog`; Ok when it was not attached. aya forgets the link
        either way, so after an error the kernel keeps running the program
        until it is unloaded. Call [`release_qdisc`](Self::release_qdisc)
        after this.
    */
    pub fn detach(&mut self, prog: &mut SchedClassifier) -> Result<()> {
        let Some(link) = self.link.take() else {
            return Ok(());
        };
        prog.detach(link).with_context(|| format!("detaching TC on {}", self.iface))
    }

    /** Remove the clsact qdisc `attach` added, taking any filter still on
        it along. Ok(false) when there was none of ours; it is tried once
        either way. The error names the command that lifts it by hand.
    */
    pub fn release_qdisc(&mut self) -> Result<bool> {
        if !mem::take(&mut self.added_clsact) {
            return Ok(false);
        }
        let iface = &self.iface;
        let by_hand = format!("`tc qdisc del dev {iface} clsact` lifts it");
        let out = Command::new("tc")
            .args(["qdisc", "del", "dev", iface, "clsact"])
            .output()
            .with_context(|| format!("running tc; {by_hand}"))?;
        if !out.status.success() {
            bail!("{}; {by_hand}", String::from_utf8_lossy(&out.stderr).trim());
        }
        Ok(true)
    }
}

impl Drop for TcHook {
    fn drop(&mut self) {
        let _ = self.release_qdisc();
    }
}

/* ===== tests ===== */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xdp_mode_comes_from_the_first_line_mode_word() {
        let dump = |mode: &str| {
            format!(
                "3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 {mode} qdisc mq state UP\n    \
                 link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff\n    prog/xdp id 42 tag 0 jited\n"
            )
        };
        assert_eq!(xdp_mode_of(&dump("xdp")), XdpAttach::Native);
        assert_eq!(xdp_mode_of(&dump("xdpoffload")), XdpAttach::Native);
        assert_eq!(xdp_mode_of(&dump("xdpgeneric")), XdpAttach::Generic);
        assert_eq!(xdp_mode_of(&dump("xdpmulti")), XdpAttach::Generic);
        /* `ip -d` style: no mode word, only the `prog/xdp` line. */
        let detailed = "3: eth1: <UP> mtu 1500 qdisc mq state UP\n    prog/xdp id 42\n";
        assert_eq!(xdp_mode_of(detailed), XdpAttach::Unconfirmed);
        /* An interface named like a mode word is not one. */
        assert_eq!(xdp_mode_of("4: xdp: <UP> mtu 1500 qdisc noop\n"), XdpAttach::Unconfirmed);
        assert_eq!(xdp_mode_of(""), XdpAttach::Unconfirmed);
    }

    #[test]
    fn loopback_facts() {
        assert_eq!(ifindex_of("lo"), Some(1));
        assert!(mtu_of("lo").is_some());
        assert!(bond_slaves("lo").is_empty());
        assert_eq!(ifindex_of("no-such-iface"), None);
    }
}
