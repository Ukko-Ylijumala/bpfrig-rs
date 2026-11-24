// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! XDP and TC helpers (feature `net`): interface facts from sysfs, the
    XDP mode an interface actually runs, a TC hook that leaves the
    interface's qdisc setup as it found it, and the two steps of an
    attachment that outlives its process: pinning the link of a fresh
    attach, and giving a pinned link the program of a new load.

    A note for the BPF side of a TCX program: under TCX a return of 0 is
    `TCX_PASS`, which ends the hook chain and skips later programs and
    classic filters. A program that only observes returns `TC_ACT_UNSPEC`
    (in `bpfrig_ebpf::consts`).
*/

use std::fmt::Debug;
use std::fs;
use std::io::ErrorKind;
use std::mem;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use aya::programs::links::{FdLink, PinnedLink};
use aya::programs::tc::{
    NlOptions, SchedClassifierLink, SchedClassifierLinkId, TcAttachOptions, TcAttachType,
    qdisc_add_clsact,
};
use aya::programs::xdp::{XdpLink, XdpLinkId};
use aya::programs::{ProgramError, SchedClassifier, Xdp};
use nix::errno::Errno;

use crate::pins::PinTxn;

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

/// What a pinned link did with the program of a new load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkSwap {
    /** The link runs the new program. The kernel replaced it in one step:
        no packet passed without a program, none ran both.
    */
    Swapped,
    /** The link is attached to nothing: its interface was deleted (and
        perhaps made again under the same name, which is another device).
        The kernel answers ENOLINK, and the link never attaches again.
        Nothing was changed: the caller removes the pin and attaches fresh.
    */
    Defunct,
}

/** True for the id of an attach aya made through netlink instead of a bpf
    link. aya has no accessor for the kind, and the one conversion that
    tells (`FdLink::try_from`) consumes the link and, for a netlink one,
    drops it without detaching: the program would stay on the interface
    with nothing owning it. The id's `Debug` names the variant, so it is
    read from there, before the link leaves its program.
*/
fn is_netlink(id: &impl Debug) -> bool {
    format!("{id:?}").contains("NlLinkId")
}

/// An attach that failed because the link's interface is gone.
fn is_defunct(err: &ProgramError) -> bool {
    matches!(err, ProgramError::SyscallError(sys)
        if sys.io_error.raw_os_error() == Some(Errno::ENOLINK as i32))
}

/// The link behind a pin, opened for a swap. The pin stays.
fn open_pinned_link(pin: &Path) -> Result<FdLink> {
    let link = PinnedLink::from_pin(pin)
        .with_context(|| format!("opening the pinned link {}", pin.display()))?;
    Ok(FdLink::from(link))
}

/** Take the link of an XDP attach out of `prog` and pin it as `<name>`:
    from then on the pin alone keeps the program attached, and dropping
    `prog` with its `Ebpf` detaches nothing. `id` is what `Xdp::attach`
    returned. An attach aya had to make through netlink (the kernel
    refused a bpf link with EINVAL) has no link to pin: that is an error,
    and the attach stays with `prog`, to end with it as usual. When the pin
    itself fails the link is gone, and the program detached.
*/
pub fn pin_xdp_link(prog: &mut Xdp, id: XdpLinkId, pins: &PinTxn, name: &str) -> Result<PathBuf> {
    if is_netlink(&id) {
        bail!("XDP was attached through netlink (no bpf link from this kernel): nothing to pin");
    }
    let link = prog.take_link(id).context("taking the XDP link from its program")?;
    let link = FdLink::try_from(link).map_err(|_| {
        anyhow!(
            "the XDP attach is not a bpf link, and is now nobody's: \
             `ip link set dev <iface> xdp off` lifts it"
        )
    })?;
    pins.pin_link(link, name)
}

/** Give the XDP link pinned at `pin` the program `prog` (already loaded):
    `bpf_link_update`, so the interface is never without a program. The
    link stays pinned, and stays attached when `prog` is dropped. An error
    other than [`LinkSwap::Defunct`] leaves the old program running.
*/
pub fn swap_xdp_link(prog: &mut Xdp, pin: &Path) -> Result<LinkSwap> {
    let link = XdpLink::try_from(open_pinned_link(pin)?)
        .with_context(|| format!("{} is not an XDP link", pin.display()))?;
    match prog.attach_to_link(link) {
        Ok(_) => Ok(LinkSwap::Swapped),
        Err(err) if is_defunct(&err) => Ok(LinkSwap::Defunct),
        Err(err) => Err(err)
            .with_context(|| format!("replacing the program of the XDP link {}", pin.display())),
    }
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

    A TCX attach can be made to outlive the process: [`pin`](Self::pin)
    after `attach`, and [`adopt`](Self::adopt) in the next one. A pinned
    hook is attached for as long as its pin exists, so dropping the hook
    or its program leaves it running; `detach` removes the pin as well.
*/
pub struct TcHook {
    iface: String,
    direction: TcAttachType,
    link: Option<SchedClassifierLinkId>,
    added_clsact: bool,
    /// The pin that keeps the link, once pinned or adopted.
    pinned: Option<PathBuf>,
}

impl TcHook {
    pub fn new(iface: &str, direction: TcAttachType) -> Self {
        Self { iface: iface.to_string(), direction, link: None, added_clsact: false, pinned: None }
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub fn attached(&self) -> bool {
        self.link.is_some() || self.pinned.is_some()
    }

    /// True when a pin keeps the attachment ([`pin`](Self::pin), [`adopt`](Self::adopt)).
    pub fn pinned(&self) -> bool {
        self.pinned.is_some()
    }

    /** Attach `prog` (already loaded). The link lives until `detach`, or
        until the program is dropped with its `Ebpf`.
    */
    pub fn attach(&mut self, prog: &mut SchedClassifier) -> Result<()> {
        if self.attached() {
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

    /** Take the link `attach` made out of `prog` and pin it as `<name>`,
        so the hook stays attached when `prog` is dropped. Ok(false), with
        nothing changed, when the attach went through netlink: there is no
        link to pin, and the hook ends with its program as before. When the
        pin itself fails the link is gone, and the hook detached.
    */
    pub fn pin(&mut self, prog: &mut SchedClassifier, pins: &PinTxn, name: &str) -> Result<bool> {
        let Some(id) = self.link.take_if(|id| !is_netlink(id)) else {
            if self.link.is_some() {
                return Ok(false);
            }
            bail!("no TC attach on {} to pin", self.iface);
        };
        let link = prog.take_link(id).context("taking the TC link from its program")?;
        let link = FdLink::try_from(link).map_err(|_| {
            anyhow!("the TC attach on {} is not a bpf link, and is now nobody's", self.iface)
        })?;
        self.pinned = Some(pins.pin_link(link, name)?);
        Ok(true)
    }

    /** Take over the hook an earlier process pinned at `pin`, giving its
        link the program `prog` (already loaded) in one step. On
        [`LinkSwap::Swapped`] the hook is attached and pinned, as after
        `attach` and `pin`. On [`LinkSwap::Defunct`], and on an error,
        nothing changed and this hook is not attached.
    */
    pub fn adopt(&mut self, prog: &mut SchedClassifier, pin: &Path) -> Result<LinkSwap> {
        if self.attached() {
            bail!("TC program already attached on {}", self.iface);
        }
        let link = SchedClassifierLink::try_from(open_pinned_link(pin)?)
            .with_context(|| format!("{} is not a TC link", pin.display()))?;
        match prog.attach_to_link(link) {
            Ok(id) => {
                self.link = Some(id);
                self.pinned = Some(pin.to_path_buf());
                Ok(LinkSwap::Swapped)
            }
            Err(err) if is_defunct(&err) => Ok(LinkSwap::Defunct),
            Err(err) => Err(err).with_context(|| {
                format!("replacing the program of the TC link {}", pin.display())
            }),
        }
    }

    /** Detach `prog`; Ok when it was not attached. aya forgets the link
        either way, so after an error the kernel keeps running the program
        until it is unloaded. A pinned hook loses its pin too, which is
        what detaches it. Call [`release_qdisc`](Self::release_qdisc)
        after this.
    */
    pub fn detach(&mut self, prog: &mut SchedClassifier) -> Result<()> {
        let unpinned = match self.pinned.take() {
            Some(pin) => match fs::remove_file(&pin) {
                Err(err) if err.kind() != ErrorKind::NotFound => {
                    Err(err).with_context(|| format!("removing {}", pin.display()))
                }
                _ => Ok(()),
            },
            None => Ok(()),
        };
        if let Some(link) = self.link.take() {
            prog.detach(link).with_context(|| format!("detaching TC on {}", self.iface))?;
        }
        unpinned
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
