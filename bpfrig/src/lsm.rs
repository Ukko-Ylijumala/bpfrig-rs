// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! The `bpf` LSM: whether it runs now, attaching to it, and whether it
    will still run after the next boot.

    An LSM program attaches without complaint on a kernel where `bpf` is
    not in the active LSM list, and is then never called. The list is
    fixed at boot (`lsm=` on the kernel command line, or the built-in
    `CONFIG_LSM`), so nothing at runtime can change it.
*/

use std::fs;

use anyhow::{Context, Result, bail};
use aya::programs::Lsm;
use aya::programs::links::FdLink;
use aya::{Btf, Ebpf};

use crate::Attached;
use crate::host::KernelConfig;
use crate::pins::PinTxn;

pub const LSM_FILE: &str = "/sys/kernel/security/lsm";
/** Where the persistent kernel command line lives, in the order checked:
    systemd-boot / proxmox-boot-tool hosts keep it in /etc/kernel/cmdline,
    GRUB hosts in /etc/default/grub. Editing the one a host does not boot
    from is a silent no-op, which is what [`boot_lsm`] exists to catch.
*/
pub const CMDLINE_FILES: &[&str] = &["/etc/kernel/cmdline", "/etc/default/grub"];

/// The LSM program a tool attaches, the hook it binds to, and its pin name.
#[derive(Clone, Copy, Debug)]
pub struct LsmTarget {
    pub prog: &'static str,
    pub hook: &'static str,
    pub pin: &'static str,
}

/** Whether the `bpf` LSM will be active after the next boot. `Unknown`
    means no boot config that could answer was readable; it is reported as
    such rather than guessed.
*/
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootLsm {
    Enabled,
    Missing,
    Unknown,
}

/** A [`BootLsm`] plus where it was read from. The source matters: `bpf` in
    `CONFIG_LSM` is the kernel's built-in default and can change with a
    kernel upgrade, while `lsm=` on the command line is pinned by the boot
    config.
*/
#[derive(Clone, Debug)]
pub struct BootLsmVerdict {
    pub state: BootLsm,
    pub source: String,
}

/// True when the `bpf` LSM is in the active list right now.
pub fn bpf_lsm_active() -> bool {
    fs::read_to_string(LSM_FILE).is_ok_and(|s| has_bpf(s.trim()))
}

/** Refuse when the `bpf` LSM is not active. `instead` is appended as the
    tool's own advice, e.g. "Use --mode tripwire on this host instead".
*/
pub fn require_bpf_lsm(instead: &str) -> Result<()> {
    if bpf_lsm_active() {
        return Ok(());
    }
    let mut msg = format!(
        "the `bpf` LSM is not in {LSM_FILE}: an LSM program would attach but \
         never run. This is fixable only by booting with `lsm=...,bpf` (keep \
         the existing entries: `lsm=` replaces the built-in list, and dropping \
         apparmor disables LXC confinement)"
    );
    if !instead.is_empty() {
        msg = format!("{msg}. {instead}");
    }
    bail!(msg)
}

/// Load one LSM program against its hook, attach it, and pin the link.
pub fn attach_lsm(ebpf: &mut Ebpf, target: &LsmTarget, pins: &PinTxn) -> Result<Attached> {
    let btf = Btf::from_sys_fs().context("reading kernel BTF")?;
    let prog: &mut Lsm = ebpf
        .program_mut(target.prog)
        .with_context(|| format!("{} not found in the object", target.prog))?
        .try_into()?;
    prog.load(target.hook, &btf)
        .with_context(|| format!("verifier rejected {}", target.prog))?;
    let link_id = prog
        .attach()
        .with_context(|| format!("attaching lsm/{}", target.hook))?;
    let link: FdLink = prog.take_link(link_id)?.into();
    pins.pin_link(link, target.pin)?;
    Ok(Attached::Lsm { prog: target.prog, hook: target.hook })
}

/** Whether the `bpf` LSM will still be active after the next reboot.

    Reads the persistent boot config rather than /proc/cmdline, because
    the question is about the next boot: an `lsm=` edit not yet applied,
    or one written to the file this host does not boot from, both look
    fine in /proc/cmdline until the reboot drops the program.

    In order: the last `lsm=` in [`CMDLINE_FILES`]; with none anywhere,
    the running kernel's `CONFIG_LSM`, the best available proxy for the
    kernel that boots next; otherwise `Unknown`.
*/
pub fn boot_lsm() -> BootLsmVerdict {
    let verdict = |list: &str, source: String| BootLsmVerdict {
        state: if has_bpf(list) { BootLsm::Enabled } else { BootLsm::Missing },
        source,
    };

    for file in CMDLINE_FILES {
        if let Ok(text) = fs::read_to_string(file)
            && let Some(list) = lsm_from_boot_text(&text, file.ends_with("grub"))
        {
            return verdict(&list, format!("lsm= in {file}"));
        }
    }

    let config = match KernelConfig::running() {
        Ok(config) => config,
        Err(err) => return BootLsmVerdict { state: BootLsm::Unknown, source: err.to_string() },
    };
    let path = config.path().display();
    match config.get("CONFIG_LSM") {
        Some(list) => verdict(list, format!("CONFIG_LSM in {path}")),
        None => BootLsmVerdict {
            state: BootLsm::Unknown,
            source: format!("no CONFIG_LSM in {path}"),
        },
    }
}

/** Print a warning when the `bpf` LSM would not survive a reboot. Meant
    for `--load`, where loading before making it persistent is legitimate;
    a `--check` should treat the same condition as an error.
*/
pub fn warn_unless_persistent() {
    let files = CMDLINE_FILES.join(" or ");
    match boot_lsm().state {
        BootLsm::Enabled => {}
        BootLsm::Missing => eprintln!(
            "\nWARNING: no `lsm=...,bpf` in {files}. The LSM program is active \
             now but WILL VANISH at the next reboot.\n\
             `lsm=` REPLACES the built-in list rather than adding to it: write \
             out every entry, since dropping apparmor silently disables LXC \
             confinement. A host that boots through proxmox-boot-tool reads \
             /etc/kernel/cmdline and needs `proxmox-boot-tool refresh` after \
             the edit; editing /etc/default/grub there does nothing."
        ),
        BootLsm::Unknown => eprintln!(
            "\nWARNING: could not determine whether the `bpf` LSM is configured \
             to persist across reboots (no readable {files}). Verify by hand."
        ),
    }
}

fn has_bpf(list: &str) -> bool {
    list.split(',').any(|lsm| lsm == "bpf")
}

/** The last `lsm=` list in a boot config file's text, if any.

    Commented-out lines are skipped, and in a GRUB config only the
    `GRUB_CMDLINE_LINUX*` assignments count. /etc/default/grub often ships
    full of commented examples, and believing one of those would report a
    program as reboot-safe when it is not.
*/
fn lsm_from_boot_text(text: &str, grub: bool) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .filter(|line| !grub || line.starts_with("GRUB_CMDLINE_LINUX"))
        .flat_map(|line| line.split([' ', '\t', '"', '\'']))
        .filter_map(|tok| tok.strip_prefix("lsm="))
        .map(str::to_owned)
        .next_back()
}

/* ===== tests ===== */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_cmdline_file() {
        let text = "root=ZFS=rpool/ROOT/pve-1 boot=zfs lsm=lockdown,yama,apparmor,bpf\n";
        assert_eq!(lsm_from_boot_text(text, false).as_deref(), Some("lockdown,yama,apparmor,bpf"));
        assert_eq!(lsm_from_boot_text("quiet\n", false), None);
    }

    #[test]
    fn grub_ignores_comments_and_other_assignments() {
        let text = "\
            # GRUB_CMDLINE_LINUX=\"lsm=bpf\"\n\
            GRUB_DISABLE_OS_PROBER=\"lsm=nonsense\"\n\
            GRUB_CMDLINE_LINUX_DEFAULT=\"quiet lsm=apparmor\"\n\
            GRUB_CMDLINE_LINUX=\"lsm=landlock,apparmor,bpf\"\n";
        assert_eq!(lsm_from_boot_text(text, true).as_deref(), Some("landlock,apparmor,bpf"));
    }

    #[test]
    fn bpf_must_be_a_whole_entry() {
        assert!(has_bpf("lockdown,bpf"));
        assert!(!has_bpf("lockdown,notbpf"));
        assert!(!has_bpf(""));
    }
}
