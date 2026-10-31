// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! bpffs and the per-tool pin directory.

    A tool that pins and exits keeps everything it attached in one
    directory, `/sys/fs/bpf/<tool>`: a link per attached program and the
    maps a later invocation reads back. Removing a pinned link is what
    detaches its program, so `--unload` is "remove the directory".

    Loading goes through a [`PinTxn`]: every pin made while it is held is
    removed again on drop unless [`PinTxn::commit`] was called, so a load
    that fails half-way (an attach error, a failed self-test, a panic)
    leaves nothing behind that looks loaded.
*/

use std::fmt;
use std::fs;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aya::programs::links::FdLink;
use nix::mount::{MsFlags, mount};

use crate::host::mounts_of;

pub const BPFFS: &str = "/sys/fs/bpf";
/** Prefix of a link pin: `link_<symbol>` for a kprobe, `link_<name>`
    otherwise. An underscore, not a dot (see [`PinDir::path`]).
*/
pub const LINK_PREFIX: &str = "link_";

/** Make sure a bpffs is mounted at /sys/fs/bpf, mounting one if missing,
    so that pins have somewhere to live.
*/
pub fn ensure_bpffs() -> Result<()> {
    ensure_bpffs_at(Path::new(BPFFS))
}

/** [`ensure_bpffs`] for another mount point. An unreadable mount table is
    an error rather than a reason to mount anyway: stacking a second bpffs
    over a populated one would hide every existing pin.
*/
pub fn ensure_bpffs_at(path: &Path) -> Result<()> {
    if mounts_of("bpf")?.iter().any(|mnt| mnt == path) {
        return Ok(());
    }
    mount(Some("bpf"), path, Some("bpf"), MsFlags::empty(), None::<&str>)
        .with_context(|| format!("mounting bpffs at {}", path.display()))?;
    Ok(())
}

/// One tool's pin directory, e.g. `/sys/fs/bpf/unix-gc-guard`.
#[derive(Clone, Debug)]
pub struct PinDir {
    bpffs: PathBuf,
    dir: PathBuf,
}

impl PinDir {
    /** `/sys/fs/bpf/<tool>`. Panics when `tool` is not a valid pin name
        (empty, or with a `.` or `/`): it is a constant of the tool, so that
        is a bug, not a runtime error.
    */
    pub fn new(tool: &str) -> Self {
        Self::under(Path::new(BPFFS), tool)
    }

    /** `<bpffs>/<tool>`, for a tool that takes its bpffs as an option.
        Panics as [`new`](Self::new) does.
    */
    pub fn under(bpffs: &Path, tool: &str) -> Self {
        if let Err(err) = check_component(tool) {
            panic!("invalid tool name for a pin directory: {err}");
        }
        Self { bpffs: bpffs.to_path_buf(), dir: bpffs.join(tool) }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn exists(&self) -> bool {
        self.dir.exists()
    }

    /** The path of one pin in the directory. The name may not contain a
        `.` (or a `/`): `bpf_lookup()` refuses any bpffs path component
        with a dot with EPERM. That only shows up at `BPF_OBJ_PIN`, after
        the attach has already succeeded, so it is refused here instead.
    */
    pub fn path(&self, name: &str) -> Result<PathBuf> {
        check_component(name)?;
        Ok(self.dir.join(name))
    }

    /// The path of the link pin for one symbol or hook: `link_<sym>`.
    pub fn link_path(&self, sym: &str) -> Result<PathBuf> {
        self.path(&format!("{LINK_PREFIX}{sym}"))
    }

    /// True when a pin of that name exists.
    pub fn has(&self, name: &str) -> bool {
        self.path(name).is_ok_and(|path| path.exists())
    }

    /// Names of the pins in the directory, sorted; empty when it is absent.
    pub fn files(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .flatten()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    /** Remove every pin and then the directory. Removing a pinned link is
        what detaches its program.
    */
    pub fn remove_all(&self) -> Result<()> {
        for name in self.files() {
            let path = self.dir.join(&name);
            fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
        }
        let _ = fs::remove_dir(&self.dir);
        Ok(())
    }

    /** Start a load: mount bpffs if needed, refuse when the directory
        already exists (the tool is loaded), and create it.
    */
    pub fn claim(&self) -> Result<PinTxn<'_>> {
        ensure_bpffs_at(&self.bpffs)?;
        if self.exists() {
            bail!("already loaded: {self} exists (use --unload first)");
        }
        fs::create_dir_all(&self.dir).with_context(|| format!("creating {self}"))?;
        Ok(PinTxn { dir: self, committed: false })
    }
}

impl fmt::Display for PinDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.dir.display().fmt(f)
    }
}

/** A load in progress. Dropping it without [`commit`](Self::commit)
    removes every pin in the directory, and the directory itself.

    A tool that pins and exits commits once its self-test has passed. A
    resident tool can hold the transaction for its whole run and never
    commit, so its pins go away on any exit, including a panic unwind.

    Derefs to the [`PinDir`], for the path helpers.
*/
pub struct PinTxn<'a> {
    dir: &'a PinDir,
    committed: bool,
}

impl PinTxn<'_> {
    /// Keep the pins.
    pub fn commit(mut self) {
        self.committed = true;
    }

    /// Pin a link as `<name>` and return the path.
    pub fn pin_link(&self, link: FdLink, name: &str) -> Result<PathBuf> {
        let path = self.dir.path(name)?;
        link.pin(&path).with_context(|| format!("pinning {}", path.display()))?;
        Ok(path)
    }
}

impl Deref for PinTxn<'_> {
    type Target = PinDir;

    fn deref(&self) -> &PinDir {
        self.dir
    }
}

impl Drop for PinTxn<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.dir.remove_all();
        }
    }
}

/// A single bpffs path component that `bpf_lookup()` will accept.
fn check_component(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("empty bpffs pin name");
    }
    if name.contains('/') {
        bail!("bpffs pin name {name:?} contains a '/'");
    }
    if name.contains('.') {
        bail!("bpffs pin name {name:?} contains a '.', which bpf_lookup() rejects with EPERM");
    }
    Ok(())
}

/* ===== tests ===== */

#[cfg(test)]
mod tests {
    use std::{env, process};

    use super::*;

    #[test]
    #[should_panic(expected = "invalid tool name")]
    fn tool_name_with_a_dot_panics() {
        PinDir::new("my.tool");
    }

    #[test]
    fn pin_names_are_checked() {
        let pins = PinDir::new("tool");
        assert_eq!(pins.dir(), Path::new("/sys/fs/bpf/tool"));
        assert_eq!(pins.link_path("unix_gc").unwrap(), Path::new("/sys/fs/bpf/tool/link_unix_gc"));
        assert!(pins.path("link.unix_gc").is_err());
        assert!(pins.path("a/b").is_err());
        assert!(pins.path("").is_err());
        assert!(!pins.has("link.x"));
    }

    /** The transaction removes what was pinned unless committed. A plain
        directory stands in for bpffs; nothing here needs the real thing
        except `claim`, so the transaction is built by hand.
    */
    #[test]
    fn uncommitted_transaction_removes_its_pins() {
        let root = env::temp_dir().join(format!("bpfrig-pins-{}", process::id()));
        let pins = PinDir::under(&root, "tool");
        for commit in [false, true] {
            fs::create_dir_all(pins.dir()).unwrap();
            fs::write(pins.path("stats").unwrap(), b"").unwrap();
            let txn = PinTxn { dir: &pins, committed: false };
            assert_eq!(txn.files(), vec!["stats".to_string()]);
            if commit {
                txn.commit();
                assert!(pins.exists());
            } else {
                drop(txn);
                assert!(!pins.exists());
            }
        }
        pins.remove_all().unwrap();
        let _ = fs::remove_dir(&root);
    }
}
