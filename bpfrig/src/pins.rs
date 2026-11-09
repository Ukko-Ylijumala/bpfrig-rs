// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! bpffs and the per-tool pin directory.

    A tool that pins and exits keeps everything it attached in one
    directory, `/sys/fs/bpf/<tool>`: a link per attached program and the
    maps a later invocation reads back. Removing a pinned link is what
    detaches its program, so `--unload` is "remove the directory".

    Loading goes through a [`PinTxn`]: every pin made through it is
    removed again on drop unless [`PinTxn::commit`] was called, so a load
    that fails half-way (an attach error, a failed self-test, a panic)
    leaves nothing behind that looks loaded. It removes its own pins only:
    a second load that raced the first one into the directory and then
    failed must not take the first one's pins with it.

    A resident tool pins its maps for its own subcommands instead, holds
    the transaction for its whole run, and claims with
    [`Existing::ReplaceStale`], so the pins of a run that was killed
    without cleanup do not block the next one.
*/

use std::cell::RefCell;
use std::error::Error as StdError;
use std::fmt;
use std::fs;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aya::maps::MapData;
use aya::programs::links::FdLink;
use nix::mount::{MsFlags, mount};
use nix::sys::statfs::{BPF_FS_MAGIC, statfs};

use crate::maps::map_in_use;

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

/** [`ensure_bpffs`] for another path. A path already on a bpffs, the
    mount point or a directory inside one, is used as it is: stacking a
    second bpffs over a populated one would hide every existing pin. Any
    other existing directory gets a bpffs mounted on it.
*/
pub fn ensure_bpffs_at(path: &Path) -> Result<()> {
    let fs = statfs(path).with_context(|| format!("statfs {}", path.display()))?;
    if fs.filesystem_type() == BPF_FS_MAGIC {
        return Ok(());
    }
    mount(Some("bpf"), path, Some("bpf"), MsFlags::empty(), None::<&str>)
        .with_context(|| format!("mounting bpffs at {}", path.display()))?;
    Ok(())
}

/// What [`PinDir::claim_with`] does with a pin directory that exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Existing {
    /** Refuse: the tool is loaded. The pin-and-exit tools, whose pinned
        links are what keeps them loaded ([`PinDir::claim`]).
    */
    Refuse,
    /** Clear it unless something in it is live. A resident tool killed
        without cleanup leaves its map pins behind, and those are stale
        once no loaded program uses the maps. A map a loaded program still
        uses belongs to a running instance, and anything that is not a map
        (a pinned link or program) is live by definition: both refuse.
        A map whose users cannot be listed counts as stale.
    */
    ReplaceStale,
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
        self.claim_with(Existing::Refuse)
    }

    /// [`claim`](Self::claim), with a choice of what an existing directory means.
    pub fn claim_with(&self, existing: Existing) -> Result<PinTxn<'_>> {
        ensure_bpffs_at(&self.bpffs)?;
        if self.exists() {
            match existing {
                Existing::Refuse => bail!("already loaded: {self} exists (use --unload first)"),
                Existing::ReplaceStale => {
                    self.refuse_live()?;
                    self.remove_all()?;
                }
            }
        }
        fs::create_dir_all(&self.dir).with_context(|| format!("creating {self}"))?;
        Ok(PinTxn { dir: self, made: RefCell::default(), committed: false })
    }

    /// Fail when any pin in the directory is live (see [`Existing::ReplaceStale`]).
    fn refuse_live(&self) -> Result<()> {
        for name in self.files() {
            let path = self.dir.join(&name);
            let data = MapData::from_pin(&path).with_context(|| {
                format!(
                    "{} is not a pinned map, so it may be live (remove it by hand if not)",
                    path.display()
                )
            })?;
            if map_in_use(&data) == Some(true) {
                bail!(
                    "{self} belongs to a running instance: a loaded program still uses \
                     its pinned map {name}"
                );
            }
        }
        Ok(())
    }
}

impl fmt::Display for PinDir {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.dir.display().fmt(f)
    }
}

/** A load in progress. Dropping it without [`commit`](Self::commit)
    removes every pin made through it, and the directory once it is empty.

    Only its own pins: the claim is a check, not a lock, so two loads
    started together can both hold a transaction on the same directory.
    The one that loses (its attach or its pin fails) then leaves the
    winner's pins alone; removing "everything in the directory" would
    unload a pin-and-exit tool, or strand a resident one's subcommands.
    A pin made by hand at a path from the `PinDir` is not tracked, so
    every pin of a load goes through [`pin_with`](Self::pin_with) or a
    helper built on it (`pin_link`, `maps::pin_maps`).

    A tool that pins and exits commits once its self-test has passed. A
    resident tool can hold the transaction for its whole run and never
    commit, so its pins go away on any exit, including a panic unwind.

    Derefs to the [`PinDir`], for the path helpers.
*/
pub struct PinTxn<'a> {
    dir: &'a PinDir,
    /// The pins this transaction made, in order.
    made: RefCell<Vec<PathBuf>>,
    committed: bool,
}

impl PinTxn<'_> {
    /// Keep the pins.
    pub fn commit(mut self) {
        self.committed = true;
    }

    /** Make the pin `<name>` with `pin`, which gets the path, and record
        it as this transaction's. A pin that fails is not recorded: a
        path that already exists (EEXIST) is someone else's pin.
    */
    pub fn pin_with<E>(&self, name: &str, pin: impl FnOnce(&Path) -> Result<(), E>) -> Result<PathBuf>
    where
        E: StdError + Send + Sync + 'static,
    {
        let path = self.dir.path(name)?;
        pin(&path).with_context(|| format!("pinning {}", path.display()))?;
        self.made.borrow_mut().push(path.clone());
        Ok(path)
    }

    /// Pin a link as `<name>` and return the path.
    pub fn pin_link(&self, link: FdLink, name: &str) -> Result<PathBuf> {
        self.pin_with(name, |path| link.pin(path).map(drop))
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
        if self.committed {
            return;
        }
        for path in self.made.get_mut().drain(..).rev() {
            let _ = fs::remove_file(path);
        }
        /* Fails, as it should, while someone else's pins are in it. */
        let _ = fs::remove_dir(&self.dir.dir);
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

    /// A transaction on `pins` as `claim` returns it, without the bpffs
    /// mount: a plain directory stands in, and a file write for a pin.
    fn txn_on(pins: &PinDir) -> PinTxn<'_> {
        fs::create_dir_all(pins.dir()).unwrap();
        PinTxn { dir: pins, made: RefCell::default(), committed: false }
    }

    fn write_pin(txn: &PinTxn, name: &str) -> Result<PathBuf> {
        txn.pin_with(name, |path| fs::write(path, b""))
    }

    /// The transaction removes what it pinned unless committed, and the
    /// directory with it.
    #[test]
    fn uncommitted_transaction_removes_its_pins() {
        let root = env::temp_dir().join(format!("bpfrig-pins-{}", process::id()));
        let pins = PinDir::under(&root, "tool");
        for commit in [false, true] {
            let txn = txn_on(&pins);
            write_pin(&txn, "stats").unwrap();
            assert_eq!(txn.files(), vec!["stats".to_string()]);
            if commit {
                txn.commit();
                assert!(pins.has("stats"));
            } else {
                drop(txn);
                assert!(!pins.exists());
            }
        }
        pins.remove_all().unwrap();
        let _ = fs::remove_dir(&root);
    }

    /** Two loads raced into one directory: the loser's unwind removes
        its own pins and leaves the winner's, and the directory, in place.
        A pin it failed to make (the winner's name) was never its own.
    */
    #[test]
    fn a_failed_load_leaves_another_loads_pins() {
        let root = env::temp_dir().join(format!("bpfrig-pins-race-{}", process::id()));
        let pins = PinDir::under(&root, "tool");
        let winner = txn_on(&pins);
        let loser = txn_on(&pins);
        write_pin(&winner, "policy").unwrap();
        write_pin(&loser, "scratch").unwrap();
        let taken = loser.pin_with("policy", |path| fs::File::create_new(path).map(drop));
        assert!(taken.is_err());
        drop(loser);
        assert_eq!(pins.files(), vec!["policy".to_string()]);
        drop(winner);
        assert!(!pins.exists());
        let _ = fs::remove_dir(&root);
    }
}
