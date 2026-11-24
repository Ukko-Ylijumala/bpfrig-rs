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

    A tool whose attachment outlives its process does both: it commits,
    and its next start finds the directory live. That start asks what the
    directory holds ([`PinDir::contents`]), and works in it as it stands
    through [`PinDir::adopt`]: a transaction that still tracks only what
    it adds.
*/

use std::cell::RefCell;
use std::error::Error as StdError;
use std::fmt;
use std::fs;
use std::io::ErrorKind;
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
/// Suffix of the scratch pin [`PinDir::replace_with`] renames into place.
const REPLACE_SUFFIX: &str = "_new";

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

/// What a pin directory holds ([`PinDir::contents`]), the strongest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Contents {
    /// Absent, or empty.
    Nothing,
    /** Only maps, none of which a loaded program uses: what a resident
        tool killed without cleanup leaves. A map whose users cannot be
        listed counts as stale, as for [`Existing::ReplaceStale`].
    */
    StaleMaps,
    /// Only maps, and a loaded program uses one: a running instance's.
    LiveMaps,
    /** Something that is not a map: a pinned link, or a pinned program.
        Whatever it keeps attached outlives every process.
    */
    Links,
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

    /** Remove one pin; Ok(false) when there was none. Removing a pinned
        link detaches its program, once no process holds the link open.
    */
    pub fn remove(&self, name: &str) -> Result<bool> {
        let path = self.path(name)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err).with_context(|| format!("removing {}", path.display())),
        }
    }

    /** Put a new object at the pin `<name>`, in place of what is pinned
        there: `pin` pins it under a scratch name (`<name>_new`), which is
        then renamed over the old pin, so the path never stops naming an
        object. Readers that open the path afterwards get the new one;
        whoever holds the old one open keeps it. Not a transaction's pin,
        whichever way it is reached: the old pin cannot be brought back,
        so there is nothing to undo, and an uncommitted [`PinTxn`] leaves
        the new one where it is.
    */
    pub fn replace_with<E>(
        &self,
        name: &str,
        pin: impl FnOnce(&Path) -> Result<(), E>,
    ) -> Result<PathBuf>
    where
        E: StdError + Send + Sync + 'static,
    {
        let path = self.path(name)?;
        let scratch = self.path(&format!("{name}{REPLACE_SUFFIX}"))?;
        /* One left by a replace that died half-way. */
        let _ = fs::remove_file(&scratch);
        pin(&scratch).with_context(|| format!("pinning {}", scratch.display()))?;
        if let Err(err) = fs::rename(&scratch, &path) {
            let _ = fs::remove_file(&scratch);
            return Err(err).with_context(|| format!("replacing {}", path.display()));
        }
        Ok(path)
    }

    /** What the directory holds, for a start that has to choose between a
        fresh load, clearing a dead run's pins, taking over an attachment
        and refusing. A pin that does not open as a map counts as a link:
        so does one this process may not open at all.
    */
    pub fn contents(&self) -> Contents {
        let mut found = Contents::Nothing;
        for name in self.files() {
            match MapData::from_pin(self.dir.join(&name)) {
                Err(_) => return Contents::Links,
                Ok(data) if map_in_use(&data) == Some(true) => found = Contents::LiveMaps,
                Ok(_) if found == Contents::Nothing => found = Contents::StaleMaps,
                Ok(_) => {}
            }
        }
        found
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
        self.txn()
    }

    /** A transaction on the directory as it stands, live pins and all:
        nothing is checked and nothing cleared, and it is created when
        missing. For a start that takes over what an earlier one left
        attached ([`contents`](Self::contents) says what that is). The
        transaction tracks only what it adds: dropped uncommitted it
        removes those pins and leaves the rest, the directory included, so
        a take-over that fails does not unload what was running.
    */
    pub fn adopt(&self) -> Result<PinTxn<'_>> {
        ensure_bpffs_at(&self.bpffs)?;
        self.txn()
    }

    /// The directory, created when missing, and an empty transaction on it.
    fn txn(&self) -> Result<PinTxn<'_>> {
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
        pins.txn().unwrap()
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

    /** A take-over of a live directory that fails: the transaction it
        worked through removes the pins it added and nothing else, so what
        was attached stays, and the directory with it. Committed, its
        additions stay too.
    */
    #[test]
    fn adopting_transaction_leaves_what_it_found() {
        let root = env::temp_dir().join(format!("bpfrig-pins-adopt-{}", process::id()));
        let pins = PinDir::under(&root, "tool");
        let first = txn_on(&pins);
        write_pin(&first, "link_xdp").unwrap();
        write_pin(&first, "policy").unwrap();
        first.commit();

        let failed = txn_on(&pins);
        write_pin(&failed, "link_egress").unwrap();
        assert!(write_pin(&failed, "scratch").is_ok());
        drop(failed);
        assert_eq!(pins.files(), vec!["link_xdp".to_string(), "policy".to_string()]);

        let taken = txn_on(&pins);
        write_pin(&taken, "link_egress").unwrap();
        taken.commit();
        assert_eq!(pins.files().len(), 3);

        assert!(pins.remove("link_egress").unwrap());
        assert!(!pins.remove("link_egress").unwrap());
        assert!(pins.remove("link.egress").is_err());
        pins.remove_all().unwrap();
        let _ = fs::remove_dir(&root);
    }

    /** A replaced pin: the path names the new object, the scratch name is
        gone, and a transaction that is dropped afterwards does not take
        the replacement back. A replace whose pin fails leaves the old one.
    */
    #[test]
    fn replace_renames_over_the_old_pin() {
        let root = env::temp_dir().join(format!("bpfrig-pins-replace-{}", process::id()));
        let pins = PinDir::under(&root, "tool");
        let first = txn_on(&pins);
        first.pin_with("config", |path| fs::write(path, b"old")).unwrap();
        first.commit();

        let txn = txn_on(&pins);
        let path = txn.replace_with("config", |path| fs::write(path, b"new")).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"new");
        drop(txn);
        assert_eq!(pins.files(), vec!["config".to_string()]);
        assert_eq!(fs::read(&path).unwrap(), b"new");

        let refused = pins.replace_with("config", |path| fs::File::open(path).map(drop));
        assert!(refused.is_err());
        assert_eq!(pins.files(), vec!["config".to_string()]);
        assert_eq!(fs::read(&path).unwrap(), b"new");

        pins.remove_all().unwrap();
        let _ = fs::remove_dir(&root);
    }

    /// Without a bpffs only two answers can be shown: nothing there, and
    /// a file that is no map, which counts as a link.
    #[test]
    fn contents_of_an_absent_empty_and_foreign_directory() {
        let root = env::temp_dir().join(format!("bpfrig-pins-contents-{}", process::id()));
        let pins = PinDir::under(&root, "tool");
        assert_eq!(pins.contents(), Contents::Nothing);
        let txn = txn_on(&pins);
        assert_eq!(pins.contents(), Contents::Nothing);
        write_pin(&txn, "link_xdp").unwrap();
        assert_eq!(pins.contents(), Contents::Links);
        drop(txn);
        let _ = fs::remove_dir(&root);
    }
}
