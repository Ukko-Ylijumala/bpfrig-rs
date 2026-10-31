// Copyright (c) 2026 Mikko Tanner. All rights reserved.

//! Small facts about the running kernel.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use nix::time::{ClockId, clock_gettime};

pub const NS_PER_SEC: u64 = 1_000_000_000;
pub const OSRELEASE: &str = "/proc/sys/kernel/osrelease";
const MOUNTS: &str = "/proc/self/mounts";

/** CLOCK_MONOTONIC in nanoseconds: the clock `bpf_ktime_get_ns()` reads,
    so it compares directly with timestamps a program stored in a map.
*/
pub fn ktime_ns() -> Result<u64> {
    let ts = clock_gettime(ClockId::CLOCK_MONOTONIC).context("clock_gettime(CLOCK_MONOTONIC)")?;
    Ok((ts.tv_sec() as u64)
        .saturating_mul(NS_PER_SEC)
        .saturating_add(ts.tv_nsec().max(0) as u64))
}

/// The running kernel's release string, e.g. `6.8.12-11-pve`.
pub fn os_release() -> Result<String> {
    let release = fs::read_to_string(OSRELEASE).with_context(|| format!("no {OSRELEASE}"))?;
    Ok(release.trim().to_string())
}

/// Mount points of every mount of one filesystem type.
pub fn mounts_of(fstype: &str) -> Result<Vec<PathBuf>> {
    let mounts = fs::read_to_string(MOUNTS).with_context(|| format!("cannot read {MOUNTS}"))?;
    Ok(mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let (_dev, mnt, ty) = (fields.next()?, fields.next()?, fields.next()?);
            (ty == fstype).then(|| PathBuf::from(mnt))
        })
        .collect())
}

/** A kernel build config, normally the running kernel's
    `/boot/config-<release>`.
*/
pub struct KernelConfig {
    path: PathBuf,
    text: String,
}

impl KernelConfig {
    /** The running kernel's config. The error says which file was missing,
        short enough to quote as the source of a verdict.
    */
    pub fn running() -> Result<Self> {
        let path = PathBuf::from(format!("/boot/config-{}", os_release()?));
        let text = fs::read_to_string(&path).with_context(|| format!("no {}", path.display()))?;
        Ok(Self { path, text })
    }

    /// A config parsed from text, for tests and for configs read elsewhere.
    pub fn from_text(path: impl Into<PathBuf>, text: String) -> Self {
        Self { path: path.into(), text }
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }

    /** The value of one option, quotes stripped (`CONFIG_LSM` gives
        `landlock,lockdown,...`). None when unset or `# ... is not set`.
    */
    pub fn get(&self, key: &str) -> Option<&str> {
        self.text
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
            .map(|value| value.trim_matches('"'))
    }

    /// True for a `=y` option.
    pub fn enabled(&self, key: &str) -> bool {
        self.get(key) == Some("y")
    }
}

/* ===== tests ===== */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_values() {
        let config = KernelConfig::from_text(
            "/boot/config-test",
            "# CONFIG_FOO is not set\nCONFIG_BPF_JIT_ALWAYS_ON=y\n\
             CONFIG_LSM=\"landlock,lockdown,bpf\"\nCONFIG_BPF_JIT=m\n"
                .to_string(),
        );
        assert!(config.enabled("CONFIG_BPF_JIT_ALWAYS_ON"));
        assert!(!config.enabled("CONFIG_BPF_JIT"));
        assert_eq!(config.get("CONFIG_LSM"), Some("landlock,lockdown,bpf"));
        assert_eq!(config.get("CONFIG_FOO"), None);
        /* A prefix of a longer option name is not that option. */
        assert_eq!(config.get("CONFIG_BPF_JIT_ALWAYS"), None);
    }

    #[test]
    fn clock_moves_forward() {
        let a = ktime_ns().unwrap();
        let b = ktime_ns().unwrap();
        assert!(b >= a && a > 0);
    }
}
