// Copyright (c) 2026 Mikko Tanner. All rights reserved.

/*! The `build.rs` of an aya tool, reduced to its package name:

    ```ignore
    fn main() -> anyhow::Result<()> {
        bpfrig_build::build_ebpf("unix-gc-guard-ebpf")
    }
    ```

    The eBPF crate must be a member of the tool's workspace. Its object
    lands in `OUT_DIR/<bin name>`, where `bpfrig::embed!("<bin name>")`
    picks it up.

    On top of aya-build this adds:

    - Rebuilds when anything the object is built from changes. aya-build
      only watches the eBPF crate's own directory; the object also bakes
      in its local path dependencies (the tool's `-common` ABI crate, a
      `[patch]`ed `bpfrig-ebpf` checkout), and git or registry ones that
      only move in `Cargo.lock`. Without this, an edit to the shared ABI
      types rebuilds userspace against the new layout while `OUT_DIR`
      keeps the old object.
    - `SKIP_EBPF_BUILD=1` writes an empty stub for every bin instead of
      building, so userspace checks and builds without nightly and
      bpf-linker. Loading the stub fails at runtime with a clear message.
*/

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use aya_build::{Package as AyaPackage, Toolchain};
use cargo_metadata::{Metadata, MetadataCommand, Package, PackageId, TargetKind};

pub const SKIP_ENV: &str = "SKIP_EBPF_BUILD";

/// Build the workspace member `package` for the BPF target (nightly).
pub fn build_ebpf(package: &str) -> Result<()> {
    build_ebpf_with(package, Toolchain::default())
}

/// [`build_ebpf`] with a specific toolchain, e.g. a pinned nightly.
pub fn build_ebpf_with(package: &str, toolchain: Toolchain<'_>) -> Result<()> {
    println!("cargo::rerun-if-env-changed={SKIP_ENV}");
    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR not set")?);
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").context("OUT_DIR not set")?);

    /* --offline: the build already resolved everything, and a build script
       must not reach for the network. */
    let metadata = MetadataCommand::new()
        .manifest_path(manifest_dir.join("Cargo.toml"))
        .other_options(vec!["--offline".to_string()])
        .exec()
        .context("running cargo metadata")?;
    let ebpf = metadata
        .workspace_packages()
        .into_iter()
        .find(|pkg| pkg.name.as_str() == package)
        .with_context(|| format!("{package} is not a member of this workspace"))?;
    let bins = bin_names(ebpf);
    if bins.is_empty() {
        bail!("{package} has no [[bin]] target, so there is no object to embed");
    }

    if env::var_os(SKIP_ENV).is_some_and(|v| !v.is_empty() && v != "0") {
        for bin in &bins {
            let stub = out_dir.join(bin);
            fs::write(&stub, []).with_context(|| format!("writing {}", stub.display()))?;
        }
        println!(
            "cargo::warning={SKIP_ENV} set: wrote an empty stub for {package}; \
             loading it will fail at runtime"
        );
        return Ok(());
    }

    for dir in local_dependency_dirs(&metadata, &ebpf.id) {
        println!("cargo::rerun-if-changed={}", dir.display());
    }
    println!("cargo::rerun-if-changed={}", metadata.workspace_root.join("Cargo.lock"));

    let root_dir = ebpf
        .manifest_path
        .parent()
        .context("eBPF crate manifest has no parent directory")?;
    aya_build::build_ebpf(
        [AyaPackage { name: package, root_dir: root_dir.as_str(), ..Default::default() }],
        toolchain,
    )
}

fn bin_names(pkg: &Package) -> Vec<String> {
    pkg.targets
        .iter()
        .filter(|target| target.kind.contains(&TargetKind::Bin))
        .map(|target| target.name.clone())
        .collect()
}

/** The directories of every local (path or `[patch]`ed path) package the
    eBPF crate depends on, directly or not, itself excluded. A package with
    no `source` in the metadata is a local one.
*/
fn local_dependency_dirs(metadata: &Metadata, root: &PackageId) -> Vec<PathBuf> {
    let Some(resolve) = &metadata.resolve else {
        return Vec::new();
    };
    let mut seen = vec![root.clone()];
    let mut queue = vec![root.clone()];
    while let Some(id) = queue.pop() {
        let Some(node) = resolve.nodes.iter().find(|node| node.id == id) else {
            continue;
        };
        for dep in &node.dependencies {
            if !seen.contains(dep) {
                seen.push(dep.clone());
                queue.push(dep.clone());
            }
        }
    }
    metadata
        .packages
        .iter()
        .filter(|pkg| pkg.id != *root && pkg.source.is_none() && seen.contains(&pkg.id))
        .filter_map(|pkg| pkg.manifest_path.parent())
        .map(|dir| Path::new(dir.as_str()).to_path_buf())
        .collect()
}
