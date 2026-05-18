//! `zboot rename <BE> <new-name>` — `zfs rename` with peer-pointer
//! updates. Required so that the `pull --name fresh + default fresh +
//! reboot + drop old + rename fresh old` recipe doesn't dangle peer
//! pointers.
//!
//! Walk all datasets on imported pools, find every `zboot:mirror`
//! pointing at the old name, rewrite to the new name. Then rewrite our
//! own pointer's render (it still points at the same peer; the value
//! on disk doesn't change, but `status` will recompute correctly).

use std::io::Write;

use anyhow::{Context, Result, anyhow, bail};
use clap::Args;

use crate::zfs_ops;
use zboot_core::PairPointer;

#[derive(Debug, Args)]
pub struct RenameArgs {
    /// BE to rename. Bare name (resolved against the booted pool — the
    /// pool whose dataset is mounted at `/`) or fully-qualified dataset
    /// path. Use full path to disambiguate across pools.
    pub be: String,
    /// New BE name (bare; same pool as the source).
    pub new_name: String,
}

pub fn run(args: &RenameArgs, w: &mut impl Write) -> Result<()> {
    let old_ds = crate::be_arg::resolve_be_dataset(&args.be)?;
    if !zfs_ops::dataset_exists(&old_ds)? {
        bail!("BE {old_ds} does not exist");
    }
    if args.new_name.contains('/') {
        bail!("--new-name takes a bare BE name, not a path (got {:?})", args.new_name);
    }
    let pool = old_ds
        .split('/')
        .next()
        .ok_or_else(|| anyhow!("bad dataset {old_ds}"))?;
    let new_ds = format!("{pool}/ROOT/{}", args.new_name);
    if zfs_ops::dataset_exists(&new_ds).unwrap_or(false) {
        bail!("target name {new_ds} already exists");
    }

    let old_pointer = PairPointer::parse_dataset(&old_ds)
        .ok_or_else(|| anyhow!("{old_ds} not in canonical form"))?;
    let new_pointer = PairPointer::parse_dataset(&new_ds)
        .ok_or_else(|| anyhow!("{new_ds} not in canonical form"))?;

    writeln!(w, "  rename {old_ds} \u{2192} {new_ds}").ok();

    // Find every dataset that points at old_ds, BEFORE the rename so we
    // know who to fix up. Walk all imported pools' `zboot:mirror`
    // properties.
    let incoming = find_incoming_pointers(&old_pointer)?;

    // Perform the rename. `zfs rename` is atomic per pool.
    crate::sub::cmd("zfs", &["rename", &old_ds, &new_ds])
        .context("zfs rename")?;

    // If pool's bootfs pointed at the old name, advance it.
    if let Ok(Some(bootfs)) = zfs_ops::pool_bootfs(pool) {
        if bootfs == old_ds {
            crate::sub::cmd("zpool", &["set", &format!("bootfs={new_ds}"), pool])
                .context("zpool set bootfs (post-rename)")?;
        }
    }

    // Rewrite incoming pointers.
    for incoming_ds in &incoming {
        writeln!(w, "    update {incoming_ds} mirror pointer").ok();
        zfs_ops::write_pair_pointer(incoming_ds, &new_pointer)
            .with_context(|| format!("updating mirror pointer on {incoming_ds}"))?;
    }

    let _ = old_pointer; // keep for compile clarity
    Ok(())
}

/// All datasets on currently-imported pools whose `zboot:mirror` equals
/// `target`. Walks pools tagged `zboot:role=root`.
fn find_incoming_pointers(target: &PairPointer) -> Result<Vec<String>> {
    let mut hits = Vec::new();
    let target_render = target.render();

    let pools = crate::sub::zpool_capture(&["list", "-Hp", "-o", "name"])?;
    for pool in pools.lines() {
        // Only walk root pools.
        if zfs_ops::pool_property(pool, "zboot:role")
            .ok()
            .as_deref()
            != Some("root")
        {
            continue;
        }
        let out = crate::sub::zfs_capture(&[
            "get", "-Hp", "-r", "-t", "filesystem", "-o", "name,value", "zboot:mirror", pool,
        ])?;
        for line in out.lines() {
            let mut parts = line.split('\t');
            let name = parts.next().unwrap_or("");
            let value = parts.next().unwrap_or("");
            if value == target_render {
                hits.push(name.to_owned());
            }
        }
    }
    Ok(hits)
}
