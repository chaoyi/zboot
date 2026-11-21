//! Selection-only menu pickers. The shared CLI owns planning and execution.
use super::{Result, refuse, restore_console};
use crate::{
    cli::grammar::{Cli, Verb},
    device, restore,
};
use std::io::{Read, Write};
use zfs_tools::engine::{DatasetIdentity, state};

#[derive(Default)]
pub(super) struct Picked {
    pub datasets: Vec<(String, DatasetIdentity)>,
    pub disks: Vec<device::DiskIdentity>,
    pub snapshots: Vec<zfs_tools::engine::SnapshotRef>,
}

/// Fill only omitted operands. Every native identity shown by a picker is
/// returned as a binding, checked at entry and again under the writer.
pub(super) fn fill(
    cli: &mut Cli,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<Option<Picked>> {
    let mut picked = Picked::default();
    let abandoning = matches!(&cli.command, Verb::Abandon { .. });
    match &mut cli.command {
        Verb::Restore {
            source,
            disk,
            keep,
            pool,
            dry_run,
            confirm,
            ..
        } if source.is_none()
            || disk.is_none()
            || (keep.is_empty() && !*dry_run && confirm.is_none()) =>
        {
            crate::handoff::prove_ram()?;
            let observed = state::observe()?;
            let pools = observed
                .inspection
                .pools
                .iter()
                .map(|pool| device::observe_pool_storage(&pool.name, &pool.guid))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let disks = disks()?;
            let mut words = vec!["restore".to_owned()];
            words.extend(source.iter().cloned());
            words.extend(disk.iter().cloned());
            let preservation =
                (!keep.is_empty() || *dry_run || confirm.is_some()).then_some(keep.as_slice());
            let Some(choice) = restore_console::selection(
                &observed,
                &disks,
                &pools,
                &words,
                input,
                output,
                preservation,
            )?
            else {
                return Ok(None);
            };
            *source = Some(choice.source.boundary.name.clone());
            *disk = Some(choice.target.path.clone());
            if keep.is_empty() {
                *keep = choice
                    .preserved_roots
                    .iter()
                    .map(|root| root.name.clone())
                    .collect();
            }
            picked.datasets.extend(
                choice
                    .preserved_roots
                    .iter()
                    .map(|root| (root.name.clone(), root.identity.clone())),
            );
            if pool.is_none() {
                *pool = Some(choice.target_pool);
            }
            picked.datasets.extend(
                choice
                    .source
                    .members
                    .into_iter()
                    .map(|member| (member.name, member.identity)),
            );
            picked.snapshots.extend(choice.source.points);
            picked.disks.push(choice.target);
        }
        Verb::Wipe {
            disk: target @ None,
            ..
        } => {
            let Some(disk) = choose_disk(input, output)? else {
                return Ok(None);
            };
            *target = Some(disk.path.clone());
            picked.disks.push(disk);
        }
        Verb::Resume { id, .. } | Verb::Abandon { id, .. } if id.is_none() => {
            let action = if abandoning { "Abandon" } else { "Resume" };
            let Some(chosen) = operation(action, input, output)? else {
                return Ok(None);
            };
            *id = Some(chosen);
        }
        _ => {}
    }
    Ok(Some(picked))
}

fn disks() -> Result<Vec<device::DiskIdentity>> {
    let mut disks = device::observe_landscape()?
        .blockdevices
        .into_iter()
        .filter(|row| row.kind == "disk" && !row.ro)
        .map(|row| device::observe_identity(&row.path))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    disks.sort_by(|left, right| left.path.cmp(&right.path));
    if disks.windows(2).any(|pair| pair[0].path == pair[1].path) {
        return Err(refuse("whole-disk inventory contains duplicate paths"));
    }
    Ok(disks)
}

fn choose_disk(
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<Option<device::DiskIdentity>> {
    let disks = disks()?;
    if disks.is_empty() {
        return Err(refuse("native inventory contains no whole disks"));
    }
    writeln!(output, "Available whole disks:")?;
    for (index, disk) in disks.iter().enumerate() {
        writeln!(
            output,
            "  {}: {}  {}  serial/wwn={}  bytes={}",
            index + 1,
            zfs_tools::engine::escape_display(&disk.path),
            zfs_tools::engine::escape_display(disk.model.as_deref().unwrap_or("-")),
            zfs_tools::engine::escape_display(
                disk.serial
                    .as_deref()
                    .or(disk.wwn.as_deref())
                    .unwrap_or("-")
            ),
            disk.bytes
        )?;
    }
    write!(output, "Choose whole-disk number (blank cancels): ")?;
    output.flush()?;
    let Some(line) = super::console_line(input)? else {
        return Ok(None);
    };
    if line.trim().is_empty() || line.trim() == "cancel" {
        return Ok(None);
    }
    let number = line
        .trim()
        .parse::<usize>()
        .map_err(|_| refuse("enter one displayed whole-disk number"))?;
    disks
        .get(
            number
                .checked_sub(1)
                .ok_or_else(|| refuse("disk number is outside the displayed list"))?,
        )
        .cloned()
        .map(Some)
        .ok_or_else(|| refuse("disk number is outside the displayed list"))
}

fn operation(
    action: &str,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<Option<String>> {
    let listing = restore::list(&mut restore::Native::new())?;
    for orphan in &listing.orphans {
        writeln!(
            output,
            "  - {}",
            zfs_tools::engine::escape_display(&orphan.describe())
        )?;
    }
    for (index, operation) in listing.operations.iter().enumerate() {
        writeln!(
            output,
            "  {}. {} {} on {}: {} ({})",
            index + 1,
            zfs_tools::engine::escape_display(operation.kind.as_deref().unwrap_or("-")),
            zfs_tools::engine::escape_display(operation.id.as_deref().unwrap_or("-")),
            zfs_tools::engine::escape_display(&operation.pool),
            zfs_tools::engine::escape_display(operation.step.as_deref().unwrap_or("unknown")),
            zfs_tools::engine::escape_display(operation.detail.as_deref().unwrap_or(""))
        )?;
    }
    if listing.operations.is_empty() {
        writeln!(output, "No interrupted operation is available.")?;
        return Ok(None);
    }
    write!(output, "{action} number (blank cancels): ")?;
    output.flush()?;
    let Some(line) = super::console_line(input)? else {
        return Ok(None);
    };
    if line.trim().is_empty() || line.trim() == "cancel" {
        return Ok(None);
    }
    let number = line
        .trim()
        .parse::<usize>()
        .map_err(|_| refuse("enter one displayed operation number"))?;
    let operation = number
        .checked_sub(1)
        .and_then(|index| listing.operations.get(index))
        .ok_or_else(|| refuse("operation number is outside the displayed list"))?;
    operation
        .id
        .clone()
        .map(Some)
        .ok_or_else(|| refuse("that record is unreadable"))
}
