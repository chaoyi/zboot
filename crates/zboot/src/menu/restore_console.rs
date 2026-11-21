//! Pure selection UI for whole-disk restoration.
//!
//! This module owns no native handles and performs no mutation.  The caller
//! supplies one complete private NativeState, whole-disk identities, and physical
//! pool observations.  The returned choice keeps those exact observations
//! attached to the operator's intent so a later planner can revalidate them
//! before any destructive action.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};
use zfs_tools::engine::{
    management::{self, Endpoint, Ownership},
    state::NativeState,
};

use super::{Result, preserve, refuse};
use crate::device::{DiskIdentity, PoolStorage};
use crate::restore::restore_plan;

const MAX_INPUT_BYTES: usize = 64 * 1024;

/// The complete, still-effect-free restoration choice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    /// The exact recursively complete source and checkpoint selected by the
    /// operator.
    pub source: restore_plan::Source,
    /// The exact whole-disk identity selected from the supplied inventory.
    pub target: DiskIdentity,
    /// The target pool name to reconstruct. Existing targets keep their
    /// observed name; an empty target has no native PoolStorage yet.
    pub target_pool: String,
    /// Target dataset roots selected for preservation, with their exact local
    /// identities from the supplied state.
    pub preserved_roots: Vec<Endpoint>,
}

/// Parse and drive the effect-free restoration selection flow.
///
/// words must contain the parsed recovery command, beginning with restore,
/// followed by at most BE[@SNAPSHOT] and a whole-disk path. A missing source
/// or disk is selected interactively. This function never invokes a native
/// command, opens a device, or confirms disk loss. Explicit preservation names
/// bypass the keep prompt and bind the same native rows before planning.
pub fn selection(
    state: &NativeState,
    available_disks: &[DiskIdentity],
    pool_storages: &[PoolStorage],
    words: &[String],
    input: &mut impl Read,
    output: &mut impl Write,
    preservation: Option<&[String]>,
) -> Result<Option<Choice>> {
    let (source_argument, disk_argument) = parse_words(words)?;
    validate_pool_storages(pool_storages)?;

    let Some(source) = choose_source(state, source_argument.as_ref(), input, output)? else {
        return Ok(None);
    };
    let disks = eligible_disks(&source, available_disks, pool_storages)?;
    let Some(target) = choose_disk(&disks, disk_argument.as_deref(), input, output)? else {
        return Ok(None);
    };

    let Some((target_pool, _)) =
        target_pool(state, pool_storages, &source, &target, input, output)?
    else {
        return Ok(None);
    };
    let restored = restore_plan::Mapping::new(&source.root.name, &target_pool, &[])?.restored_be;
    let rows = preservation_rows(state, &target_pool, &restored);
    let preserved_rows = if let Some(names) = preservation {
        names
            .iter()
            .map(|name| {
                rows.iter()
                    .find(|row| &row.dataset == name)
                    .cloned()
                    .ok_or_else(|| refuse("requested keep root is not eligible for this restore"))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        let Some(rows) = choose_preservation(rows, input, output)? else {
            return Ok(None);
        };
        rows
    };
    let preserved_roots = preserved_rows
        .into_iter()
        .map(|row| Endpoint {
            name: row.dataset,
            identity: row.identity,
        })
        .collect::<Vec<_>>();
    let preserve_names = preserved_roots
        .iter()
        .map(|root| root.name.clone())
        .collect::<Vec<_>>();
    // Refuses preserved roots outside the target pool before review.
    restore_plan::Mapping::new(&source.root.name, &target_pool, &preserve_names)?;

    Ok(Some(Choice {
        source,
        target,
        target_pool,
        preserved_roots,
    }))
}

fn parse_words(words: &[String]) -> Result<(Option<restore_plan::SourceArgument>, Option<String>)> {
    if words.first().map(String::as_str) != Some("restore") {
        return Err(refuse(
            "restore selection requires the restore command; transfer aliases are not accepted",
        ));
    }
    if words.len() > 3 {
        return Err(refuse("usage: restore [BE[@SNAPSHOT]] [DISK]"));
    }
    let source = words
        .get(1)
        .map(|value| restore_plan::SourceArgument::parse(value))
        .transpose()?;
    let disk = words.get(2).cloned();
    Ok((source, disk))
}

fn choose_source(
    state: &NativeState,
    argument: Option<&restore_plan::SourceArgument>,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<Option<restore_plan::Source>> {
    if let Some(argument) = argument {
        return restore_plan::Source::observe(state, argument)
            .map(Some)
            .map_err(Into::into);
    }

    let sources = source_choices(state);
    if sources.is_empty() {
        return Err(refuse(
            "no boot environment has a complete recursively retained snapshot",
        ));
    }
    writeln!(output, "Restore sources with complete recursive snapshots:")?;
    for (index, source) in sources.iter().enumerate() {
        writeln!(
            output,
            "  {}: {}  checkpoint={}  members={}",
            index + 1,
            zfs_tools::engine::escape_display(&source.root.name),
            zfs_tools::engine::escape_display(&source.boundary.name),
            source.members.len(),
        )?;
    }
    loop {
        let Some(line) = prompt_line(input, output, "Choose restore source (number, cancel): ")?
        else {
            writeln!(output, "restore selection cancelled at end of input.")?;
            return Ok(None);
        };
        let value = line.trim();
        if value.is_empty() || value == "cancel" {
            writeln!(output, "restore selection cancelled.")?;
            return Ok(None);
        }
        let Some(number) = positive_number(value) else {
            writeln!(
                output,
                "invalid restore source number; choose a listed number."
            )?;
            continue;
        };
        let Some(source) = sources.get(number - 1) else {
            writeln!(
                output,
                "restore source number is outside the displayed list."
            )?;
            continue;
        };
        return Ok(Some(source.clone()));
    }
}

/// Enumerate only sources whose latest complete recursive checkpoint can be
/// bound by Source::observe. Invalid or partial candidates are intentionally
/// omitted from this operator-facing list.
fn source_choices(state: &NativeState) -> Vec<restore_plan::Source> {
    let mut choices = BTreeMap::new();
    for candidate in crate::menu::inventory::candidates(state) {
        let argument = restore_plan::SourceArgument {
            dataset: candidate.dataset,
            snapshot: None,
        };
        if let Ok(source) = restore_plan::Source::observe(state, &argument) {
            choices.entry(source.root.name.clone()).or_insert(source);
        }
    }
    choices.into_values().collect()
}

fn validate_pool_storages(pool_storages: &[PoolStorage]) -> Result<()> {
    let mut pools = BTreeSet::new();
    let mut guids = BTreeSet::new();
    for storage in pool_storages {
        zfs_tools::engine::validate_dataset_name(&storage.pool)?;
        if storage.pool.contains('/') || storage.guid.get() == 0 {
            return Err(refuse("pool storage has an invalid root name or GUID"));
        }
        if !pools.insert(storage.pool.as_str()) || !guids.insert(storage.guid) {
            return Err(refuse("pool storage inventory contains a duplicate pool"));
        }
        if storage.disks.is_empty() {
            return Err(refuse(format!(
                "pool storage {} has no physical disks",
                zfs_tools::engine::escape_display(&storage.pool)
            )));
        }
        let mut paths = BTreeSet::new();
        for disk in &storage.disks {
            validate_disk_identity(disk)?;
            if !paths.insert(disk.path.as_str()) {
                return Err(refuse(format!(
                    "pool storage {} repeats a disk path",
                    zfs_tools::engine::escape_display(&storage.pool)
                )));
            }
        }
    }
    Ok(())
}

fn validate_disk_identity(disk: &DiskIdentity) -> Result<()> {
    if disk.path.is_empty() || disk.bytes == 0 {
        return Err(refuse(
            "whole-disk inventory contains an incomplete identity",
        ));
    }
    Ok(())
}

fn eligible_disks(
    source: &restore_plan::Source,
    available: &[DiskIdentity],
    pool_storages: &[PoolStorage],
) -> Result<Vec<DiskIdentity>> {
    let source_pool = source
        .root
        .name
        .split_once('/')
        .map_or(source.root.name.as_str(), |(pool, _)| pool);
    let source_pool_guid = source.root.identity.pool_guid;
    let source_storage_seen = pool_storages
        .iter()
        .any(|storage| storage.pool == source_pool && storage.guid == source_pool_guid);
    if !source_storage_seen {
        return Err(refuse(
            "source pool physical storage was not supplied for disk exclusion",
        ));
    }

    let mut by_path = BTreeMap::new();
    for disk in available {
        validate_disk_identity(disk)?;
        if by_path.insert(disk.path.clone(), disk.clone()).is_some() {
            return Err(refuse("whole-disk inventory contains duplicate paths"));
        }
    }
    let mut choices = Vec::new();
    for disk in by_path.into_values() {
        let excluded = pool_storages.iter().any(|storage| {
            let source_media = storage.pool == source_pool && storage.guid == source_pool_guid;
            let multi_disk_pool = storage.disks.len() != 1;
            (source_media || multi_disk_pool)
                && storage
                    .disks
                    .iter()
                    .any(|backing| same_disk_selector(backing, &disk))
        });
        if !excluded {
            choices.push(disk);
        }
    }
    choices.sort_by(|a, b| a.path.cmp(&b.path));
    if choices.is_empty() {
        return Err(refuse(
            "no whole disk remains after excluding source and multi-disk pool media",
        ));
    }
    Ok(choices)
}

fn choose_disk(
    choices: &[DiskIdentity],
    explicit_path: Option<&str>,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<Option<DiskIdentity>> {
    if let Some(path) = explicit_path {
        let Some(disk) = choices.iter().find(|disk| disk.path == path) else {
            return Err(refuse(
                "requested restore disk is absent from the filtered whole-disk inventory",
            ));
        };
        return Ok(Some(disk.clone()));
    }

    writeln!(output, "Available restore target disks:")?;
    for (index, disk) in choices.iter().enumerate() {
        let model = disk
            .model
            .as_deref()
            .map(zfs_tools::engine::escape_display)
            .unwrap_or_else(|| "-".into());
        let serial = disk
            .serial
            .as_deref()
            .or(disk.wwn.as_deref())
            .map(zfs_tools::engine::escape_display)
            .unwrap_or_else(|| "-".into());
        writeln!(
            output,
            "  {}: {}  model={}  serial/wwn={}  bytes={}",
            index + 1,
            zfs_tools::engine::escape_display(&disk.path),
            model,
            serial,
            disk.bytes,
        )?;
    }
    loop {
        let Some(line) = prompt_line(input, output, "Choose restore disk (number, cancel): ")?
        else {
            writeln!(output, "restore selection cancelled at end of input.")?;
            return Ok(None);
        };
        let value = line.trim();
        if value.is_empty() || value == "cancel" {
            writeln!(output, "restore selection cancelled.")?;
            return Ok(None);
        }
        let Some(number) = positive_number(value) else {
            writeln!(
                output,
                "invalid restore disk number; choose a listed number."
            )?;
            continue;
        };
        let Some(disk) = choices.get(number - 1) else {
            writeln!(output, "restore disk number is outside the displayed list.")?;
            continue;
        };
        return Ok(Some(disk.clone()));
    }
}

fn target_pool(
    state: &NativeState,
    pool_storages: &[PoolStorage],
    source: &restore_plan::Source,
    target: &DiskIdentity,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<Option<(String, Option<PoolStorage>)>> {
    for storage in pool_storages {
        if storage.disks.len() == 1
            && same_disk_selector(&storage.disks[0], target)
            && storage.disks[0] != *target
        {
            return Err(refuse(format!(
                "target pool {} has a stale disk identity; select the refreshed disk",
                zfs_tools::engine::escape_display(&storage.pool)
            )));
        }
    }
    let existing = pool_storages
        .iter()
        .filter(|storage| storage.disks.len() == 1 && storage.disks[0] == *target)
        .collect::<Vec<_>>();
    if existing.len() > 1 {
        return Err(refuse(
            "target disk has more than one exact single-disk pool storage",
        ));
    }
    if let Some(storage) = existing.first() {
        let storage = *storage;
        let observed = state
            .inspection
            .pools
            .iter()
            .filter(|pool| pool.name == storage.pool)
            .collect::<Vec<_>>();
        if observed.len() != 1 || observed[0].guid != storage.guid {
            return Err(refuse(
                "target pool storage does not match the observed native pool identity",
            ));
        }
        return Ok(Some((storage.pool.clone(), Some(storage.clone()))));
    }

    let used = used_pool_names(state, pool_storages);
    if let Some(peer_pool) = pair_peer_pool(state, source, &used)? {
        writeln!(
            output,
            "Empty target: using the unimported peer pool name {}.",
            zfs_tools::engine::escape_display(&peer_pool)
        )?;
        return Ok(Some((peer_pool, None)));
    }
    if !used.contains("rpool") {
        writeln!(output, "Empty target: using free pool name rpool.")?;
        return Ok(Some(("rpool".into(), None)));
    }

    writeln!(
        output,
        "No unambiguous automatic pool name is free; enter a new root pool name."
    )?;
    loop {
        let Some(line) = prompt_line(input, output, "Target pool name (cancel): ")? else {
            writeln!(output, "restore selection cancelled at end of input.")?;
            return Ok(None);
        };
        let name = line.trim();
        if name.is_empty() || name == "cancel" {
            writeln!(output, "restore selection cancelled.")?;
            return Ok(None);
        }
        if zfs_tools::engine::validate_dataset_name(name).is_err() || name.contains('/') {
            writeln!(output, "invalid root pool name; use one dataset component.")?;
            continue;
        }
        if used.contains(name) {
            writeln!(output, "that pool name is already imported or reserved.")?;
            continue;
        }
        return Ok(Some((name.into(), None)));
    }
}

fn used_pool_names(state: &NativeState, pool_storages: &[PoolStorage]) -> BTreeSet<String> {
    state
        .inspection
        .pools
        .iter()
        .map(|pool| pool.name.clone())
        .chain(pool_storages.iter().map(|storage| storage.pool.clone()))
        .collect()
}

fn pair_peer_pool(
    state: &NativeState,
    source: &restore_plan::Source,
    used: &BTreeSet<String>,
) -> Result<Option<String>> {
    let ownership = management::ownership(state, &source.root.name)?;
    let record = match ownership {
        Ownership::Unpaired => return Ok(None),
        Ownership::Primary { record } | Ownership::Secondary { record } => record,
    };
    let Some((pool, _)) = record.peer.name.split_once('/') else {
        return Err(refuse("paired source peer is not rooted in a pool"));
    };
    if pool.is_empty()
        || pool.contains('/')
        || zfs_tools::engine::validate_dataset_name(pool).is_err()
    {
        return Err(refuse("paired source peer has an invalid pool name"));
    }
    if used.contains(pool) {
        return Ok(None);
    }
    Ok(Some(pool.into()))
}

fn preservation_rows(
    state: &NativeState,
    target_pool: &str,
    restored_be: &str,
) -> Vec<preserve::PreservationRow> {
    let root = format!("{target_pool}/ROOT");
    let mut rows = state
        .inspection
        .datasets
        .iter()
        .filter(|dataset| {
            dataset
                .name
                .split_once('/')
                .is_some_and(|(pool, _)| pool == target_pool)
                && dataset.name != target_pool
                && dataset.name != root
                && !crate::history::contains_dataset(restored_be, &dataset.name)
                && !crate::history::contains_dataset(&dataset.name, restored_be)
        })
        .map(|dataset| {
            preserve::PreservationRow::new(dataset.name.clone(), dataset.identity.clone())
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| left.dataset.cmp(&right.dataset));
    rows
}

fn choose_preservation(
    rows: Vec<preserve::PreservationRow>,
    input: &mut impl Read,
    output: &mut impl Write,
) -> Result<Option<Vec<preserve::PreservationRow>>> {
    let mut chooser =
        preserve::PreservationChooser::new(rows).map_err(|error| refuse(error.to_string()))?;
    loop {
        chooser.render(output)?;
        let Some(line) = prompt_line(input, output, "Preserve selection> ")? else {
            writeln!(output, "preservation selection cancelled at end of input.")?;
            return Ok(None);
        };
        match chooser.apply_line(&line) {
            Ok(preserve::PromptResult::Continue) => {}
            Ok(preserve::PromptResult::Cancel) => {
                writeln!(output, "preservation selection cancelled.")?;
                return Ok(None);
            }
            Ok(preserve::PromptResult::Done(rows)) => return Ok(Some(rows)),
            Err(error) => {
                writeln!(output, "invalid preservation selection: {error}")?;
            }
        }
    }
}

fn same_disk_selector(left: &DiskIdentity, right: &DiskIdentity) -> bool {
    left == right
        || left.path == right.path
        || (!left.device_number.is_empty() && left.device_number == right.device_number)
        || left
            .serial
            .as_ref()
            .zip(right.serial.as_ref())
            .is_some_and(|(left, right)| left == right)
        || left
            .wwn
            .as_ref()
            .zip(right.wwn.as_ref())
            .is_some_and(|(left, right)| left == right)
}

fn positive_number(value: &str) -> Option<usize> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse::<usize>().ok().filter(|number| *number > 0)
}

fn prompt_line(
    input: &mut impl Read,
    output: &mut impl Write,
    prompt: &str,
) -> Result<Option<String>> {
    write!(output, "{prompt}")?;
    output.flush()?;
    read_line(input)
}

/// Read exactly one prompt line, preserving EOF as cancellation even when a
/// partial final line was supplied. The loop consumes one byte at a time so a
/// later shell or command cannot lose already-buffered input.
fn read_line(input: &mut impl Read) -> Result<Option<String>> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => {
                if bytes.len() == MAX_INPUT_BYTES {
                    return Err(refuse("restore selection input line exceeds 64 KiB"));
                }
                bytes.push(byte[0]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|error| refuse(format!("restore selection input is not UTF-8: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use zfs_tools::engine::{
        Guid, InspectRequest,
        native::{self, NativeProperty},
    };

    #[test]
    fn preservation_excludes_the_rebuilt_be_but_keeps_other_boot_environments() {
        let state = fixture_with_extra(&[
            ("dst/ROOT/be", "/", 105),
            ("dst/ROOT/be/var", "/var", 106),
            ("dst/ROOT/be-other", "/", 107),
            ("dst/ROOT/be-other/var", "/var", 108),
        ]);
        let names = preservation_rows(&state, "dst", "dst/ROOT/be")
            .into_iter()
            .map(|row| row.dataset)
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            vec![
                "dst/ROOT/be-other",
                "dst/ROOT/be-other/var",
                "dst/home",
                "dst/home/child"
            ]
        );
    }

    fn prop(value: impl ToString) -> NativeProperty {
        NativeProperty {
            value: value.to_string(),
            source: "local".into(),
        }
    }

    fn fixture() -> NativeState {
        fixture_with_extra(&[])
    }

    fn fixture_with_extra(extra: &[(&str, &str, u64)]) -> NativeState {
        let mut datasets = vec![
            ("src", "none", 1),
            ("src/ROOT", "none", 2),
            ("src/ROOT/be", "/", 3),
            ("src/ROOT/be/home", "none", 4),
            ("dst", "none", 101),
            ("dst/ROOT", "none", 102),
            ("dst/home", "/home", 103),
            ("dst/home/child", "none", 104),
        ];
        datasets.extend_from_slice(extra);
        let dataset_output = datasets
            .iter()
            .map(|(name, mountpoint, guid)| {
                format!(
                    "{name}\tfilesystem\t{guid}\t0\t1000\t0\t{mountpoint}\t-\t{}\t{}\tno\toff\ton\t-\toff\t-\t-\t-\t-\n",
                    guid + 10,
                    guid + 20
                )
            })
            .collect::<String>();
        let snapshot_output = concat!(
            "src/ROOT/be@save\t501\t1700000000\t0\t20\t20\t30\t0\toff\t-\n",
            "src/ROOT/be/home@save\t502\t1700000001\t0\t21\t21\t31\t0\toff\t-\n",
        );
        let inspection = native::inspect_with(
            &InspectRequest::new(vec![], true).unwrap(),
            |program, args| {
                Ok(if program == "zpool" {
                    "src\t101\t1000\t100\t900\tONLINE\tsrc/ROOT/be\n\
                     dst\t202\t1000\t100\t900\tONLINE\t-\n"
                        .into()
                } else if args.iter().any(|arg| arg == "snapshot") {
                    snapshot_output.into()
                } else {
                    dataset_output.clone()
                })
            },
        )
        .unwrap();
        let mut dataset_properties = native::PropertyInventory::new();
        for dataset in &inspection.datasets {
            let mut properties = BTreeMap::from([
                ("guid".into(), prop(dataset.identity.guid)),
                ("createtxg".into(), prop(dataset.identity.createtxg)),
                ("objsetid".into(), prop(dataset.identity.objsetid)),
            ]);
            for key in &crate::boot_support::tests::FIXTURE_COLUMNS {
                let value = match *key {
                    "mountpoint" => dataset.mountpoint.as_deref().unwrap(),
                    "canmount" => "on",
                    "readonly" => "off",
                    "nbmand" => "off",
                    "encryptionroot" | "keylocation" => "-",
                    _ => "on",
                };
                properties.insert((*key).into(), prop(value));
            }
            dataset_properties.insert(dataset.name.clone(), properties);
        }
        NativeState {
            inspection,
            dataset_properties,
            pool_properties: BTreeMap::from([
                (
                    "src".into(),
                    BTreeMap::from([("guid".into(), prop(101)), ("readonly".into(), prop("on"))]),
                ),
                (
                    "dst".into(),
                    BTreeMap::from([("guid".into(), prop(202)), ("readonly".into(), prop("on"))]),
                ),
            ]),
        }
    }

    fn disk(path: &str, serial: &str, bytes: u64) -> DiskIdentity {
        DiskIdentity {
            path: path.into(),
            device_number: format!("8:{}", bytes),
            sysfs_path: format!("/sys/{serial}"),
            bytes,
            logical_sector: 512,
            physical_sector: 4096,
            serial: Some(serial.into()),
            wwn: None,
            model: Some("fixture-disk".into()),
        }
    }

    fn inventory() -> (Vec<DiskIdentity>, Vec<PoolStorage>) {
        let source = disk("/dev/src", "SRC", 100);
        let target = disk("/dev/dst", "DST", 200);
        let empty = disk("/dev/empty", "EMPTY", 300);
        (
            vec![source.clone(), target.clone(), empty],
            vec![
                PoolStorage {
                    pool: "src".into(),
                    guid: Guid::new(101),
                    disks: vec![source],
                },
                PoolStorage {
                    pool: "dst".into(),
                    guid: Guid::new(202),
                    disks: vec![target],
                },
            ],
        )
    }

    fn words(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).into()).collect()
    }

    #[test]
    fn scripted_source_disk_and_preservation_selection_binds_exact_rows() {
        let state = fixture();
        let (disks, pools) = inventory();
        let mut input = Cursor::new(b"1\n1\n1\ndone\n");
        let mut output = Vec::new();

        let choice = selection(
            &state,
            &disks,
            &pools,
            &words(&["restore"]),
            &mut input,
            &mut output,
            None,
        )
        .unwrap()
        .unwrap();

        assert_eq!(choice.source.root.name, "src/ROOT/be");
        assert_eq!(choice.source.boundary.name, "src/ROOT/be@save");
        assert_eq!(choice.target, disks[1]);
        assert_eq!(choice.target_pool, "dst");
        assert_eq!(
            choice
                .preserved_roots
                .iter()
                .map(|root| root.name.as_str())
                .collect::<Vec<_>>(),
            vec!["dst/home"]
        );
        assert!(String::from_utf8(output).unwrap().contains("/dev/dst"));

        let mut encoded = serde_json::to_value(&choice).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), true.into());
        assert!(serde_json::from_value::<Choice>(encoded).is_err());
    }

    #[test]
    fn explicit_keep_skips_the_preservation_prompt_and_binds_native_identity() {
        let state = fixture();
        let (disks, pools) = inventory();
        let mut input = Cursor::new(b"next command\n");
        let mut output = Vec::new();
        let names = vec!["dst/home".to_owned()];
        let choice = selection(
            &state,
            &disks,
            &pools,
            &words(&["restore", "src/ROOT/be@save", "/dev/dst"]),
            &mut input,
            &mut output,
            Some(&names),
        )
        .unwrap()
        .unwrap();
        assert_eq!(choice.preserved_roots.len(), 1);
        assert_eq!(choice.preserved_roots[0].name, names[0]);
        assert_eq!(
            &choice.preserved_roots[0].identity,
            &state
                .inspection
                .datasets
                .iter()
                .find(|dataset| dataset.name == names[0])
                .unwrap()
                .identity
        );
        assert_eq!(input.position(), 0);
        assert!(
            !String::from_utf8(output)
                .unwrap()
                .contains("Preserve selection>")
        );
        let mut output = Vec::new();
        assert!(
            selection(
                &state,
                &disks,
                &pools,
                &words(&["restore", "src/ROOT/be@save", "/dev/dst"]),
                &mut input,
                &mut output,
                Some(&["dst/ROOT/be".into()])
            )
            .is_err()
        );
    }

    #[test]
    fn explicit_snapshot_and_cancel_stop_before_preservation() {
        let state = fixture();
        let (disks, pools) = inventory();
        let mut input = Cursor::new(b"cancel\n");
        let mut output = Vec::new();
        assert_eq!(
            selection(
                &state,
                &disks,
                &pools,
                &words(&["restore", "src/ROOT/be@save"]),
                &mut input,
                &mut output,
                None,
            )
            .unwrap(),
            None
        );
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("restore selection cancelled")
        );
    }

    #[test]
    fn eof_with_partial_source_input_is_cancellation() {
        let state = fixture();
        let (disks, pools) = inventory();
        let mut input = Cursor::new(b"1");
        let mut output = Vec::new();
        assert_eq!(
            selection(
                &state,
                &disks,
                &pools,
                &words(&["restore"]),
                &mut input,
                &mut output,
                None,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn invalid_prompts_reprompt_and_preservation_input_remains_atomic() {
        let state = fixture();
        let (disks, pools) = inventory();
        let mut input = Cursor::new(b"99\n1\n1 99\ndone\n");
        let mut output = Vec::new();
        let choice = selection(
            &state,
            &disks,
            &pools,
            &words(&["restore", "src/ROOT/be"]),
            &mut input,
            &mut output,
            None,
        )
        .unwrap()
        .unwrap();
        assert!(choice.preserved_roots.is_empty());
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("restore disk number is outside")
        );
    }

    #[test]
    fn source_media_and_stale_target_identity_are_rejected() {
        let state = fixture();
        let (disks, mut pools) = inventory();
        let mut input = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        assert!(
            selection(
                &state,
                &disks,
                &pools,
                &words(&["restore", "src/ROOT/be@save", "/dev/src"]),
                &mut input,
                &mut output,
                None,
            )
            .unwrap_err()
            .to_string()
            .contains("filtered whole-disk")
        );

        pools[1].disks[0].bytes += 1;
        let mut output = Vec::new();
        assert!(
            selection(
                &state,
                &disks,
                &pools,
                &words(&["restore", "src/ROOT/be@save", "/dev/dst"]),
                &mut input,
                &mut output,
                None,
            )
            .unwrap_err()
            .to_string()
            .contains("stale disk identity")
        );

        let (disks, mut pools) = inventory();
        pools[1].guid = Guid::new(999);
        let mut output = Vec::new();
        assert!(
            selection(
                &state,
                &disks,
                &pools,
                &words(&["restore", "src/ROOT/be@save", "/dev/dst"]),
                &mut input,
                &mut output,
                None,
            )
            .unwrap_err()
            .to_string()
            .contains("observed native pool identity")
        );
    }

    #[test]
    fn empty_target_uses_free_rpool_and_rejects_old_transfer_alias() {
        let state = fixture();
        let (disks, pools) = inventory();
        let mut input = Cursor::new(b"1\ndone\n");
        let mut output = Vec::new();
        let choice = selection(
            &state,
            &disks,
            &pools,
            &words(&["restore", "src/ROOT/be@save", "/dev/empty"]),
            &mut input,
            &mut output,
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(choice.target_pool, "rpool");
        assert!(choice.preserved_roots.is_empty());

        let mut input = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();
        assert!(
            selection(
                &state,
                &disks,
                &pools,
                &words(&["push", "src/ROOT/be", "/dev/empty"]),
                &mut input,
                &mut output,
                None,
            )
            .is_err()
        );
    }
}
