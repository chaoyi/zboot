//! The menu's boot environment listing: candidates, their kernel pairs and the
//! displayed inventory.
use super::{RecoveryError, Result, cleanup_error_for, discovery, hostid_adopt, menu_view, refuse};
use crate::handoff::{
    Action, AssetHashes, NativeRecovery, RecoveryBackend, bound_file, default_assets, diagnostic,
    digest_file, eligible, readonly_pools,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use zfs_tools::engine::{
    DatasetIdentity,
    management::Ownership,
    state::{self, NativeState},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BootCandidate {
    pub dataset: String,
    pub identity: DatasetIdentity,
    pub default: bool,
    pub once: bool,
    pub ownership: Option<Ownership>,
    pub refusal: Option<String>,
}

fn pool_defaults(state: &NativeState) -> BTreeSet<&str> {
    state
        .inspection
        .pools
        .iter()
        .filter_map(|p| p.bootfs.as_deref())
        .collect()
}

/// Root-shaped imported datasets and observed native defaults. Kernel content
/// is inspected separately, without keeping a mount between menu commands.
fn boot_environments(state: &NativeState) -> Vec<&zfs_tools::engine::Dataset> {
    crate::boot_environment::roots(state)
}

/// Imported candidates use native root shape and role admission. Native defaults
/// remain visible with their refusal, including a private restore workspace.
///
/// A boot environment is also refused while another one has a `canmount=on`
/// descendant ([`crate::mounting::refusal`]).
pub fn candidates(state: &NativeState) -> Vec<BootCandidate> {
    let defaults = pool_defaults(state);
    let once = crate::once::selected(state).ok().flatten();
    let mut result = Vec::new();
    for dataset in boot_environments(state) {
        let eligibility = eligible(state, &dataset.name);
        result.push(BootCandidate {
            dataset: dataset.name.clone(),
            identity: dataset.identity.clone(),
            default: defaults.contains(dataset.name.as_str()),
            once: once.is_some_and(|marked| marked.identity == dataset.identity),
            ownership: eligibility
                .as_ref()
                .ok()
                .map(|(_, ownership, _)| ownership.clone()),
            refusal: match eligibility {
                Err(error) => Some(error.to_string()),
                Ok(_) => crate::mounting::refusal(state, Some(&dataset.name)),
            },
        });
    }
    result.sort_by(|a, b| a.dataset.cmp(&b.dataset));
    result
}

/// Render the BE tree, then any adopted identity, which must stay visible.
pub(super) fn render_menu(inventory: &MenuInventory) -> Result<()> {
    render_menu_listing(inventory, &mut io::stdout())?;
    discovery::progress().render(&mut io::stdout())?;
    if let Some(adoption) = hostid_adopt::adopted() {
        for line in hostid_adopt::banner(&adoption) {
            println!("{line}");
        }
    }
    Ok(())
}

pub(super) fn menu_inventory() -> Result<(NativeState, Vec<menu_view::MenuEntry>)> {
    discovery::inventory(|| {
        let observed = state::observe()?;
        let entries = menu_entries(&observed)?;
        Ok((observed, entries))
    })
}

/// Asynchronous import output can arrive after a prompt with no newline.
/// Every snapshot starts a physical line so its banner is unambiguous.
fn render_menu_listing(inventory: &MenuInventory, output: &mut impl Write) -> Result<()> {
    writeln!(output)?;
    menu_view::render(&inventory.entries, output)?;
    if let Some(state) = inventory.countdown_state()
        && let Err(error) = crate::once::selected(state)
    {
        writeln!(
            output,
            "One-time boot blocked: {}",
            zfs_tools::engine::escape_display(&error.to_string())
        )?;
    }
    if !inventory.pairs.is_empty() {
        writeln!(output, "Recorded pairs (primary -> secondary)")?;
        for pair in &inventory.pairs {
            writeln!(output, "  {}", zfs_tools::engine::escape_display(pair))?;
        }
        writeln!(
            output,
            "Use status for pair details or status --devices to identify attached disks."
        )?;
    }
    Ok(())
}

/// Read a bounded menu inventory. Every displayed pair remains only a hint:
/// handoff mounts and verifies the selected BE and assets again before loading.
pub(crate) fn kernel_choices(root: &Path) -> Result<Vec<menu_view::KernelChoice>> {
    let root = std::fs::canonicalize(root)?;
    let mut paths = Vec::new();
    for (kernel, initrd) in [
        ("vmlinuz", "initrd.img"),
        ("vmlinuz.old", "initrd.img.old"),
        ("boot/vmlinuz", "boot/initrd.img"),
        ("boot/vmlinuz.old", "boot/initrd.img.old"),
    ] {
        if root.join(kernel).symlink_metadata().is_ok()
            && root.join(initrd).symlink_metadata().is_ok()
        {
            paths.push((PathBuf::from(kernel), PathBuf::from(initrd)));
        }
    }
    let boot = root.join("boot");
    if boot.exists() {
        if !std::fs::canonicalize(&boot)?.starts_with(&root) {
            return Err(refuse("boot directory escapes the selected BE"));
        }
        for pair in crate::handoff::scan_versioned_boot_pairs(
            &root,
            "boot directory exceeds the 4096-entry menu limit",
        )? {
            paths.push(pair);
            if paths.len() > 128 {
                return Err(refuse("boot environment exceeds the 128-pair menu limit"));
            }
        }
    }
    let default = default_assets(&root).ok();
    // Pointer names sort first; version labels are deterministic, never used
    // to guess a default when the selected BE supplies no default pointer.
    paths.sort_by_key(|(kernel, _)| {
        (
            kernel
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("vmlinuz-")),
            kernel.clone(),
        )
    });
    let mut seen = BTreeSet::new();
    let mut choices = Vec::new();
    for (kernel, initrd) in paths {
        let resolved = match bound_file(&root, &kernel)
            .and_then(|kernel| bound_file(&root, &initrd).map(|initrd| (kernel, initrd)))
        {
            Ok(pair) => pair,
            Err(RecoveryError::Io(error)) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if seen.insert(resolved.clone()) {
            choices.push(menu_view::KernelChoice {
                assets: Some(AssetHashes {
                    kernel_sha256: digest_file(&resolved.0)?,
                    initrd_sha256: digest_file(&resolved.1)?,
                }),
                // Display the resolved versioned filenames, not only vmlinuz
                // symlink names, and retain paths relative to this BE.
                kernel: resolved
                    .0
                    .strip_prefix(&root)
                    .map_err(|_| refuse("kernel escaped BE"))?
                    .to_owned(),
                initrd: resolved
                    .1
                    .strip_prefix(&root)
                    .map_err(|_| refuse("initrd escaped BE"))?
                    .to_owned(),
                default: default.as_ref() == Some(&resolved),
            });
        }
    }
    if choices.is_empty() {
        return Err(refuse("no matching kernel/initrd pairs found"));
    }
    Ok(choices)
}

/// Inner errors describe unavailable assets after successful cleanup. Outer
/// errors mean a preflight or cleanup failure; do not continue into another
/// mount or handoff in that case.
fn inventory_with(
    state: &NativeState,
    candidate: &BootCandidate,
    backend: &mut impl RecoveryBackend,
    read: impl FnOnce(&Path) -> Result<Vec<menu_view::KernelChoice>>,
) -> Result<Result<Vec<menu_view::KernelChoice>>> {
    backend.prove_ram()?;
    readonly_pools(state)?;
    let (scope, ownership, command_line) = eligible(state, &candidate.dataset)?;
    let binding = zfs_tools::engine::state::ReadonlyInventoryBinding::capture(state, &scope)?;
    let validate = |backend: &mut dyn RecoveryBackend| {
        backend.revalidate_inventory(
            &binding,
            &candidate.dataset,
            &scope,
            &ownership,
            &command_line,
        )
    };
    validate(backend)?;
    let work = backend.workspace()?;
    let mount = work.join("root");
    let mut mounted = false;
    let result = (|| {
        backend.action(&Action::MountReadonly {
            dataset: candidate.dataset.clone(),
            target: mount.clone(),
        })?;
        mounted = true;
        backend.verify_mount(&candidate.dataset, &mount)?;
        validate(backend)?;
        let choices = read(&mount)?;
        backend.verify_mount(&candidate.dataset, &mount)?;
        validate(backend)?;
        Ok(choices)
    })();
    if mounted && let Err(error) = backend.action(&Action::Unmount { target: mount }) {
        return Err(cleanup_error_for(
            "kernel inventory",
            result.map(|_| ()),
            "release selected BE mount after kernel inventory",
            error,
        ));
    }
    if let Err(error) = backend.cleanup(&work) {
        return Err(cleanup_error_for(
            "kernel inventory",
            result.map(|_| ()),
            "remove RAM workspace after kernel inventory",
            error,
        ));
    }
    Ok(result)
}

pub(super) fn menu_entries(state: &NativeState) -> Result<Vec<menu_view::MenuEntry>> {
    entries_with(
        state,
        candidates(state),
        &mut NativeRecovery::for_listing(),
        kernel_choices,
    )
}

/// The entries a `boot` without a displayed binding can select: the BE it
/// names, or else the pool defaults. A boot reads no other BE's kernels; each
/// inventory mounts its BE and observes it three times, and the handoff checks
/// the selected BE again under the lock.
pub(super) fn boot_entries(
    state: &NativeState,
    dataset: Option<&str>,
) -> Result<Vec<menu_view::MenuEntry>> {
    if crate::once::selected(state)?.is_some() && dataset.is_none() {
        super::select::unambiguous_bootfs(state)?;
    }
    entries_with(
        state,
        boot_candidates(state, dataset),
        &mut NativeRecovery::new(),
        kernel_choices,
    )
}

fn boot_candidates(state: &NativeState, dataset: Option<&str>) -> Vec<BootCandidate> {
    let mut candidates = candidates(state);
    let armed = candidates.iter().any(|candidate| candidate.once);
    candidates.retain(|candidate| match dataset {
        Some(name) => candidate.dataset == name,
        None if armed => candidate.once,
        None => candidate.default,
    });
    candidates
}

fn entries_with(
    state: &NativeState,
    candidates: Vec<BootCandidate>,
    backend: &mut impl RecoveryBackend,
    read: impl Fn(&Path) -> Result<Vec<menu_view::KernelChoice>>,
) -> Result<Vec<menu_view::MenuEntry>> {
    let started = std::time::Instant::now();
    if candidates.len() > 128 {
        return Err(refuse(
            "more than 128 boot environments; use status or boot explicitly",
        ));
    }
    let pool_refusal = readonly_pools(state).err().map(|error| error.to_string());
    let mut entries = Vec::new();
    for candidate in candidates {
        let inventory = if let Some(reason) = candidate.refusal.as_ref().or(pool_refusal.as_ref()) {
            Err(refuse(reason))
        } else {
            inventory_with(state, &candidate, &mut *backend, &read)?
        };
        let (kernels, asset_refusal) = match inventory {
            Ok(kernels) => (kernels, None),
            Err(error) => (Vec::new(), Some(error.to_string())),
        };
        entries.push(menu_view::MenuEntry {
            candidate,
            kernels,
            asset_refusal,
        });
    }
    let elapsed_ms = started.elapsed().as_millis().min(u32::MAX as u128) as u32;
    diagnostic!("ZBOOT_MENU_LISTING_MS={elapsed_ms}");
    Ok(entries)
}

/// Preserve displayed native bindings while asynchronous pools arrive. New
/// entries append, so an existing numeric selector keeps referring to its BE.
pub(super) fn stable_entries(
    prior: &[menu_view::MenuEntry],
    mut fresh: Vec<menu_view::MenuEntry>,
) -> Vec<menu_view::MenuEntry> {
    fresh.sort_by_key(|entry| {
        prior
            .iter()
            .position(|old| old.candidate.identity == entry.candidate.identity)
            .unwrap_or(prior.len())
    });
    fresh
}

/// Describe only the local records in the current inventory. Enumerating
/// history, inspecting disks and assessing boot eligibility are separate reads.
fn pair_rows(state: &NativeState) -> Vec<String> {
    use crate::pairs::PeerStatus;
    use zfs_tools::engine::management::{PAIR_PROPERTY, Role};

    let mut rows = Vec::new();
    for (name, properties) in &state.dataset_properties {
        if properties
            .get(PAIR_PROPERTY)
            .is_none_or(|p| p.source != "local")
        {
            continue;
        }
        let record = match crate::pairs::local_record(state, name) {
            Ok(Some(record)) => record,
            Ok(None) => continue,
            Err(error) => {
                rows.push(format!("{name}  pair details unavailable: {error}"));
                continue;
            }
        };
        let peer = &record.peer.name;
        let status = crate::pairs::peer_status(state, &record);
        if status == PeerStatus::Mutual && record.role == Role::Secondary {
            continue;
        }
        let (primary, secondary) = match record.role {
            Role::Primary => (name, peer),
            Role::Secondary => (peer, name),
        };
        let row = format!("{primary} -> {secondary}");
        rows.push(if status == PeerStatus::Mutual {
            row
        } else {
            format!("{row}  peer {peer}: {}", status.describe())
        });
    }
    rows
}

/// Display state is published only with entries derived from that same
/// validated inventory. Failed observations retain the display, never authority
/// for a countdown; the console loop retries at its normal poll cadence.
#[derive(Default)]
pub(super) struct MenuInventory {
    state: Option<NativeState>,
    pub(super) pairs: Vec<String>,
    pub(super) entries: Vec<menu_view::MenuEntry>,
    pub(super) error: Option<String>,
}
impl MenuInventory {
    pub(super) fn refresh_with(
        &mut self,
        observe: impl FnOnce() -> Result<(NativeState, Vec<menu_view::MenuEntry>)>,
    ) -> bool {
        match observe() {
            Ok((state, entries)) => {
                self.pairs = pair_rows(&state);
                self.entries = stable_entries(&self.entries, entries);
                self.state = Some(state);
                self.error = None;
                true
            }
            Err(error) => {
                let message = error.to_string();
                if self.error.as_ref() != Some(&message) {
                    eprintln!(
                        "menu inventory: {}",
                        zfs_tools::engine::escape_display(&message)
                    );
                }
                self.error = Some(message);
                false
            }
        }
    }
    pub(super) fn retry_needed(&self) -> bool {
        self.state.is_none() || self.error.is_some()
    }
    pub(super) fn countdown_state(&self) -> Option<&NativeState> {
        if self.error.is_some() {
            None
        } else {
            self.state.as_ref()
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::handoff::tests::{
        Fake, Scratch, error_sources_include_erofs, fixture, fixture_with_be_guid,
        fixture_with_extra_bes, prop, two_bes,
    };
    use crate::handoff::{Action, AssetHashes, handoff_with};
    use crate::menu::select::auto_boot_request;
    use crate::menu::{menu_prompt, menu_view, refuse};
    use zfs_tools::engine::Error as NativeError;

    pub(in crate::menu) fn displayed_be(state: &NativeState) -> menu_view::MenuEntry {
        let mut entry = menu_entry("tank/ROOT/be", false, None, vec![], None);
        entry.candidate.identity = state
            .inspection
            .datasets
            .iter()
            .find(|dataset| dataset.name == "tank/ROOT/be")
            .unwrap()
            .identity
            .clone();
        entry
    }

    #[test]
    fn paired_boot_and_data_leaves_remain_visible_when_only_the_copy_pool_is_imported() {
        use zfs_tools::engine::management::{Endpoint, PAIR_PROPERTY, PairRecord, Role};
        let mut fake = crate::tree::fake::Fake::new();
        fake.create("a/ROOT");
        fake.create("b/ROOT");
        for leaf in ["ROOT/be1", "fleet-source", "scratch"] {
            let primary = format!("a/{leaf}");
            let secondary = format!("b/{leaf}");
            fake.create(&primary);
            fake.create(&secondary);
            let record = PairRecord {
                schema_version: 1,
                pair_id: uuid::Uuid::new_v4().to_string(),
                endpoint: Endpoint {
                    name: primary.clone(),
                    identity: fake.identity(&primary),
                },
                peer: Endpoint {
                    name: secondary.clone(),
                    identity: fake.identity(&secondary),
                },
                role: Role::Primary,
            };
            fake.set(&primary, PAIR_PROPERTY, &record.encode().unwrap());
            fake.set(
                &secondary,
                PAIR_PROPERTY,
                &record.counterpart().encode().unwrap(),
            );
        }
        let mut inventory = MenuInventory::default();
        let refresh = |inventory: &mut MenuInventory, fake: &crate::tree::fake::Fake| {
            inventory.refresh_with(|| Ok((fake.state().unwrap(), vec![])))
        };
        assert!(refresh(&mut inventory, &fake));
        assert_eq!(
            inventory.pairs,
            [
                "a/ROOT/be1 -> b/ROOT/be1",
                "a/fleet-source -> b/fleet-source",
                "a/scratch -> b/scratch"
            ]
        );
        fake.datasets.remove("a/scratch");
        assert!(refresh(&mut inventory, &fake));
        assert!(
            inventory
                .pairs
                .iter()
                .any(|row| row.contains("peer a/scratch: it is not in its imported pool"))
        );
        fake.pools.remove("a");
        fake.datasets
            .retain(|name, _| zfs_tools::engine::pool_of(name) != "a");
        assert!(refresh(&mut inventory, &fake));
        let mut listing = Vec::new();
        render_menu_listing(&inventory, &mut listing).unwrap();
        let listing = String::from_utf8(listing).unwrap();
        assert!(listing.contains("Recorded pairs (primary -> secondary)"));
        assert!(listing.contains("status --devices"));
        for leaf in ["ROOT/be1", "fleet-source", "scratch"] {
            assert!(listing.contains(&format!(
                "a/{leaf} -> b/{leaf}  peer a/{leaf}: its pool is not imported"
            )));
        }
    }

    #[test]
    fn inconsistent_menu_inventory_keeps_the_last_view_and_retries_before_countdown() {
        let mut inventory = MenuInventory::default();
        let inconsistent = || {
            Err(
                NativeError::Inconsistent("dataset outside observed pools/request: e2ea".into())
                    .into(),
            )
        };
        assert!(!inventory.refresh_with(inconsistent));
        assert!(inventory.retry_needed());
        assert!(inventory.entries.is_empty());
        assert!(inventory.countdown_state().is_none());

        let first_state = fixture(true);
        let mut first = menu_entry(
            "tank/ROOT/be",
            true,
            None,
            vec![menu_kernel("boot/vmlinuz-1", "boot/initrd.img-1", true)],
            None,
        );
        first.candidate = candidates(&first_state)
            .into_iter()
            .find(|candidate| candidate.dataset == "tank/ROOT/be")
            .unwrap();
        let first_identity = first.candidate.identity.clone();
        assert!(inventory.refresh_with(|| Ok((first_state, vec![first.clone()]))));
        assert!(!inventory.retry_needed());
        assert!(inventory.countdown_state().is_some());
        assert!(auto_boot_request(&inventory.entries).is_some());

        assert!(!inventory.refresh_with(inconsistent));
        let first_error = inventory.error.clone();
        assert!(!inventory.refresh_with(inconsistent));
        assert_eq!(inventory.error, first_error);
        assert_eq!(inventory.entries, [first]);
        assert_eq!(
            candidates(inventory.state.as_ref().unwrap())[0].identity,
            first_identity
        );
        assert!(inventory.retry_needed());
        assert!(
            inventory.countdown_state().is_none(),
            "cached entries cannot authorize automatic boot after an inconsistent observation"
        );

        let fresh_state = fixture_with_be_guid(true, 4);
        let mut fresh = inventory.entries[0].clone();
        fresh.candidate = candidates(&fresh_state)
            .into_iter()
            .find(|candidate| candidate.dataset == "tank/ROOT/be")
            .unwrap();
        fresh.kernels = vec![menu_kernel("boot/vmlinuz-2", "boot/initrd.img-2", true)];
        let fresh_identity = fresh.candidate.identity.clone();
        assert_ne!(fresh_identity, first_identity);
        assert!(inventory.refresh_with(|| Ok((fresh_state, vec![fresh.clone()]))));
        assert_eq!(inventory.entries, [fresh]);
        assert_eq!(
            candidates(inventory.countdown_state().unwrap())[0].identity,
            fresh_identity
        );
        assert!(!inventory.retry_needed());
        assert_eq!(
            auto_boot_request(&inventory.entries)
                .unwrap()
                .kernel
                .as_deref(),
            Some(Path::new("boot/vmlinuz-2"))
        );
    }

    pub(in crate::menu) fn menu_entry(
        dataset: &str,
        be_default: bool,
        refusal: Option<&str>,
        kernels: Vec<menu_view::KernelChoice>,
        asset_refusal: Option<&str>,
    ) -> menu_view::MenuEntry {
        menu_view::MenuEntry {
            candidate: BootCandidate {
                dataset: dataset.into(),
                identity: DatasetIdentity {
                    pool_guid: zfs_tools::engine::Guid::new(1),
                    guid: zfs_tools::engine::Guid::new(2),
                    createtxg: zfs_tools::engine::Txg::new(3),
                    objsetid: zfs_tools::engine::ObjsetId::new(4),
                },
                default: be_default,
                once: false,
                ownership: None,
                refusal: refusal.map(str::to_owned),
            },
            kernels,
            asset_refusal: asset_refusal.map(str::to_owned),
        }
    }

    pub(in crate::menu) fn menu_kernel(
        kernel: &str,
        initrd: &str,
        default: bool,
    ) -> menu_view::KernelChoice {
        menu_view::KernelChoice {
            assets: None,
            kernel: kernel.into(),
            initrd: initrd.into(),
            default,
        }
    }

    #[test]
    fn a_boot_inventories_only_the_be_it_can_select() {
        let extra = ["tank/ROOT/b".to_owned(), "tank/ROOT/c".to_owned()];
        let state = fixture_with_extra_bes(&extra, "tank/ROOT/be");
        let read = |_: &Path| {
            Ok(vec![menu_view::KernelChoice {
                kernel: "boot/vmlinuz-1".into(),
                initrd: "boot/initrd.img-1".into(),
                default: true,
                assets: None,
            }])
        };
        let inventory = |candidates: Vec<BootCandidate>| {
            let mut backend = Fake::new();
            backend.state = state.clone();
            let entries = entries_with(&state, candidates, &mut backend, read).unwrap();
            (entries, backend.observations)
        };
        let (all, observed) = inventory(candidates(&state));
        assert_eq!(all.len(), 3);
        assert!(
            all.iter()
                .all(|entry| entry.candidate.refusal.is_none() && entry.asset_refusal.is_none())
        );
        // Three observations per inventoried BE: before mount, after mount, after reading.
        assert_eq!(observed, 9);
        for (dataset, kernel) in [
            (Some("tank/ROOT/c"), None),
            (Some("tank/ROOT/b"), Some("1")),
            (None, None),
            (None, Some("1")),
        ] {
            let (selected, observed) = inventory(boot_candidates(&state, dataset));
            assert_eq!(selected.len(), 1);
            assert_eq!(observed, 3);
            let request = |entries: &Vec<menu_view::MenuEntry>| {
                crate::menu::select::boot_request(
                    dataset.map(str::to_owned),
                    kernel.map(str::to_owned),
                    || Ok(entries.clone()),
                )
                .unwrap()
            };
            assert_eq!(request(&selected), request(&all), "{dataset:?} {kernel:?}");
        }
        let (missing, observed) = inventory(boot_candidates(&state, Some("tank/ROOT/gone")));
        assert!(missing.is_empty());
        assert_eq!(observed, 0);
    }

    #[test]
    fn guided_restore_workspace_be_is_hidden_from_boot_candidates() {
        let id = "0123456789abcdef";
        let staged = format!("tank/zboot-restore-{id}/layout/ROOT/be1");
        let legitimate = format!("tank/ROOT/zboot-restore-{id}");
        let invalid_id = "0123456789ABCDEF";
        let similar = format!("tank/zboot-restore-{invalid_id}/layout/ROOT/be2");
        let state = fixture_with_extra_bes(
            &[staged.clone(), legitimate.clone(), similar.clone()],
            "tank/ROOT/be",
        );

        let candidates = candidates(&state);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.dataset != staged)
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.dataset == legitimate)
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.dataset == similar)
        );
        assert!(
            candidates
                .iter()
                .any(|candidate| candidate.dataset == "tank/ROOT/be")
        );
    }

    #[test]
    fn guided_restore_workspace_default_is_visible_and_refused_without_fallback() {
        let id = "0123456789abcdef";
        let staged = format!("tank/zboot-restore-{id}/layout/ROOT/be1");
        let state = fixture_with_extra_bes(std::slice::from_ref(&staged), &staged);

        let candidates = candidates(&state);
        assert!(candidates.iter().any(|candidate| {
            candidate.dataset == "tank/ROOT/be" && candidate.refusal.is_none()
        }));
        assert!(candidates.iter().any(|candidate| {
            candidate.dataset == staged
                && candidate.default
                && candidate
                    .refusal
                    .as_deref()
                    .is_some_and(|reason| reason.contains("guided restore workspace cannot boot"))
        }));
    }

    #[test]
    fn menu_inventory_lists_real_pairs_and_preserves_pointer_default() {
        let scratch = Scratch::new();
        std::fs::create_dir(scratch.0.join("boot")).unwrap();
        for name in [
            "vmlinuz-1",
            "initrd.img-1",
            "vmlinuz-2",
            "initrd.img-2",
            "vmlinuz-orphan",
        ] {
            std::fs::write(scratch.0.join("boot").join(name), b"asset").unwrap();
        }
        let choices = kernel_choices(&scratch.0).unwrap();
        assert_eq!(choices.len(), 2);
        assert!(choices.iter().all(|choice| !choice.default));
        std::os::unix::fs::symlink("boot/vmlinuz-1", scratch.0.join("vmlinuz")).unwrap();
        std::os::unix::fs::symlink("boot/initrd.img-1", scratch.0.join("initrd.img")).unwrap();
        let choices = kernel_choices(&scratch.0).unwrap();
        assert_eq!(choices.len(), 2);
        assert_eq!(choices.iter().filter(|choice| choice.default).count(), 1);
        assert_eq!(
            choices.iter().find(|choice| choice.default).unwrap().kernel,
            Path::new("boot/vmlinuz-1")
        );
        std::fs::remove_file(scratch.0.join("boot/vmlinuz-1")).unwrap();
        let choices = kernel_choices(&scratch.0).unwrap();
        assert_eq!(choices.len(), 1);
        assert!(!choices[0].default); // Broken default never silently selects the remaining kernel.
    }

    #[test]
    fn menu_inventory_refuses_escape_empty_and_unbounded_directories() {
        let scratch = Scratch::new();
        std::fs::create_dir(scratch.0.join("boot")).unwrap();
        assert!(kernel_choices(&scratch.0).is_err());
        std::os::unix::fs::symlink("/etc/passwd", scratch.0.join("vmlinuz")).unwrap();
        std::fs::write(scratch.0.join("initrd.img"), b"initrd").unwrap();
        assert!(
            kernel_choices(&scratch.0)
                .unwrap_err()
                .to_string()
                .contains("escapes")
        );
        std::fs::remove_file(scratch.0.join("vmlinuz")).unwrap();
        for index in 0..4097 {
            std::fs::write(scratch.0.join("boot").join(index.to_string()), b"").unwrap();
        }
        assert!(
            kernel_choices(&scratch.0)
                .unwrap_err()
                .to_string()
                .contains("4096")
        );
    }

    #[test]
    fn menu_mount_inventory_revalidates_and_cleans_up_without_write_actions() {
        let mut backend = Fake::new();
        let writable = fixture(false);
        let candidate = candidates(&writable).remove(0);
        assert!(inventory_with(&writable, &candidate, &mut backend, |_| Ok(Vec::new())).is_err());
        assert!(backend.actions.is_empty());
        for drift in [false, true] {
            let mut backend = Fake::new();
            backend.drift = drift;
            let state = backend.state.clone();
            let candidate = candidates(&state).remove(0);
            let result =
                inventory_with(&state, &candidate, &mut backend, |_| Ok(Vec::new())).unwrap();
            assert_eq!(result.is_err(), drift);
            assert!(matches!(
                backend.actions.as_slice(),
                [Action::MountReadonly { .. }, Action::Unmount { .. }]
            ));
        }
        let mut backend = Fake::new();
        let state = backend.state.clone();
        let candidate = candidates(&state).remove(0);
        assert!(
            inventory_with(&state, &candidate, &mut backend, |_| Err(refuse(
                "missing assets"
            )))
            .unwrap()
            .is_err()
        );
        assert!(matches!(
            backend.actions.last(),
            Some(Action::Unmount { .. })
        ));
        backend.fail_unmount = true;
        assert!(inventory_with(&state, &candidate, &mut backend, |_| Ok(Vec::new())).is_err());
    }

    #[test]
    fn menu_inventory_cleanup_preserves_the_asset_error() {
        let mut backend = Fake::new();
        backend.fail_cleanup = true;
        let state = backend.state.clone();
        let candidate = candidates(&state).remove(0);
        let error = inventory_with(&state, &candidate, &mut backend, |_| {
            Err(io::Error::from_raw_os_error(libc::EROFS).into())
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("kernel inventory failed ("),
            "{error}"
        );
        assert!(error.to_string().contains("os error 30"), "{error}");
        assert!(
            error.to_string().contains(
                "remove RAM workspace after kernel inventory failed: workspace cleanup denied"
            ),
            "{error}"
        );
        assert!(error_sources_include_erofs(&error));
        assert!(matches!(
            backend.actions.last(),
            Some(Action::Unmount { .. })
        ));

        let mut backend = Fake::new();
        backend.fail_unmount = true;
        let state = backend.state.clone();
        let candidate = candidates(&state).remove(0);
        let error = inventory_with(&state, &candidate, &mut backend, |_| {
            Err(io::Error::from_raw_os_error(libc::EROFS).into())
        })
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("release selected BE mount after kernel inventory failed: busy mount"),
            "{error}"
        );
        assert!(error_sources_include_erofs(&error));
    }

    #[test]
    fn candidates_refuse_a_pending_boot_environment() {
        let mut state = fixture(true);
        let refusal = |state: &NativeState| {
            candidates(state)
                .into_iter()
                .find(|candidate| candidate.dataset == "tank/ROOT/be")
                .unwrap()
                .refusal
        };
        assert_eq!(refusal(&state), None);
        state
            .dataset_properties
            .get_mut("tank/ROOT/be")
            .unwrap()
            .insert("zboot:pending".into(), prop("unfinished"));
        assert!(refusal(&state).is_some());
    }
    #[test]
    fn a_displayed_boot_probes_each_candidate_once_then_only_the_selected_mount() {
        let mut backend = Fake::new();
        backend.state = two_bes(false);
        let state = backend.state.clone();
        let mut entries = Vec::new();
        for candidate in candidates(&state) {
            let kernels = inventory_with(&state, &candidate, &mut backend, |_| {
                let mut kernel = menu_kernel("boot/vmlinuz-1", "boot/initrd.img-1", true);
                kernel.assets = Some(AssetHashes {
                    kernel_sha256: "a".repeat(64),
                    initrd_sha256: "b".repeat(64),
                });
                Ok(vec![kernel])
            })
            .unwrap()
            .unwrap();
            entries.push(menu_view::MenuEntry {
                candidate,
                kernels,
                asset_refusal: None,
            });
        }
        assert_eq!(entries.len(), 2);
        let mounts = |actions: &[Action], name: &str| {
            actions.iter().filter(|action|
            matches!(action, Action::MountReadonly {dataset, ..} if dataset == name)).count()
        };
        for name in ["tank/ROOT/be", "tank/ROOT/b"] {
            assert_eq!(mounts(&backend.actions, name), 1);
        }
        // A listed request goes to the handoff without repeating the all-BE probe.
        let request = menu_view::select(&entries, "2.1").unwrap();
        assert_eq!(request.dataset, "tank/ROOT/be");
        let error = handoff_with(&request, &mut backend).unwrap_err();
        assert!(error.to_string().contains("kexec returned"), "{error}");
        assert_eq!(mounts(&backend.actions, "tank/ROOT/be"), 2);
        assert_eq!(mounts(&backend.actions, "tank/ROOT/b"), 1);
    }

    #[test]
    fn asynchronous_menu_snapshots_start_on_a_new_physical_line() {
        let mut output = Vec::new();
        let mut shown = false;
        menu_prompt(&mut output, &mut shown).unwrap();
        render_menu_listing(&MenuInventory::default(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.starts_with("zboot> \nZboot menu "));
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("Zboot menu "))
                .count(),
            1
        );
    }
}
