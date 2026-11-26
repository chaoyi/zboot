//! Pure presentation and selection for the standalone recovery menu.
//!
//! The parent recovery module owns native observation and revalidation.  This
//! module only renders the already bounded inventory and maps a displayed
//! number back to a handoff request; it never discovers or invents assets.

use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub(crate) struct KernelChoice {
    pub(crate) kernel: PathBuf,
    pub(crate) initrd: PathBuf,
    pub(crate) default: bool,
    pub(crate) assets: Option<crate::handoff::AssetHashes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MenuEntry {
    pub(super) candidate: crate::menu::inventory::BootCandidate,
    pub(super) kernels: Vec<KernelChoice>,
    pub(super) asset_refusal: Option<String>,
}

fn escaped(value: &str) -> String {
    zfs_tools::engine::escape_display(value)
}

fn escaped_path(path: &Path) -> String {
    escaped(&path.to_string_lossy())
}

fn blocked_reason(entry: &MenuEntry) -> Option<&str> {
    entry
        .candidate
        .refusal
        .as_deref()
        .or(entry.asset_refusal.as_deref())
}

/// Render each BE with its stable menu number and each kernel pair as `N.M`.
pub(super) fn render(entries: &[MenuEntry], writer: &mut impl Write) -> super::Result<()> {
    writeln!(
        writer,
        "Zboot menu {} - boot environments",
        crate::build_identity::VERSION
    )?;

    let mut previous_pool: Option<&str> = None;
    for (entry_index, entry) in entries.iter().enumerate() {
        let dataset = entry.candidate.dataset.as_str();
        let pool = dataset.split_once('/').map_or(dataset, |(pool, _)| pool);
        if previous_pool != Some(pool) {
            if previous_pool.is_some() {
                writeln!(writer)?;
            }
            writeln!(writer, "-- pool {} --", escaped(pool))?;
            previous_pool = Some(pool);
        }

        let number = entry_index + 1;
        let default_label = if entry.candidate.default {
            " [default]"
        } else {
            ""
        };
        write!(writer, "{number}: {}{default_label}", escaped(dataset))?;
        if let Some(reason) = blocked_reason(entry) {
            write!(writer, "  blocked: {}", escaped(reason))?;
        }
        writeln!(writer)?;

        if entry.candidate.once {
            writeln!(writer, "  [once] Selected for the next boot")?;
        }

        for (kernel_index, kernel) in entry.kernels.iter().enumerate() {
            let kernel_default = if kernel.default { " [default]" } else { "" };
            let branch = if kernel_index + 1 == entry.kernels.len() {
                "└─"
            } else {
                "├─"
            };
            writeln!(
                writer,
                "  {branch} {number}.{}: {}  + {}{}",
                kernel_index + 1,
                escaped_path(&kernel.kernel),
                escaped_path(&kernel.initrd),
                kernel_default
            )?;
        }
    }

    if entries.is_empty() {
        writeln!(writer, "No boot environments are currently imported.")?;
    }
    Ok(())
}

fn positive_number(value: &str) -> Option<usize> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value = value.parse::<usize>().ok()?;
    (value > 0).then_some(value)
}

fn parse_selection(input: &str) -> Option<(usize, Option<usize>)> {
    let input = input.trim();
    let (entry, kernel) = match input.split_once('.') {
        Some((entry, kernel)) => (entry, Some(kernel)),
        None => (input, None),
    };
    let entry = positive_number(entry)?;
    let kernel = match kernel {
        Some(kernel) => Some(positive_number(kernel)?),
        None => None,
    };
    Some((entry, kernel))
}

fn invalid_selection(input: &str) -> super::Result<crate::handoff::HandoffRequest> {
    Err(super::refuse(format!(
        "invalid menu selection: {}",
        escaped(input)
    )))
}

fn unknown_selection(input: &str) -> super::Result<crate::handoff::HandoffRequest> {
    Err(super::refuse(format!(
        "unknown menu selection: {}",
        escaped(input)
    )))
}

fn blocked_selection(entry: &MenuEntry) -> super::Result<crate::handoff::HandoffRequest> {
    let reason = entry
        .candidate
        .refusal
        .as_deref()
        .expect("blocked_selection called only for a refused candidate");
    Err(super::refuse(format!(
        "boot environment {} is blocked: {}",
        escaped(&entry.candidate.dataset),
        escaped(reason)
    )))
}

/// Map a displayed `N` or `N.M` selection to a handoff request.
///
/// A plain BE number carries the displayed default pair as explicit paths. It
/// is accepted only when the BE and its assets are unblocked and exactly one
/// pair is marked default; explicit `N.M` selections carry the chosen pair and
/// may be used when the BE has no unambiguous default pair. Both forms bind the
/// observed native dataset identity and listed asset hashes for handoff revalidation.
pub(super) fn select(
    entries: &[MenuEntry],
    input: &str,
) -> super::Result<crate::handoff::HandoffRequest> {
    let Some((entry_number, kernel_number)) = parse_selection(input) else {
        return invalid_selection(input);
    };
    let Some(entry) = entry_number
        .checked_sub(1)
        .and_then(|index| entries.get(index))
    else {
        return unknown_selection(input);
    };

    if entry.candidate.refusal.is_some() {
        return blocked_selection(entry);
    }

    if let Some(reason) = entry.asset_refusal.as_deref() {
        return Err(super::refuse(format!(
            "boot environment {} assets are blocked: {}",
            escaped(&entry.candidate.dataset),
            escaped(reason)
        )));
    }
    let Some(kernel_number) = kernel_number else {
        let mut defaults = entry.kernels.iter().filter(|kernel| kernel.default);
        let Some(default) = defaults.next() else {
            return Err(super::refuse(format!(
                "boot environment {} has no unambiguous kernel/initrd pair; select N.M",
                escaped(&entry.candidate.dataset)
            )));
        };
        if defaults.next().is_some() {
            return Err(super::refuse(format!(
                "boot environment {} has no unambiguous kernel/initrd pair; select N.M",
                escaped(&entry.candidate.dataset)
            )));
        }
        return Ok(crate::handoff::HandoffRequest {
            selection: crate::handoff::PairSelection::DefaultPair,
            dataset: entry.candidate.dataset.clone(),
            kernel: Some(default.kernel.clone()),
            initrd: Some(default.initrd.clone()),
            expected_identity: Some(entry.candidate.identity.clone()),
            expected_assets: default.assets.clone(),
        });
    };

    let Some(kernel) = kernel_number
        .checked_sub(1)
        .and_then(|index| entry.kernels.get(index))
    else {
        return unknown_selection(input);
    };
    Ok(crate::handoff::HandoffRequest {
        selection: crate::handoff::PairSelection::Explicit,
        dataset: entry.candidate.dataset.clone(),
        kernel: Some(kernel.kernel.clone()),
        initrd: Some(kernel.initrd.clone()),
        expected_identity: Some(entry.candidate.identity.clone()),
        expected_assets: kernel.assets.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zfs_tools::engine::{DatasetIdentity, Guid, ObjsetId, Txg};

    fn candidate(
        dataset: &str,
        default: bool,
        refusal: Option<&str>,
    ) -> crate::menu::inventory::BootCandidate {
        crate::menu::inventory::BootCandidate {
            dataset: dataset.into(),
            identity: DatasetIdentity {
                pool_guid: Guid::new(1),
                guid: Guid::new(2),
                createtxg: Txg::new(3),
                objsetid: ObjsetId::new(4),
            },
            default,
            once: false,
            ownership: None,
            refusal: refusal.map(str::to_owned),
        }
    }

    fn hashes() -> crate::handoff::AssetHashes {
        crate::handoff::AssetHashes {
            kernel_sha256: "a".repeat(64),
            initrd_sha256: "b".repeat(64),
        }
    }

    fn kernel(name: &str, initrd: &str, default: bool) -> KernelChoice {
        KernelChoice {
            kernel: name.into(),
            initrd: initrd.into(),
            default,
            assets: Some(hashes()),
        }
    }

    fn entry(
        dataset: &str,
        be_default: bool,
        refusal: Option<&str>,
        kernels: Vec<KernelChoice>,
        asset_refusal: Option<&str>,
    ) -> MenuEntry {
        MenuEntry {
            candidate: candidate(dataset, be_default, refusal),
            kernels,
            asset_refusal: asset_refusal.map(str::to_owned),
        }
    }

    #[test]
    fn selection_maps_be_and_kernel_numbers() {
        let entries = vec![
            entry(
                "tank/ROOT/stable",
                true,
                None,
                vec![
                    kernel("vmlinuz", "initrd.img", true),
                    kernel("boot/vmlinuz-old", "boot/initrd.img-old", false),
                ],
                None,
            ),
            entry(
                "rpool/ROOT/recovery",
                false,
                None,
                vec![kernel("boot/vmlinuz-rescue", "boot/initrd-rescue", false)],
                None,
            ),
        ];

        assert_eq!(
            select(&entries, "1").unwrap(),
            crate::handoff::HandoffRequest {
                selection: crate::handoff::PairSelection::DefaultPair,
                dataset: "tank/ROOT/stable".into(),
                kernel: Some("vmlinuz".into()),
                initrd: Some("initrd.img".into()),
                expected_assets: Some(hashes()),
                expected_identity: Some(DatasetIdentity {
                    pool_guid: Guid::new(1),
                    guid: Guid::new(2),
                    createtxg: Txg::new(3),
                    objsetid: ObjsetId::new(4),
                }),
            }
        );
        assert_eq!(
            select(&entries, "1.2").unwrap(),
            crate::handoff::HandoffRequest {
                selection: crate::handoff::PairSelection::Explicit,
                dataset: "tank/ROOT/stable".into(),
                kernel: Some("boot/vmlinuz-old".into()),
                initrd: Some("boot/initrd.img-old".into()),
                expected_assets: Some(hashes()),
                expected_identity: Some(DatasetIdentity {
                    pool_guid: Guid::new(1),
                    guid: Guid::new(2),
                    createtxg: Txg::new(3),
                    objsetid: ObjsetId::new(4),
                }),
            }
        );
        assert_eq!(
            select(&entries, "2.1").unwrap(),
            crate::handoff::HandoffRequest {
                selection: crate::handoff::PairSelection::Explicit,
                dataset: "rpool/ROOT/recovery".into(),
                kernel: Some("boot/vmlinuz-rescue".into()),
                initrd: Some("boot/initrd-rescue".into()),
                expected_assets: Some(hashes()),
                expected_identity: Some(DatasetIdentity {
                    pool_guid: Guid::new(1),
                    guid: Guid::new(2),
                    createtxg: Txg::new(3),
                    objsetid: ObjsetId::new(4),
                }),
            }
        );
    }

    #[test]
    fn selection_retains_both_listed_asset_hashes() {
        let mut other = kernel("vmlinuz-old", "initrd-old", false);
        other.assets = Some(crate::handoff::AssetHashes {
            kernel_sha256: "c".repeat(64),
            initrd_sha256: "d".repeat(64),
        });
        let entries = [entry(
            "tank/ROOT/stable",
            true,
            None,
            vec![kernel("vmlinuz", "initrd.img", true), other],
            None,
        )];
        assert_eq!(
            select(&entries, "1").unwrap().expected_assets,
            Some(hashes())
        );
        assert_eq!(
            select(&entries, "1.2").unwrap().expected_assets,
            entries[0].kernels[1].assets
        );
    }

    #[test]
    fn render_preserves_legacy_rows_and_shows_tree_pool_and_escaping() {
        let entries = vec![
            entry(
                "tank/ROOT/stable",
                true,
                None,
                vec![kernel("boot/vmlinuz", "boot/initrd.img", true)],
                None,
            ),
            entry(
                "tank/ROOT/old",
                false,
                Some("secondary cannot boot\nnow"),
                vec![],
                None,
            ),
            entry(
                "rpool/ROOT/recovery",
                false,
                None,
                vec![],
                Some("no pair at \\run"),
            ),
        ];
        let mut output = Vec::new();
        render(&entries, &mut output).unwrap();
        let output = String::from_utf8(output).unwrap();

        assert!(output.starts_with(&format!(
            "Zboot menu {} - boot environments\n-- pool tank --\n",
            crate::build_identity::VERSION
        )));
        assert!(output.contains("1: tank/ROOT/stable [default]\n"));
        assert!(output.contains("  └─ 1.1: boot/vmlinuz  + boot/initrd.img [default]\n"));
        assert!(output.contains("2: tank/ROOT/old  blocked: secondary cannot boot\\u{a}now\n"));
        assert!(output.contains("-- pool rpool --\n"));
        assert!(output.ends_with("3: rpool/ROOT/recovery  blocked: no pair at \\\\run\n"));
        assert!(!output.contains("secondary cannot boot\nnow"));
    }

    #[test]
    fn blocked_and_defaultless_selection_requires_explicit_pair() {
        let entries = vec![
            entry(
                "tank/ROOT/blocked",
                true,
                Some("secondary cannot boot"),
                vec![kernel("vmlinuz", "initrd.img", true)],
                None,
            ),
            entry(
                "tank/ROOT/assets",
                false,
                None,
                vec![],
                Some("no matching kernel/initrd pairs found"),
            ),
            entry(
                "tank/ROOT/multiple",
                false,
                None,
                vec![
                    kernel("vmlinuz-a", "initrd-a", false),
                    kernel("vmlinuz-b", "initrd-b", false),
                ],
                None,
            ),
        ];

        assert!(select(&entries, "1").is_err());
        assert!(select(&entries, "1.1").is_err());
        let asset_error = select(&entries, "2").unwrap_err().to_string();
        assert!(asset_error.contains("no matching kernel/initrd pairs found"));
        let default_error = select(&entries, "3").unwrap_err().to_string();
        assert!(default_error.contains("select N.M"));
        assert_eq!(
            select(&entries, "3.2").unwrap().kernel,
            Some(PathBuf::from("vmlinuz-b"))
        );
    }

    #[test]
    fn malformed_zero_overflow_and_out_of_range_numbers_refuse() {
        let entries = vec![entry(
            "tank/ROOT/stable",
            true,
            None,
            vec![kernel("vmlinuz", "initrd.img", true)],
            None,
        )];
        for input in [
            "",
            "0",
            "0.1",
            "1.0",
            "1.",
            ".1",
            "1.2.3",
            "one",
            "184467440737095516160",
        ] {
            assert!(select(&entries, input).is_err(), "{input:?}");
        }
        assert!(select(&entries, "2").is_err());
        assert!(select(&entries, "1.2").is_err());
    }
}
