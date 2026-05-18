//! `Source` URL parsing — the pluggable backend for `populate_be`.
//!
//! Two MVP variants (tar, debootstrap); the rest of the catalog from
//! DESIGN.md § "Sources" is rejected at parse time with a pointer to
//! when it's expected to land.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};

/// `Debootstrap` carries only `suite` and an optional `mirror`. The
/// package set, components, and chroot-handling are baked in by
/// `populate_from_debootstrap` — a bootable BE is the only contract
/// `zboot deploy` makes, and exposing knobs for the rest just invites
/// half-configured BEs to land in production.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Source {
    Tar {
        path: String,
    },
    Debootstrap {
        suite: String,
        mirror: Option<String>,
    },
}

/// Packages always installed by the debootstrap source — the minimum
/// to produce a BE the kexec handoff can actually boot into AND that
/// reaches userspace once `run-init` pivots:
///
/// - **`linux-image-amd64`** — the kernel. Without it, the BE renders
///   in the menu but kexec fails with "no kernel found".
/// - **`linux-headers-amd64`** — required by zfs-dkms's postinst to
///   build the matching `zfs.ko`.
/// - **`zfs-dkms`** — builds the kernel module against the installed
///   kernel. Triggers an in-chroot DKMS compile (~minutes).
/// - **`zfs-initramfs`** — wires the BE's initramfs to import the pool
///   and mount the root dataset on boot.
/// - **`systemd-sysv`** — provides `/sbin/init`. `--variant=minbase`
///   skips this, so without it run-init bails immediately after the
///   pool import with "Target filesystem doesn't have requested
///   /sbin/init".
pub(super) const DEBOOTSTRAP_PACKAGES: &str =
    "linux-image-amd64,linux-headers-amd64,zfs-dkms,zfs-initramfs,systemd-sysv";

/// Components debootstrap pulls from. `contrib` is needed because the
/// zfs-* packages live there on debian trixie.
pub(super) const DEBOOTSTRAP_COMPONENTS: &str = "main,contrib";

/// Fallback mirror when the URL doesn't carry one.
pub(super) const DEFAULT_DEBOOTSTRAP_MIRROR: &str = "http://deb.debian.org/debian";

impl Source {
    pub(super) fn parse(url: &str) -> Result<Self> {
        let (scheme, rest) = url
            .split_once("://")
            .with_context(|| format!("source {url:?} is not a URL — expected `<scheme>://...`"))?;
        match scheme {
            "tar" => {
                if rest.is_empty() {
                    bail!("tar:// source needs a path (e.g. `tar:///payload/root.tar.zst`)");
                }
                Ok(Source::Tar {
                    path: rest.to_owned(),
                })
            }
            "debootstrap" => {
                let (suite, query) = rest.split_once('?').unwrap_or((rest, ""));
                if suite.is_empty() {
                    bail!(
                        "debootstrap:// source needs a suite (e.g. `debootstrap://trixie` or \
                         `debootstrap://testing?mirror=http://deb.debian.org/debian`)",
                    );
                }
                let q = parse_query(query);
                let unknown: Vec<&String> = q.keys().filter(|k| k.as_str() != "mirror").collect();
                if !unknown.is_empty() {
                    bail!(
                        "debootstrap:// only accepts `mirror=` in the query string; \
                         unknown keys: {unknown:?}. Package set + components are \
                         fixed by zboot (see DEBOOTSTRAP_PACKAGES).",
                    );
                }
                Ok(Source::Debootstrap {
                    suite: suite.to_owned(),
                    mirror: q.get("mirror").cloned(),
                })
            }
            "zfs-recv" | "restic" => bail!(
                "source scheme `{scheme}://` is deferred (Phase 2/3); \
                 only `tar://` and `debootstrap://` are wired in MVP",
            ),
            other => {
                bail!("unknown source scheme `{other}://` — expected `tar://` or `debootstrap://`")
            }
        }
    }

    /// One-line human-readable summary for the plan output.
    pub(super) fn render(&self) -> String {
        match self {
            Source::Tar { path } => format!("tar://{path}"),
            Source::Debootstrap { suite, mirror } => match mirror {
                Some(m) => format!("debootstrap://{suite}?mirror={m}"),
                None => format!("debootstrap://{suite}"),
            },
        }
    }
}

/// `?a=1&b=2` → `{a: 1, b: 2}`. Tolerates `?`-less input and trailing
/// `&`s. Values aren't url-decoded — debootstrap mirror URLs don't
/// typically need it, and we keep the parser one-liner small.
fn parse_query(query: &str) -> BTreeMap<String, String> {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}
