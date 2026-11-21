//! The receipt: original placement and the manifest of every copied dataset,
//! on B before any data moves. Streams carry no properties, so once A is
//! erased this is the only record of them. It is a write-once
//! [attachment](zfs_tools::engine::attachment) on the staging container, on
//! B's pool beside the restore record. The Quiesced advance that names it in
//! the record is its commit: before it a resume captures it again from A,
//! which is untouched; from then on every pass reads it where the record
//! names it and nothing writes it again. Completion removes it once no step
//! reads it. An only-copy abandon first copies it outside `zboot:`, as inert
//! placement metadata the staging keeps until it is dropped.
use super::{
    Backend, DatasetView, State, View,
    manifest::{self, Copied, Keys},
    refuse, tree_digest,
};
use crate::{
    menu::{RecoveryError, Result},
    placement::ReceivePlacement,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zfs_tools::engine::{
    DatasetIdentity, Guid,
    attachment::{self, Attachment, AttachmentBackend, Key},
    management::Endpoint,
    native::NativeProperty,
};

const KEYS: &[&str] = &[
    "mountpoint",
    "readonly",
    "canmount",
    "volmode",
    "zboot:placement",
    "zboot:cmdline",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Member {
    pub identity: DatasetIdentity,
    pub volume: bool,
    pub placement: ReceivePlacement,
    pub managed: BTreeMap<String, String>,
    /// Copied properties with their class on the source.
    pub properties: BTreeMap<String, Copied>,
    /// Its key; `None` for a plaintext dataset.
    pub encryption: Option<Keys>,
    /// Its role in the pair it was part of: a former fenced copy returns
    /// fenced, a former working copy active, both unpaired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<zfs_tools::engine::management::Role>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tree {
    /// Actual metadata source: A before erasure, or an old staged copy.
    pub observed: Endpoint,
    pub original_guid: Guid,
    pub digest: String,
    pub members: BTreeMap<String, Member>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Receipt {
    pub restore_id: String,
    pub source: Endpoint,
    pub source_tree: Tree,
    /// Keys are the kept roots' original pool-relative names.
    pub kept: BTreeMap<String, Tree>,
}

/// The receipt's attachment key: `zboot:attachment:ID:receipt:`.
pub(super) fn key(id: &str) -> Result<Key> {
    Ok(Key::new(id, "receipt")?)
}

pub(super) fn endpoint(view: &View, state: &State) -> Result<Endpoint> {
    let owner = view
        .dataset(&state.staging)
        .ok_or_else(|| refuse("restore placement receipt owner disappeared"))?;
    if owner.identity.pool_guid != state.source.identity.pool_guid {
        return Err(refuse(
            "restore placement receipt is on another pool incarnation",
        ));
    }
    Ok(Endpoint {
        name: owner.name.clone(),
        identity: owner.identity.clone(),
    })
}

fn native(error: crate::menu::RecoveryError) -> zfs_tools::engine::Error {
    match error {
        crate::menu::RecoveryError::Native(error) => error,
        error => zfs_tools::engine::Error::Inconsistent(error.to_string()),
    }
}

/// Restore's existing typed effects are also the attachment's backend, so
/// every chunk write is a cut and lost-reply seam of its own.
pub(super) struct Store<'a, B: Backend>(pub &'a mut B);
impl<B: Backend> Store<'_, B> {
    fn bound(
        &mut self,
        endpoint: &Endpoint,
    ) -> std::result::Result<DatasetView, zfs_tools::engine::Error> {
        let view = self.0.view().map_err(native)?;
        let member = view
            .dataset(&endpoint.name)
            .filter(|d| d.identity == endpoint.identity)
            .ok_or_else(|| {
                zfs_tools::engine::Error::Inconsistent(
                    "restore receipt owner incarnation changed".into(),
                )
            })?;
        Ok(member.clone())
    }
}
impl<B: Backend> AttachmentBackend for Store<'_, B> {
    fn properties(
        &mut self,
        endpoint: &Endpoint,
    ) -> std::result::Result<BTreeMap<String, NativeProperty>, zfs_tools::engine::Error> {
        Ok(self
            .bound(endpoint)?
            .properties
            .into_iter()
            .map(|(key, p)| {
                (
                    key,
                    NativeProperty {
                        value: p.value,
                        source: p.source,
                    },
                )
            })
            .collect())
    }
    fn set(
        &mut self,
        endpoint: &Endpoint,
        values: &[(String, String)],
    ) -> std::result::Result<(), zfs_tools::engine::Error> {
        attachment::validate_set(values)?;
        self.bound(endpoint)?;
        for (key, value) in values {
            self.0.set(&endpoint.name, key, value).map_err(native)?;
        }
        self.bound(endpoint).map(drop)
    }
    fn inherit(
        &mut self,
        endpoint: &Endpoint,
        key: &str,
    ) -> std::result::Result<(), zfs_tools::engine::Error> {
        // Admit only an attachment chunk; its value plays no part.
        attachment::validate_set(&[(key.into(), "00".into())])?;
        self.bound(endpoint)?;
        self.0.inherit(&endpoint.name, key).map_err(native)?;
        self.bound(endpoint).map(drop)
    }
}

/// The attachment the record names, which must be on the recorded staging.
/// Every caller passes the state of the record as it last read or wrote it.
fn named(state: &State) -> Result<&Attachment> {
    let named = state
        .receipt
        .as_ref()
        .ok_or_else(|| refuse("restore record names no placement receipt"))?;
    if named.endpoint().name != state.staging
        || named.endpoint().identity.pool_guid != state.source.identity.pool_guid
    {
        return Err(refuse(
            "restore record names a placement receipt off its staging",
        ));
    }
    Ok(named)
}

/// Write `receipt` as this restore's attachment on its staging and return
/// its name, for the advance that commits it. Only a restore whose record
/// names no receipt yet writes one: what an interrupted earlier write left
/// is discarded, or adopted when it is exactly this receipt.
pub(super) fn write(
    backend: &mut impl Backend,
    state: &State,
    id: &str,
    receipt: &Receipt,
) -> Result<Attachment> {
    if state.receipt.is_some() {
        return Err(refuse("restore placement receipt is already committed"));
    }
    let owner = endpoint(&backend.view()?, state)?;
    Ok(attachment::write(
        &mut Store(backend),
        &owner,
        &key(id)?,
        receipt,
        None,
    )?)
}

/// The committed receipt, read where the record names it. A named receipt
/// that does not read exactly refuses; it is never captured again.
pub(super) fn read(backend: &mut impl Backend, state: &State, id: &str) -> Result<Receipt> {
    let named = named(state)?;
    let receipt =
        attachment::read::<Receipt>(&mut Store(backend), &key(id)?, named).map_err(|error| {
            refuse(format!(
                "the restore placement receipt on {} does not read: {error}",
                state.staging
            ))
        })?;
    validate(&receipt, state, id)?;
    Ok(receipt)
}

/// How an operator ends restore ID by hand when zboot cannot, while STAGING
/// may hold the only copy of the kept data or of A's original properties:
/// keep the receipt's chunks, copy the data, and only then end it. It never
/// offers to remove a chunk.
fn by_hand(staging: &str, id: &str) -> String {
    format!(
        "to end it by hand, first save what is left of the receipt with `{}`, where \
         {SAVED_ON} is a directory on a disk other than A and B (not RAM, as the zboot menu \
         and a rescue shell run in), copy the kept data from {staging} elsewhere, and only \
         then end the operation (RECOVERY.md, \"Ending a restore by hand\")",
        crate::recipe::save_properties(staging, &format!("{SAVED_ON}/restore-{id}.properties"))
    )
}
/// Where the hand procedure's first step saves the receipt, for the
/// operator to choose.
const SAVED_ON: &str = "/PATH/ON/ANOTHER/DISK";

/// The refusal for a record past the receipt's commit that names none: not
/// a record this zboot leaves, so it never continues.
pub(super) fn unnamed(state: &State, id: &str, only_copy: bool) -> RecoveryError {
    let staging = &state.staging;
    if only_copy {
        refuse(format!(
            "restore record {id} names no placement receipt past the step that commits it, so \
             no zboot left it so. While {staging} may be the only complete copy of the kept \
             data, zboot neither continues nor abandons it, and {staging} stays held and \
             marked: {}",
            by_hand(staging, id)
        ))
    } else {
        refuse(format!(
            "restore record {id} names no placement receipt past the step that commits it, so \
             it cannot continue; `zboot abandon {id}` ends it"
        ))
    }
}

/// `error`, a named receipt that does not read or will not retire, with its
/// chunks named and what may be done. zboot never discards a named receipt
/// unread; where it is not the only copy of what it records, its chunks may
/// be removed by hand once checked, and `zboot VERB ID` then goes on.
pub(super) fn damaged(
    backend: &mut impl Backend,
    state: &State,
    id: &str,
    only_copy: bool,
    verb: &str,
    error: RecoveryError,
) -> RecoveryError {
    let staging = &state.staging;
    let Some(named) = state.receipt.as_ref() else {
        return error;
    };
    // A receipt that reads now failed in passing; it is not damaged.
    if read(backend, state, id).is_ok() {
        return error;
    }
    let (Ok(view), Ok(key)) = (backend.view(), key(id)) else {
        return error;
    };
    let Some(owner) = view
        .dataset(staging)
        .filter(|d| d.identity == named.endpoint().identity)
    else {
        return refuse(format!(
            "{error}. {staging} is not the dataset the record names the receipt on: put that \
             dataset back at {staging}, then run `zboot {verb} {id}` again"
        ));
    };
    let chunks: Vec<&str> = owner
        .properties
        .iter()
        .filter(|(name, p)| name.starts_with(key.prefix()) && p.local())
        .map(|(name, _)| name.as_str())
        .collect();
    let listed = if chunks.is_empty() {
        "none is left".to_owned()
    } else {
        chunks.join(", ")
    };
    if only_copy {
        if owner
            .property(&archive_key(id, "manifest"))
            .is_some_and(|p| p.local())
        {
            return refuse(format!(
                "{error}. An abandon of this restore stopped after copying the receipt to \
                 {ARCHIVE_PREFIX}{id}: on {staging}: run `zboot abandon {id}` again to finish \
                 it from that copy"
            ));
        }
        return refuse(format!(
            "{error}. Its chunks on {staging} ({listed}) are the only record of A's original \
             properties now: do not remove them. zboot neither continues nor abandons this \
             restore until they read; {}",
            by_hand(staging, id)
        ));
    }
    let inherit: Vec<_> = chunks
        .iter()
        .map(|name| format!("`{}`", crate::recipe::inherit(name, staging)))
        .collect();
    refuse(format!(
        "{error}. At this step it is not the only copy of what it records, so it may be \
         removed by hand: check its chunks on {staging} ({listed}) with \
         `zfs get -H -s local all {}`, then {}run `zboot {verb} {id}`",
        crate::recipe::quote(staging),
        if inherit.is_empty() {
            String::new()
        } else {
            format!("remove each with {}, and ", inherit.join(", "))
        }
    ))
}

/// Remove this restore's receipt chunks once nothing reads them: the named
/// attachment from its recorded staging, or what an uncommitted write left
/// there. A staging that is gone took its chunks with it; one renamed is
/// refused by [`admit_cleanup_location`] first. A named receipt that will
/// not retire refuses, naming how `zboot VERB ID` can go on.
pub(super) fn remove(
    backend: &mut impl Backend,
    state: &State,
    id: &str,
    verb: &str,
) -> Result<()> {
    let view = backend.view()?;
    let owner = match &state.receipt {
        Some(_) => {
            let named = named(state)?;
            if let Some(moved) = renamed(&view, named) {
                return Err(refuse(format!(
                    "restore staging {} was renamed to {moved}; restore its recorded name before continuing",
                    state.staging
                )));
            }
            view.dataset(&state.staging)
                .filter(|d| d.identity == named.endpoint().identity)
                .map(|_| named.endpoint().clone())
        }
        None => endpoint(&view, state).ok(),
    };
    if let Some(owner) = owner {
        let key = key(id)?;
        let left = |backend: &mut _| -> Option<Vec<String>> {
            let view: super::View = Backend::view(backend).ok()?;
            Some(
                view.dataset(&owner.name)?
                    .properties
                    .keys()
                    .filter(|name| name.starts_with(key.prefix()))
                    .cloned()
                    .collect(),
            )
        };
        let before = left(backend);
        // With a named receipt this retires exactly that attachment;
        // without one it discards an unnamed partial write.
        if let Err(error) =
            attachment::remove(&mut Store(backend), &owner, &key, state.receipt.as_ref())
        {
            if left(backend) != before {
                return Err(refuse(format!(
                    "{error}. Part of the restore placement receipt on {} is removed: run \
                     `zboot {verb} {id}` again to finish",
                    state.staging
                )));
            }
            return Err(damaged(backend, state, id, false, verb, error.into()));
        }
    }
    Ok(())
}

/// Where the named receipt's incarnation is now, when not at its name.
fn renamed<'v>(view: &'v View, named: &Attachment) -> Option<&'v str> {
    view.datasets
        .iter()
        .find(|d| d.identity == named.endpoint().identity && d.name != named.endpoint().name)
        .map(|d| d.name.as_str())
}

/// Inert original-placement data, not a coordination record. It deliberately
/// survives abandonment and ordinary raw copying until the staging is
/// dropped: the receipt's attachment chunks, byte for byte, as
/// `org.zfs-tools:restore-placement:ID:NNNN`, then `...:ID:manifest`, the
/// archive's commit, holding the record's name for the receipt.
pub(super) const ARCHIVE_PREFIX: &str = "org.zfs-tools:restore-placement:";

fn archive_key(id: &str, part: &str) -> String {
    format!("{ARCHIVE_PREFIX}{id}:{part}")
}

/// The archive's chunks seen as the receipt's attachment chunks, so the
/// attachment's own write and read build and check them. Only archive
/// chunks are visible through it, never the receipt's own.
struct ArchivedStore<'a, B: Backend> {
    store: Store<'a, B>,
    stored: String,
    named: String,
}
impl<'a, B: Backend> ArchivedStore<'a, B> {
    fn new(backend: &'a mut B, id: &str) -> Result<Self> {
        Ok(Self {
            store: Store(backend),
            stored: archive_key(id, ""),
            named: key(id)?.prefix().to_owned(),
        })
    }
    fn stored(&self, key: &str) -> std::result::Result<String, zfs_tools::engine::Error> {
        let part = key.strip_prefix(&self.named).ok_or_else(|| {
            zfs_tools::engine::Error::Inconsistent("archive key names another receipt".into())
        })?;
        Ok(format!("{}{part}", self.stored))
    }
}
impl<B: Backend> AttachmentBackend for ArchivedStore<'_, B> {
    fn properties(
        &mut self,
        endpoint: &Endpoint,
    ) -> std::result::Result<BTreeMap<String, NativeProperty>, zfs_tools::engine::Error> {
        let mut chunks = BTreeMap::new();
        for (key, property) in self.store.properties(endpoint)? {
            if !key.starts_with(ARCHIVE_PREFIX) {
                continue;
            }
            let part = key.strip_prefix(&self.stored).ok_or_else(|| {
                zfs_tools::engine::Error::Inconsistent(
                    "another restore archive occupies staging".into(),
                )
            })?;
            if part != "manifest" {
                chunks.insert(format!("{}{part}", self.named), property);
            }
        }
        Ok(chunks)
    }
    fn set(
        &mut self,
        endpoint: &Endpoint,
        values: &[(String, String)],
    ) -> std::result::Result<(), zfs_tools::engine::Error> {
        attachment::validate_set(values)?;
        self.store.bound(endpoint)?;
        for (key, value) in values {
            let key = self.stored(key)?;
            self.store
                .0
                .set(&endpoint.name, &key, value)
                .map_err(native)?;
        }
        self.store.bound(endpoint).map(drop)
    }
    fn inherit(
        &mut self,
        endpoint: &Endpoint,
        key: &str,
    ) -> std::result::Result<(), zfs_tools::engine::Error> {
        attachment::validate_set(&[(key.into(), "00".into())])?;
        self.store.bound(endpoint)?;
        let key = self.stored(key)?;
        self.store.0.inherit(&endpoint.name, &key).map_err(native)?;
        self.store.bound(endpoint).map(drop)
    }
}

/// Recover retained placement independently of the now-ended operation. The
/// manifest's endpoint is part of the immutable data, not authority to
/// operate on a later copy at a different endpoint.
pub(super) fn read_archive(
    backend: &mut impl Backend,
    owner: &Endpoint,
    id: &str,
) -> Result<(Attachment, Receipt)> {
    let member = Store(backend).bound(owner)?;
    let manifest = member
        .property(&archive_key(id, "manifest"))
        .filter(|property| property.local())
        .ok_or_else(|| refuse("complete original-placement archive is unavailable"))?;
    let named: Attachment = serde_json::from_str(&manifest.value)
        .map_err(|e| refuse(format!("restore placement archive manifest: {e}")))?;
    if serde_json::to_string(&named).ok().as_ref() != Some(&manifest.value) {
        return Err(refuse(
            "restore placement archive manifest is not its canonical encoding",
        ));
    }
    if named.endpoint() != owner {
        return Err(refuse("restore placement archive names another owner"));
    }
    let receipt =
        attachment::read::<Receipt>(&mut ArchivedStore::new(backend, id)?, &key(id)?, &named)?;
    Ok((named, receipt))
}

/// The receipt's own chunks and the archive's on `member`, by their index
/// part, with their sources.
type Chunks<'v> = BTreeMap<&'v str, &'v super::Property>;
fn chunks<'v>(member: &'v DatasetView, prefix: &str) -> Chunks<'v> {
    member
        .properties
        .iter()
        .filter_map(|(key, property)| Some((key.strip_prefix(prefix)?, property)))
        .filter(|(part, _)| *part != "manifest")
        .collect()
}

/// A renamed owned workspace must never be stranded by retiring its intent.
/// The recorded path may already be occupied by a replacement.
pub(super) fn admit_cleanup_location(
    backend: &mut impl Backend,
    state: &State,
    id: &str,
    staging_required: bool,
) -> Result<()> {
    let view = backend.view()?;
    let mut elsewhere: Vec<_> = view
        .datasets
        .iter()
        .filter(|member| {
            member.name != state.staging
                && member.identity.pool_guid == state.source.identity.pool_guid
                && member
                    .property(zfs_tools::engine::management::STAGING_PROPERTY)
                    .is_some_and(|p| p.local() && p.value == id)
        })
        .map(|member| member.name.as_str())
        .collect();
    // The receipt's own staging, even unmarked, keeps its receipt chunks.
    if let Some(moved) = state
        .receipt
        .as_ref()
        .and_then(|named| renamed(&view, named))
        && !elsewhere.contains(&moved)
    {
        elsewhere.push(moved);
    }
    if !elsewhere.is_empty() {
        return Err(refuse(format!(
            "restore staging {} has marked locations elsewhere ({elsewhere:?}). Its intent and holds are retained. Restore the recorded staging name before continuing",
            state.staging
        )));
    }
    if staging_required && view.dataset(&state.staging).is_none() {
        return Err(refuse(format!(
            "required restore staging {} is missing. Its intent and holds are retained. Restore the recorded staging name before abandoning",
            state.staging
        )));
    }
    Ok(())
}

/// Read-only admission before any abandon effects. The named receipt is the
/// original authority. Only a cut during an earlier only-copy abandon leaves
/// it partly removed, and then only once its archive was complete; the
/// archive stands in for it exactly then: the archive's manifest must be the
/// record's name for the receipt, its chunks must read as that, and the
/// receipt chunks left must be its last ones, each the archive's. Absence
/// never authorizes completion. The staging marker stays until an only-copy
/// abandon finishes, so a retry always finds it.
pub(super) fn prepare_abandon_archive(
    backend: &mut impl Backend,
    state: &State,
    id: &str,
) -> Result<Receipt> {
    admit_cleanup_location(backend, state, id, true)?;
    let view = backend.view()?;
    let member = view
        .dataset(&state.staging)
        .ok_or_else(|| refuse("only-copy staging disappeared during abandon admission"))?;
    if !member
        .property(zfs_tools::engine::management::STAGING_PROPERTY)
        .is_some_and(|property| property.local() && property.value == id)
    {
        return Err(refuse("staging lost its local restore ownership"));
    }
    if state.receipt.is_none() {
        return Err(unnamed(state, id, true));
    }
    let named = named(state)?;
    if *named.endpoint() != endpoint(&view, state)? {
        return Err(refuse(
            "only-copy staging is not the incarnation its placement receipt is on; its intent and holds are retained",
        ));
    }
    let key = key(id)?;
    let own = chunks(member, key.prefix());
    let archive_prefix = archive_key(id, "");
    if let Some(other) = member
        .properties
        .keys()
        .find(|k| k.starts_with(ARCHIVE_PREFIX) && !k.starts_with(&archive_prefix))
    {
        return Err(refuse(format!(
            "another restore archive occupies staging: {other}"
        )));
    }
    let archive = chunks(member, &archive_prefix);
    let manifest = member.property(&archive_key(id, "manifest"));
    let receipt = match attachment::read::<Receipt>(&mut Store(backend), &key, named) {
        Ok(receipt) => {
            // Any archive there was written from this receipt, and is all
            // of it once its manifest is.
            let canonical = serde_json::to_string(named).map_err(|e| refuse(e.to_string()))?;
            let part = archive.iter().all(|(index, chunk)| {
                chunk.local() && own.get(index).is_some_and(|c| c.value == chunk.value)
            });
            let committed = manifest.map(|m| m.local() && m.value == canonical);
            if !part
                || committed == Some(false)
                || (committed.is_some() && archive.len() != own.len())
            {
                return Err(refuse(
                    "restore placement archive differs from its exact canonical receipt",
                ));
            }
            receipt
        }
        Err(error) => {
            let listed: Vec<_> = own
                .keys()
                .map(|part| format!("{}{part}", key.prefix()))
                .collect();
            let (archived, receipt) =
                read_archive(backend, named.endpoint(), id).map_err(|_| {
                    refuse(format!(
                        "the only-copy placement receipt on {} ({}) does not read ({error}) and \
                     staging has no complete archive of it; its intent and holds are retained. \
                     It is the only record of A's original properties now: do not remove it; {}",
                        state.staging,
                        if listed.is_empty() {
                            "none is left".to_owned()
                        } else {
                            listed.join(", ")
                        },
                        by_hand(&state.staging, id)
                    ))
                })?;
            if archived != *named {
                return Err(refuse(
                    "restore placement archive names another receipt than its record",
                ));
            }
            // Removal goes in order, so a cut leaves the receipt's last
            // chunks, each the archive's at its index; only those are retired.
            let first = archive.len().saturating_sub(own.len());
            if own.len() > archive.len()
                || !own
                    .keys()
                    .zip(first..)
                    .all(|(part, index)| *part == format!("{index:04x}"))
                || !own.iter().all(|(index, chunk)| {
                    chunk.local() && archive.get(index).is_some_and(|c| c.value == chunk.value)
                })
            {
                return Err(refuse(
                    "the only-copy placement receipt has chunks its archive does not",
                ));
            }
            receipt
        }
    };
    validate(&receipt, state, id)?;
    Ok(receipt)
}

/// Whether `key` is `value`, locally, on the bound `owner`.
fn archived(backend: &mut impl Backend, owner: &Endpoint, key: &str, value: &str) -> Result<bool> {
    Ok(Store(backend)
        .bound(owner)?
        .property(key)
        .is_some_and(|p| p.local() && p.value == value))
}

/// Copy the named receipt to its archive, chunks first and the manifest,
/// the archive's commit, last; then read the whole archive back.
pub(super) fn publish_archive(
    backend: &mut impl Backend,
    state: &State,
    id: &str,
    receipt: &Receipt,
) -> Result<()> {
    if prepare_abandon_archive(backend, state, id)? != *receipt {
        return Err(refuse(
            "restore placement changed before archive publication",
        ));
    }
    let named = named(state)?;
    let owner = named.endpoint();
    let canonical = serde_json::to_string(named).map_err(|e| refuse(e.to_string()))?;
    let manifest = archive_key(id, "manifest");
    // Once its manifest is there, which admission found to be the record's
    // name, the archive is complete and only read back. Until then whatever
    // a cut left of it is written over, as an unnamed attachment would be.
    if !archived(backend, owner, &manifest, &canonical)? {
        let copied = attachment::write(
            &mut ArchivedStore::new(backend, id)?,
            owner,
            &key(id)?,
            receipt,
            None,
        )?;
        if copied != *named {
            return Err(refuse(
                "restore placement archive is not the receipt its record names",
            ));
        }
        let result = backend.set(&owner.name, &manifest, &canonical);
        if !archived(backend, owner, &manifest, &canonical)? {
            result?;
            return Err(refuse(
                "restore placement archive manifest was not verified",
            ));
        }
    }
    if read_archive(backend, owner, id)? != (named.clone(), receipt.clone()) {
        return Err(refuse(
            "restore placement archive publication was not verified",
        ));
    }
    Ok(())
}

/// Archive the receipt, then remove it: the archive stays as inert data and
/// the ended operation leaves no attachment behind.
pub(super) fn preserve_abandoned(
    backend: &mut impl Backend,
    state: &State,
    id: &str,
    receipt: &Receipt,
) -> Result<()> {
    publish_archive(backend, state, id, receipt)?;
    let named = named(state)?;
    // This retires exactly the receipt the record names, or finishes a
    // retirement a cut left partial.
    attachment::remove(
        &mut Store(backend),
        named.endpoint(),
        &key(id)?,
        Some(named),
    )?;
    if read_archive(backend, named.endpoint(), id)? != (named.clone(), receipt.clone()) {
        return Err(refuse(
            "retained placement changed during coordination cleanup",
        ));
    }
    Ok(())
}

pub(super) fn validate(receipt: &Receipt, state: &State, id: &str) -> Result<()> {
    if receipt.restore_id != id
        || receipt.source != state.source
        || receipt.source_tree.observed != state.source
        || receipt.source_tree.original_guid != state.source.identity.guid
        || Some(&receipt.source_tree.digest) != state.source_digest.as_ref()
        || receipt.kept.len() != state.keep.len()
        || !receipt.source_tree.members.contains_key("")
    {
        return Err(refuse(
            "restore placement receipt differs from the frozen operation",
        ));
    }
    for kept in &state.keep {
        let tree = receipt
            .kept
            .get(&kept.relative)
            .ok_or_else(|| refuse("restore placement receipt lacks a kept tree"))?;
        if tree.original_guid != kept.guid
            || Some(&tree.digest) != kept.digest.as_ref()
            || !tree.members.contains_key("")
        {
            return Err(refuse(
                "restore placement receipt has different kept ancestry",
            ));
        }
    }
    for tree in std::iter::once(&receipt.source_tree).chain(receipt.kept.values()) {
        for (relative, member) in &tree.members {
            if relative.starts_with('/')
                || (!relative.is_empty()
                    && zfs_tools::engine::validate_dataset_name(relative).is_err())
                || member.volume != member.placement.canmount.is_none()
                || member.volume != member.placement.mountpoint.is_none()
                || member.identity.pool_guid != tree.observed.identity.pool_guid
            {
                return Err(refuse("restore placement receipt has invalid membership"));
            }
            if member
                .managed
                .keys()
                .any(|key| !super::MANAGED.contains(&key.as_str()))
            {
                return Err(refuse(
                    "restore placement receipt has an unsupported managed property",
                ));
            }
            if member.properties.keys().any(|key| {
                zfs_tools::engine::management::managed_key(key)
                    || crate::placement::PLACEMENT_KEYS.contains(&key.as_str())
            }) || member
                .encryption
                .as_ref()
                .is_some_and(|keys| !tree.members.contains_key(&keys.root))
            {
                return Err(refuse("restore manifest has an invalid member"));
            }
        }
    }
    Ok(())
}

fn capture_tree(
    backend: &mut impl Backend,
    view: &View,
    root: &str,
    suffix: &str,
    original_guid: Guid,
    digest: &str,
) -> Result<Tree> {
    if tree_digest(view, root, suffix) != digest {
        return Err(refuse(
            "placement source ancestry changed before receipt publication",
        ));
    }
    let dataset = view
        .dataset(root)
        .ok_or_else(|| refuse("placement source disappeared"))?;
    let received = backend.received(root, KEYS)?;
    let altroot = view
        .pool(root.split('/').next().unwrap())
        .and_then(|p| p.altroot.as_deref());
    let mut members = BTreeMap::new();
    let boundary = view
        .snapshot(&format!("{root}@{suffix}"))
        .ok_or_else(|| refuse("placement source boundary disappeared"))?
        .point
        .identity
        .createtxg;
    for member in view.tree(root) {
        if member.identity.createtxg > boundary
            && view
                .snapshot(&format!("{}@{suffix}", member.name))
                .is_none()
        {
            // Members made after the boundary are not part of this copy.
            continue;
        }
        let mut properties: BTreeMap<_, _> = member
            .properties
            .iter()
            .map(|(key, p)| {
                (
                    key.clone(),
                    NativeProperty {
                        value: p.value.clone(),
                        source: p.source.clone(),
                    },
                )
            })
            .collect();
        if let Some(mountpoint) = properties.get_mut("mountpoint") {
            mountpoint.value = super::strip_altroot(&mountpoint.value, altroot);
        }
        let empty = BTreeMap::new();
        let placement = ReceivePlacement::capture(
            member.volume,
            &properties,
            received.get(&member.name).unwrap_or(&empty),
        )?;
        let managed = member
            .properties
            .iter()
            .filter(|(k, p)| super::MANAGED.contains(&k.as_str()) && (p.local() || p.received()))
            .map(|(k, p)| (k.clone(), p.value.clone()))
            .collect();
        let role = member
            .property(zfs_tools::engine::management::PAIR_PROPERTY)
            .filter(|p| p.local())
            .map(|p| zfs_tools::engine::management::PairRecord::parse(&p.value))
            .transpose()?
            .map(|record| record.role);
        members.insert(
            member.name[root.len()..].trim_start_matches('/').into(),
            Member {
                identity: member.identity.clone(),
                volume: member.volume,
                placement,
                managed,
                properties: manifest::capture(member),
                encryption: manifest::keys(view, root, member)?,
                role,
            },
        );
    }
    Ok(Tree {
        observed: Endpoint {
            name: root.into(),
            identity: dataset.identity.clone(),
        },
        original_guid,
        digest: digest.into(),
        members,
    })
}

pub(super) fn capture(backend: &mut impl Backend, state: &State, id: &str) -> Result<Receipt> {
    let view = backend.view()?;
    let suffix = state
        .snapshot
        .split_once('@')
        .ok_or_else(|| refuse("restore source boundary is malformed"))?
        .1;
    let source_tree = capture_tree(
        backend,
        &view,
        &state.source.name,
        suffix,
        state.source.identity.guid,
        state
            .source_digest
            .as_deref()
            .ok_or_else(|| refuse("restore source is not captured"))?,
    )?;
    let mut kept_trees = BTreeMap::new();
    for kept in &state.keep {
        let old = state
            .old_pool
            .as_ref()
            .map(|p| format!("{}/{}", p.name, kept.relative));
        // Placement is captured from A before it is erased, never rebuilt.
        let root = old
            .as_ref()
            .filter(|root| {
                view.dataset(root).is_some_and(|d| {
                    d.identity.guid == kept.guid
                        && Some(d.identity.pool_guid) == state.old_pool.as_ref().map(|p| p.guid)
                })
            })
            .ok_or_else(|| {
                refuse(format!(
                    "kept tree {} is no longer on A; its original placement cannot be captured",
                    kept.relative
                ))
            })?;
        let mut tree = capture_tree(
            backend,
            &view,
            root,
            &State::suffix(id),
            kept.guid,
            kept.digest
                .as_deref()
                .ok_or_else(|| refuse("kept source is not captured"))?,
        )?;
        let root = tree
            .members
            .get_mut("")
            .ok_or_else(|| refuse("kept receipt lacks its root"))?;
        root.placement.readonly.value = if kept.readonly { "on" } else { "off" }.into();
        if let (Some(saved), Some(value)) = (&mut root.placement.mountpoint, &kept.mountpoint) {
            saved.value = value.clone();
        }
        kept_trees.insert(kept.relative.clone(), tree);
    }
    let receipt = Receipt {
        restore_id: id.into(),
        source: state.source.clone(),
        source_tree,
        kept: kept_trees,
    };
    validate(&receipt, state, id)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::restore::fake::Fake;

    #[test]
    fn a_receipt_contains_only_members_sent_by_its_boundary() {
        let mut backend = Fake::world();
        let root = "bpool/ROOT/debian";
        backend.add(&format!("{root}/later"), &[]);
        let view = backend.view().unwrap();
        let digest = tree_digest(&view, root, "old");
        let guid = view.dataset(root).unwrap().identity.guid;
        // Exercise capture's stream-shape invariant independently of the
        // stricter planner, which refuses a selected boundary missing any
        // current member. Later members must never get invented receipts.
        let tree = capture_tree(&mut backend, &view, root, "old", guid, &digest).unwrap();
        assert_eq!(
            tree.members.keys().map(String::as_str).collect::<Vec<_>>(),
            ["", "var"]
        );
        assert_eq!(tree.digest, digest);
        assert!(backend.effects.is_empty());
    }

    #[test]
    fn new_receipts_omit_legacy_boot_markers_from_local_received_and_inherited_layers() {
        let root = "bpool/ROOT/debian";
        for source in ["local", "received", "inherited"] {
            let mut backend = Fake::world();
            match source {
                "local" => backend
                    .dataset_mut(root)
                    .local
                    .insert("zboot:be".into(), "arbitrary legacy value".into()),
                "received" => backend
                    .dataset_mut(root)
                    .received
                    .insert("zboot:be".into(), "0".into()),
                "inherited" => backend
                    .dataset_mut("bpool")
                    .local
                    .insert("zboot:be".into(), "1".into()),
                _ => unreachable!(),
            };
            let view = backend.view().unwrap();
            let digest = tree_digest(&view, root, "old");
            let guid = view.dataset(root).unwrap().identity.guid;
            let tree = capture_tree(&mut backend, &view, root, "old", guid, &digest).unwrap();
            assert!(
                tree.members
                    .values()
                    .all(|member| !member.managed.contains_key("zboot:be")),
                "{source}: {tree:?}"
            );
            assert!(backend.effects.is_empty());
        }
    }
}
