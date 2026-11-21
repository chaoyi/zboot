//! Write-once, checksummed typed payloads too large for an intent record, kept
//! as chunked user properties on one identity-bound dataset. An operation's
//! [intent record](crate::engine::intent) names each one by its
//! [`Attachment`]; that record is its only header. There are no generations
//! and no tombstone. Chunks are `zboot:attachment:ID:SLOT:NNNN`, so one
//! operation can keep more than one attachment. Callers:
//!
//! 1. commit an attachment by the intent write that names it;
//! 2. pass [`write`] and [`remove`] what their record names under the key, or
//!    `None`: only an unnamed key's chunks are discarded. A key the record
//!    already names is [`read`], never written again, and a name works only
//!    with the key it was written under;
//! 3. retire a named attachment only once no path reads it again, and clear
//!    the record only after that;
//! 4. keep the attachment in the pool that holds the record. A `zfs set`
//!    returns once its transaction group is on disk and a pool commits them
//!    in order, so the naming write makes chunks read back before it durable;
//! 5. keep one dataset per key: the same key on a dataset and a descendant
//!    shadow each other through inheritance.
use crate::engine::native::{self, NativeProperty};
use crate::engine::{Error, management::Endpoint};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) const MAX_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const CHUNK_BYTES: usize = 3000;
pub(crate) const MAX_CHUNKS: usize = MAX_BYTES.div_ceil(CHUNK_BYTES);
pub const PREFIX: &str = "zboot:attachment:";
const SLOT_BYTES: usize = 16;
/// `KEY=VALUE` argument bytes per `zfs set`. Linux accepts at least 128 KiB of
/// arguments under any stack limit, and that floor must also hold the program
/// path, the dataset name, the environment and the pointers to them all.
const BATCH_BYTES: usize = 96 * 1024;

/// What an intent record stores to name one attachment, bound to the key it
/// was written under. Only [`write`] and the decoding of a record make one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attachment {
    /// `ID:SLOT` of its [`Key`].
    key: String,
    endpoint: Endpoint,
    sha256: String,
    chunks: usize,
}
impl Attachment {
    /// The dataset that holds the chunks.
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    /// The largest name `key` can have on `endpoint`, to size a record before
    /// any effect. It names no stored chunks: it never reads, and no complete
    /// or partly retired set matches it.
    pub fn widest(key: &Key, endpoint: Endpoint) -> Self {
        Self {
            key: key.name().into(),
            endpoint,
            sha256: "f".repeat(64),
            chunks: MAX_CHUNKS,
        }
    }
    /// A well-formed name of `key`, refused before any effect otherwise.
    fn bound(&self, key: &Key) -> Result<(), Error> {
        if self.key != key.name() {
            return Err(refuse(format!(
                "the record names attachment {}, not {}; nothing changed",
                self.key,
                key.name()
            )));
        }
        self.validate()
    }
    fn validate(&self) -> Result<(), Error> {
        let (id, slot) = self
            .key
            .split_once(':')
            .ok_or_else(|| refuse("invalid attachment name"))?;
        Key::new(id, slot)?;
        validate_endpoint(&self.endpoint)?;
        if self.chunks == 0
            || self.chunks > MAX_CHUNKS
            || self.sha256.len() != 64
            || !is_hex(&self.sha256)
        {
            return Err(refuse("invalid attachment name"));
        }
        Ok(())
    }
}

/// One attachment of one operation: the id its intent record carries, a
/// canonical UUID v4 or restore's 16 lowercase hex digits, and a short
/// lowercase slot name, e.g. `plan` or `receipt`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Key(String);
impl Key {
    pub fn new(operation_id: &str, slot: &str) -> Result<Self, Error> {
        if validate_operation_id(operation_id).is_err()
            && !(operation_id.len() == 16 && is_hex(operation_id))
        {
            return Err(refuse(
                "attachment operation ID must be a canonical UUID v4 or 16 hex digits",
            ));
        }
        if slot.is_empty()
            || slot.len() > SLOT_BYTES
            || !slot.bytes().all(|b| b.is_ascii_lowercase())
        {
            return Err(refuse("attachment slot must be 1-16 lowercase letters"));
        }
        Ok(Self(format!("{PREFIX}{operation_id}:{slot}:")))
    }
    /// What every chunk property of this attachment starts with.
    pub fn prefix(&self) -> &str {
        &self.0
    }
    /// `ID:SLOT`, as a name records it.
    fn name(&self) -> &str {
        &self.0[PREFIX.len()..self.0.len() - 1]
    }
    fn chunk(&self, index: usize) -> String {
        format!("{}{index:04x}", self.0)
    }
    /// This attachment's properties on one dataset, each a valid chunk key.
    fn present<'a>(
        &self,
        properties: &'a BTreeMap<String, NativeProperty>,
    ) -> Result<BTreeMap<&'a str, &'a NativeProperty>, Error> {
        let mut present = BTreeMap::new();
        for (name, property) in properties.range(self.0.clone()..) {
            if !name.starts_with(&self.0) {
                break;
            }
            chunk_index(name)?;
            present.insert(name.as_str(), property);
        }
        Ok(present)
    }
    /// The chunks present on `endpoint`, every one local to it.
    fn own<'a>(
        &self,
        endpoint: &Endpoint,
        properties: &'a BTreeMap<String, NativeProperty>,
    ) -> Result<BTreeMap<&'a str, &'a NativeProperty>, Error> {
        let present = self.present(properties)?;
        if let Some((name, property)) = present.iter().find(|(_, p)| p.source != "local") {
            return Err(refuse(format!(
                "attachment property {name} on {} is {}, not local; each attachment key \
                 belongs to one dataset",
                endpoint.name, property.source
            )));
        }
        Ok(present)
    }
}

pub trait AttachmentBackend {
    /// Complete identity-bound native properties, preserving sources.
    fn properties(
        &mut self,
        endpoint: &Endpoint,
    ) -> Result<BTreeMap<String, NativeProperty>, Error>;
    /// One native write of all `values`, which may apply in part on error.
    fn set(&mut self, endpoint: &Endpoint, values: &[(String, String)]) -> Result<(), Error>;
    fn inherit(&mut self, endpoint: &Endpoint, property: &str) -> Result<(), Error>;
}

/// Native attachment properties on the bound endpoint incarnation. Callers
/// hold the writer lock; separate commands are not atomic.
#[derive(Default)]
pub struct NativeAttachment;
impl AttachmentBackend for NativeAttachment {
    fn properties(
        &mut self,
        endpoint: &Endpoint,
    ) -> Result<BTreeMap<String, NativeProperty>, Error> {
        bound_properties(endpoint)
    }
    fn set(&mut self, endpoint: &Endpoint, values: &[(String, String)]) -> Result<(), Error> {
        validate_set(values)?;
        bound_set(endpoint, values)
    }
    fn inherit(&mut self, endpoint: &Endpoint, property: &str) -> Result<(), Error> {
        chunk_index(property)?;
        bound_inherit(endpoint, property)
    }
}

/// Shared admission for attachment backends: only chunk properties, each a
/// nonempty encoded chunk. Semantic properties have their own primitives.
pub fn validate_set(values: &[(String, String)]) -> Result<(), Error> {
    if values.is_empty() {
        return Err(refuse("empty attachment property set"));
    }
    for (key, value) in values {
        chunk_index(key)?;
        if value.is_empty() || value.len() > CHUNK_BYTES * 2 {
            return Err(refuse("attachment chunk exceeds supported size"));
        }
    }
    Ok(())
}

/// The chunk index of a `zboot:attachment:ID:SLOT:NNNN` property.
fn chunk_index(key: &str) -> Result<usize, Error> {
    let parts: Vec<_> = key
        .strip_prefix(PREFIX)
        .ok_or_else(|| refuse("property outside attachment namespace"))?
        .split(':')
        .collect();
    let [id, slot, index] = parts.as_slice() else {
        return Err(refuse(format!("invalid attachment property: {key}")));
    };
    Key::new(id, slot)?;
    if index.len() != 4 || !is_hex(index) {
        return Err(refuse(format!("invalid attachment chunk property: {key}")));
    }
    let index = usize::from_str_radix(index, 16).expect("four hex digits");
    if index >= MAX_CHUNKS {
        return Err(refuse(format!(
            "attachment chunk outside supported range: {key}"
        )));
    }
    Ok(index)
}

/// The encoded chunks of `payload` exactly as [`write`] stores them, for a
/// byte-identical copy under another namespace such as restore's archive.
pub fn encode<T: Serialize>(payload: &T) -> Result<Vec<String>, Error> {
    Ok(canonical(payload)?.chunks(CHUNK_BYTES).map(hex).collect())
}

/// The typed payload of encoded `chunks`, in order, that `attachment` names.
pub fn decode<T: DeserializeOwned>(attachment: &Attachment, chunks: &[&str]) -> Result<T, Error> {
    attachment.validate()?;
    if chunks.len() != attachment.chunks {
        return Err(refuse(format!(
            "{} attachment chunks where its name has {}",
            chunks.len(),
            attachment.chunks
        )));
    }
    let bytes = join(chunks)?;
    if digest(&bytes) != attachment.sha256 {
        return Err(refuse("attachment checksum mismatch"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| refuse(format!("invalid typed attachment: {error}")))
}

/// Write `payload` as `key` on `endpoint` and return its name once read back.
/// `named` is what the record already names under `key`. A resume reads a
/// named key instead; with a name, this only confirms that the chunks there
/// are that name and this payload, and refuses otherwise without any effect. With none, chunks already there are
/// kept only if they are exactly this payload; any other leftovers, a write
/// the record never named, are removed first.
pub fn write<T: Serialize + DeserializeOwned + PartialEq>(
    backend: &mut impl AttachmentBackend,
    endpoint: &Endpoint,
    key: &Key,
    payload: &T,
    named: Option<&Attachment>,
) -> Result<Attachment, Error> {
    validate_endpoint(endpoint)?;
    let bytes = canonical(payload)?;
    let chunks: Vec<String> = bytes.chunks(CHUNK_BYTES).map(hex).collect();
    let attachment = Attachment {
        key: key.name().into(),
        endpoint: endpoint.clone(),
        sha256: digest(&bytes),
        chunks: chunks.len(),
    };
    if let Some(named) = named {
        named.bound(key)?;
        if *named != attachment {
            return Err(refuse(format!(
                "attachment {} on {} is already named by its record; read it rather than \
                 writing it again; nothing changed",
                key.name(),
                named.endpoint.name
            )));
        }
        verify(backend, key, &attachment, payload, &chunks)?;
        return Ok(attachment);
    }
    let wanted: Vec<_> = chunks
        .iter()
        .enumerate()
        .map(|(index, value)| (key.chunk(index), value.clone()))
        .collect();
    let before = backend.properties(endpoint)?;
    let present = key.own(endpoint, &before)?;
    let complete = present.len() == wanted.len()
        && wanted.iter().all(|(name, value)| {
            present
                .get(name.as_str())
                .is_some_and(|p| p.value == *value)
        });
    if !complete {
        remove(backend, endpoint, key, None)?;
        for batch in batches(&wanted) {
            if let Err(error) = backend.set(endpoint, batch) {
                // On error the kernel retries a multi-key set one key at a
                // time, so any part of the batch may have applied.
                let now = backend.properties(endpoint)?;
                if batch
                    .iter()
                    .any(|(name, value)| local(&now, name).ok() != Some(value.as_str()))
                {
                    return Err(error);
                }
            }
        }
    }
    verify(backend, key, &attachment, payload, &chunks)?;
    Ok(attachment)
}
/// The chunks read back are `payload`, and encode to the very same bytes.
fn verify<T: Serialize + DeserializeOwned + PartialEq>(
    backend: &mut impl AttachmentBackend,
    key: &Key,
    attachment: &Attachment,
    payload: &T,
    chunks: &[String],
) -> Result<(), Error> {
    let observed = read::<T>(backend, key, attachment)?;
    if observed != *payload || encode(&observed)? != chunks {
        return Err(refuse("attachment payload does not survive its encoding"));
    }
    Ok(())
}
/// Consecutive runs of `values` within [`BATCH_BYTES`] of arguments each.
fn batches(values: &[(String, String)]) -> Vec<&[(String, String)]> {
    let mut batches = Vec::new();
    let (mut start, mut bytes) = (0, 0);
    for (index, (key, value)) in values.iter().enumerate() {
        // `KEY=VALUE` and its terminating NUL.
        let argument = key.len() + value.len() + 2;
        if index > start && bytes + argument > BATCH_BYTES {
            batches.push(&values[start..index]);
            (start, bytes) = (index, 0);
        }
        bytes += argument;
    }
    if start < values.len() {
        batches.push(&values[start..]);
    }
    batches
}

/// The payload `attachment` names: on its bound endpoint, exactly chunks
/// `0..chunks`, each local, hashing to its digest and decoding as `T`.
pub fn read<T: DeserializeOwned>(
    backend: &mut impl AttachmentBackend,
    key: &Key,
    attachment: &Attachment,
) -> Result<T, Error> {
    attachment.bound(key)?;
    let properties = backend.properties(&attachment.endpoint)?;
    let present = key.present(&properties)?;
    let names: Vec<_> = (0..attachment.chunks).map(|i| key.chunk(i)).collect();
    if let Some(missing) = names.iter().find(|n| !present.contains_key(n.as_str())) {
        return Err(refuse(format!(
            "attachment on {} lacks {missing}, one of the {} chunks its record names",
            attachment.endpoint.name, attachment.chunks
        )));
    }
    if present.len() != names.len() {
        return Err(refuse(format!(
            "attachment on {} has {} chunks where its record names {}",
            attachment.endpoint.name,
            present.len(),
            attachment.chunks
        )));
    }
    let chunks = names
        .iter()
        .map(|name| local(&properties, name))
        .collect::<Result<Vec<_>, _>>()?;
    decode(attachment, &chunks)
}

/// Remove every chunk of `key` on `endpoint`, in index order, stopping at the
/// first that is still there after its inherit, so whatever a failure or cut
/// leaves is the last chunks and a retry finishes. `named` is what the record
/// names under `key`: `None` discards a write the record never named. A name
/// retires that attachment, refusing before any effect a name of another key
/// or endpoint, a chunk beyond it, a complete set that differs from it, or a
/// partial set that is not its last chunks. A chunk this dataset does not own
/// locally refuses before any effect.
pub fn remove(
    backend: &mut impl AttachmentBackend,
    endpoint: &Endpoint,
    key: &Key,
    named: Option<&Attachment>,
) -> Result<(), Error> {
    validate_endpoint(endpoint)?;
    if let Some(named) = named {
        named.bound(key)?;
        if named.endpoint != *endpoint {
            return Err(refuse(format!(
                "the attachment under {} is named on {}, not {}",
                key.0, named.endpoint.name, endpoint.name
            )));
        }
    }
    let before = backend.properties(endpoint)?;
    let present = key.own(endpoint, &before)?;
    if let Some(named) = named {
        for name in present.keys() {
            if chunk_index(name)? >= named.chunks {
                return Err(refuse(format!(
                    "{name} on {} lies beyond the attachment its record names; nothing removed",
                    endpoint.name
                )));
            }
        }
        if present.len() == named.chunks {
            let values: Vec<_> = present.values().map(|p| p.value.as_str()).collect();
            if !join(&values).is_ok_and(|bytes| digest(&bytes) == named.sha256) {
                return Err(refuse(format!(
                    "the attachment under {} on {} differs from the one its record names; \
                     nothing removed",
                    key.0, endpoint.name
                )));
            }
        } else if let Some(first) = present.keys().next()
            && chunk_index(first)? != named.chunks - present.len()
        {
            return Err(refuse(format!(
                "the attachment under {} on {} keeps chunks other than the last {} of the \
                 {} its record names; nothing removed",
                key.0,
                endpoint.name,
                present.len(),
                named.chunks
            )));
        }
    }
    for name in present.keys() {
        let result = backend.inherit(endpoint, name);
        if backend.properties(endpoint)?.contains_key(*name) {
            return Err(result.err().unwrap_or_else(|| {
                refuse(format!(
                    "inherit of {name} on {} did not apply; nothing more was done",
                    endpoint.name
                ))
            }));
        }
    }
    if let Some(name) = key.present(&backend.properties(endpoint)?)?.keys().next() {
        return Err(refuse(format!(
            "attachment property remains on {} after removal: {name}",
            endpoint.name
        )));
    }
    Ok(())
}

/// Bind `endpoint`'s exact incarnation; a replaced or renamed dataset refuses.
pub(crate) fn bind(endpoint: &Endpoint) -> Result<(), Error> {
    validate_endpoint(endpoint)?;
    let inspection = native::inspect_with(
        &crate::engine::InspectRequest::new(vec![endpoint.name.clone()], false)?,
        native::run,
    )?;
    let dataset = inspection
        .datasets
        .iter()
        .find(|d| d.name == endpoint.name)
        .ok_or_else(|| refuse(format!("{} disappeared", endpoint.name)))?;
    if dataset.identity != endpoint.identity {
        return Err(refuse(format!("{} incarnation changed", endpoint.name)));
    }
    Ok(())
}
/// Every native property of the bound endpoint, with its source.
pub(crate) fn bound_properties(
    endpoint: &Endpoint,
) -> Result<BTreeMap<String, NativeProperty>, Error> {
    bind(endpoint)?;
    let properties =
        native::dataset_properties_with(std::slice::from_ref(&endpoint.name), native::run)?
            .remove(&endpoint.name)
            .ok_or_else(|| refuse(format!("{} property inventory missing", endpoint.name)))?;
    for (key, value) in [
        ("guid", endpoint.identity.guid.get()),
        ("createtxg", endpoint.identity.createtxg.get()),
        ("objsetid", endpoint.identity.objsetid.get()),
    ] {
        if properties.get(key).map(|p| p.value.as_str()) != Some(value.to_string().as_str()) {
            return Err(refuse(format!(
                "{} changed during property query",
                endpoint.name
            )));
        }
    }
    bind(endpoint)?;
    Ok(properties)
}
/// One `zfs set` of already admitted `values`, skipped when all are local.
fn bound_set(endpoint: &Endpoint, values: &[(String, String)]) -> Result<(), Error> {
    let before = bound_properties(endpoint)?;
    if values.iter().all(|(key, value)| {
        before
            .get(key)
            .is_some_and(|property| property.source == "local" && property.value == *value)
    }) {
        return Ok(());
    }
    let mut args = vec!["set".into()];
    args.extend(values.iter().map(|(key, value)| format!("{key}={value}")));
    args.push(endpoint.name.clone());
    native::run_mutating("zfs", &args)?;
    bind(endpoint)
}
/// `zfs inherit` of an already admitted property, skipped when not local.
fn bound_inherit(endpoint: &Endpoint, property: &str) -> Result<(), Error> {
    if bound_properties(endpoint)?
        .get(property)
        .is_none_or(|value| value.source != "local")
    {
        return Ok(());
    }
    native::run_mutating(
        "zfs",
        &["inherit".into(), property.into(), endpoint.name.clone()],
    )?;
    bind(endpoint)
}

fn validate_endpoint(endpoint: &Endpoint) -> Result<(), Error> {
    crate::engine::validate_dataset_name(&endpoint.name)?;
    if !endpoint.identity.is_complete() {
        return Err(refuse("record endpoint identity is incomplete"));
    }
    Ok(())
}
fn validate_operation_id(operation_id: &str) -> Result<(), Error> {
    if !crate::engine::is_canonical_uuid_v4(operation_id) {
        return Err(refuse("operation ID must be a canonical UUID v4"));
    }
    Ok(())
}
fn is_hex(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(value: &str) -> Result<Vec<u8>, Error> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || value.len() > CHUNK_BYTES * 2
        || !is_hex(value)
    {
        return Err(refuse("invalid chunk encoding or size"));
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| {
            u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16)
                .map_err(|_| refuse("invalid chunk byte"))
        })
        .collect()
}
/// Concatenate encoded chunks; every chunk but the last is full.
pub(crate) fn join(chunks: &[&str]) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    for (index, value) in chunks.iter().enumerate() {
        let chunk = unhex(value)?;
        if index + 1 < chunks.len() && chunk.len() != CHUNK_BYTES {
            return Err(refuse("noncanonical chunk boundary"));
        }
        bytes.extend(chunk);
        if bytes.len() > MAX_BYTES {
            return Err(refuse("chunked record exceeds supported size"));
        }
    }
    Ok(bytes)
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
/// serde_json's ordered object representation makes HashMap field order
/// irrelevant to the checksum.
pub(crate) fn canonical<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let value = serde_json::to_value(value).map_err(|error| refuse(error.to_string()))?;
    let bytes = serde_json::to_vec(&value).map_err(|error| refuse(error.to_string()))?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(refuse("chunked record size exceeds supported boundary"));
    }
    Ok(bytes)
}
/// A property's value, which this dataset must own locally.
pub(crate) fn local<'a>(
    properties: &'a BTreeMap<String, NativeProperty>,
    key: &str,
) -> Result<&'a str, Error> {
    let property = properties
        .get(key)
        .ok_or_else(|| refuse(format!("property missing: {key}")))?;
    if property.source != "local" {
        return Err(refuse(format!("property is not locally owned: {key}")));
    }
    Ok(&property.value)
}
fn refuse(detail: impl Into<String>) -> Error {
    Error::Inconsistent(detail.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{DatasetIdentity, Guid, ObjsetId, Txg};
    const OP: &str = "12345678-1234-4234-9234-1234567890ab";

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Plan {
        source: String,
        members: Vec<String>,
    }
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Other {
        source: String,
    }
    /// Equal by `kept` alone, and `dropped` never decodes: a payload whose
    /// read-back compares equal but no longer encodes to the stored bytes.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct Loose {
        kept: String,
        #[serde(skip_deserializing)]
        dropped: u32,
    }
    impl PartialEq for Loose {
        fn eq(&self, other: &Self) -> bool {
            self.kept == other.kept
        }
    }
    fn endpoint() -> Endpoint {
        Endpoint {
            name: "tank/archive".into(),
            identity: DatasetIdentity {
                pool_guid: Guid::new(1),
                guid: Guid::new(2),
                createtxg: Txg::new(3),
                objsetid: ObjsetId::new(4),
            },
        }
    }
    fn key(slot: &str) -> Key {
        Key::new(OP, slot).unwrap()
    }
    /// Three chunks, the last partial.
    fn plan(tag: &str) -> Plan {
        Plan {
            source: format!("tank/archive {tag}"),
            members: vec!["x".repeat(CHUNK_BYTES); 2],
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Effect {
        Set(usize),
        Inherit,
    }
    /// One dataset whose writes are durable on return, as `zfs set` is.
    #[derive(Clone)]
    struct Fake {
        endpoint: Endpoint,
        properties: BTreeMap<String, NativeProperty>,
        effects: Vec<Effect>,
        /// Stop the process before (`false`) or after (`true`) this effect.
        cut: Option<(usize, bool)>,
        /// Apply this effect but lose its reply.
        lost_reply: Option<usize>,
        /// This set applies only so many of its keys, then fails.
        partial: Option<(usize, usize)>,
        /// After a partial set, the next observation fails too.
        partial_stops: bool,
        /// Report success for this effect without applying it.
        ignored: Option<usize>,
        stopped: bool,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                endpoint: endpoint(),
                properties: BTreeMap::from([(
                    "zboot:mirror".into(),
                    NativeProperty {
                        value: "unrelated".into(),
                        source: "local".into(),
                    },
                )]),
                effects: vec![],
                cut: None,
                lost_reply: None,
                partial: None,
                partial_stops: false,
                ignored: None,
                stopped: false,
            }
        }
        fn failure() -> Error {
            refuse("injected native interruption")
        }
        fn bound(&self, endpoint: &Endpoint) -> Result<(), Error> {
            if self.stopped {
                return Err(Self::failure());
            }
            if *endpoint != self.endpoint {
                return Err(refuse("fake endpoint incarnation changed"));
            }
            Ok(())
        }
        /// Record an effect; whether it applies.
        fn before(&mut self, endpoint: &Endpoint, effect: Effect) -> Result<bool, Error> {
            self.bound(endpoint)?;
            self.effects.push(effect);
            if self.cut == Some((self.effects.len(), false)) {
                self.stopped = true;
                return Err(Self::failure());
            }
            Ok(self.ignored != Some(self.effects.len()))
        }
        fn after(&mut self) -> Result<(), Error> {
            let n = self.effects.len();
            if self.cut == Some((n, true)) {
                self.stopped = true;
                return Err(Self::failure());
            }
            if self.lost_reply == Some(n) {
                return Err(Self::failure());
            }
            Ok(())
        }
        /// A new process after a cut: the same durable properties.
        fn restart(&mut self) {
            self.effects.clear();
            self.cut = None;
            self.lost_reply = None;
            self.partial = None;
            self.partial_stops = false;
            self.ignored = None;
            self.stopped = false;
        }
        fn chunks(&self, key: &Key) -> Vec<String> {
            self.properties
                .keys()
                .filter(|k| k.starts_with(&key.0))
                .cloned()
                .collect()
        }
        fn source(&mut self, key: &Key, source: &str) {
            for (_, property) in self
                .properties
                .iter_mut()
                .filter(|(k, _)| k.starts_with(&key.0))
            {
                property.source = source.into();
            }
        }
    }
    impl AttachmentBackend for Fake {
        fn properties(
            &mut self,
            endpoint: &Endpoint,
        ) -> Result<BTreeMap<String, NativeProperty>, Error> {
            self.bound(endpoint)?;
            Ok(self.properties.clone())
        }
        fn set(&mut self, endpoint: &Endpoint, values: &[(String, String)]) -> Result<(), Error> {
            validate_set(values).unwrap();
            assert!(
                values
                    .iter()
                    .map(|(k, v)| k.len() + v.len() + 2)
                    .sum::<usize>()
                    <= BATCH_BYTES,
                "one zfs set exceeds its argument budget"
            );
            let applies = self.before(endpoint, Effect::Set(values.len()))?;
            let applied = match self.partial {
                Some((n, applied)) if n == self.effects.len() => applied,
                _ if applies => values.len(),
                _ => 0,
            };
            for (key, value) in &values[..applied] {
                let property = NativeProperty {
                    value: value.clone(),
                    source: "local".into(),
                };
                self.properties.insert(key.clone(), property);
            }
            if applies && applied < values.len() {
                self.stopped = self.partial_stops;
                return Err(Self::failure());
            }
            self.after()
        }
        fn inherit(&mut self, endpoint: &Endpoint, property: &str) -> Result<(), Error> {
            chunk_index(property).unwrap();
            if self.before(endpoint, Effect::Inherit)? {
                self.properties.remove(property);
            }
            self.after()
        }
    }

    #[test]
    fn a_payload_round_trips_and_an_identical_write_is_no_effect() {
        let mut fake = Fake::new();
        let attachment = write(&mut fake, &endpoint(), &key("plan"), &plan("a"), None).unwrap();
        assert_eq!(attachment.endpoint(), &endpoint());
        assert_eq!(attachment.chunks, 3);
        assert_eq!(fake.effects, vec![Effect::Set(3)], "one native write");
        assert_eq!(
            fake.chunks(&key("plan")),
            [0, 1, 2].map(|i| format!("zboot:attachment:{OP}:plan:000{i}"))
        );
        assert_eq!(
            read::<Plan>(&mut fake, &key("plan"), &attachment).unwrap(),
            plan("a")
        );
        fake.effects.clear();
        for named in [None, Some(&attachment)] {
            let again = write(&mut fake, &endpoint(), &key("plan"), &plan("a"), named);
            assert_eq!(again.unwrap(), attachment);
        }
        assert!(fake.effects.is_empty());
        // The name is plain data a record can carry.
        let json = serde_json::to_string(&attachment).unwrap();
        assert_eq!(
            serde_json::from_str::<Attachment>(&json).unwrap(),
            attachment
        );
        assert!(fake.properties.contains_key("zboot:mirror"));
    }

    #[test]
    fn whole_chunks_and_a_payload_that_does_not_survive_its_encoding() {
        // A payload of exactly two whole chunks: `"` + 5998 bytes + `"`.
        let whole = "w".repeat(CHUNK_BYTES * 2 - 2);
        let mut fake = Fake::new();
        let attachment = write(&mut fake, &endpoint(), &key("plan"), &whole, None).unwrap();
        assert_eq!(attachment.chunks, 2);
        let values = fake.chunks(&key("plan"));
        assert!(
            values
                .iter()
                .all(|k| fake.properties[k].value.len() == CHUNK_BYTES * 2)
        );
        assert_eq!(
            read::<String>(&mut fake, &key("plan"), &attachment).unwrap(),
            whole
        );
        // Compares equal on read-back but no longer encodes to the same bytes.
        let loose = Loose {
            kept: "k".into(),
            dropped: 7,
        };
        let mut fake = Fake::new();
        let error = write(&mut fake, &endpoint(), &key("plan"), &loose, None).unwrap_err();
        assert!(
            error.to_string().contains("does not survive its encoding"),
            "{error}"
        );
        // A retry finds the same unnamed chunks, writes nothing and refuses
        // again; only a discard removes them.
        fake.effects.clear();
        assert!(write(&mut fake, &endpoint(), &key("plan"), &loose, None).is_err());
        assert!(fake.effects.is_empty());
        remove(&mut fake, &endpoint(), &key("plan"), None).unwrap();
        assert!(fake.chunks(&key("plan")).is_empty());
    }

    #[test]
    fn one_operation_keeps_separate_slots_and_large_payloads_write_in_batches() {
        let mut fake = Fake::new();
        let big = Plan {
            source: "big".into(),
            members: vec!["y".repeat(CHUNK_BYTES); 40],
        };
        let a = write(&mut fake, &endpoint(), &key("plan"), &big, None).unwrap();
        // Each chunk argument is 6065 bytes, so 16 fit in one 96 KiB set.
        let n = a.chunks;
        assert!(n > 32 && n <= 48, "{n}");
        assert_eq!(
            fake.effects,
            vec![Effect::Set(16), Effect::Set(16), Effect::Set(n - 32)]
        );
        assert_eq!(read::<Plan>(&mut fake, &key("plan"), &a).unwrap(), big);
        // A slot that is a prefix of another is still its own namespace.
        let pai = write(&mut fake, &endpoint(), &key("pai"), &plan("pai"), None).unwrap();
        let pair = write(&mut fake, &endpoint(), &key("pair"), &plan("pair"), None).unwrap();
        remove(&mut fake, &endpoint(), &key("plan"), Some(&a)).unwrap();
        assert!(fake.chunks(&key("plan")).is_empty());
        remove(&mut fake, &endpoint(), &key("pai"), Some(&pai)).unwrap();
        assert!(fake.chunks(&key("pai")).is_empty());
        assert_eq!(fake.chunks(&key("pair")).len(), 3);
        assert_eq!(
            read::<Plan>(&mut fake, &key("pair"), &pair).unwrap(),
            plan("pair")
        );
        let pai = write(&mut fake, &endpoint(), &key("pai"), &plan("pai"), None).unwrap();
        remove(&mut fake, &endpoint(), &key("pair"), None).unwrap();
        assert_eq!(
            read::<Plan>(&mut fake, &key("pai"), &pai).unwrap(),
            plan("pai")
        );
    }

    #[test]
    fn a_read_refuses_another_incarnation_and_any_chunk_set_but_the_named_one() {
        let mut base = Fake::new();
        let attachment = write(&mut base, &endpoint(), &key("plan"), &plan("a"), None).unwrap();
        let k = key("plan");
        let first = k.chunk(0);
        let refused = |fake: &mut Fake, attachment: &Attachment| {
            read::<Plan>(fake, &k, attachment).unwrap_err().to_string()
        };

        let mut fake = base.clone();
        fake.endpoint.identity.objsetid = ObjsetId::new(999);
        assert!(refused(&mut fake, &attachment).contains("incarnation changed"));
        let mut renamed = attachment.clone();
        renamed.endpoint.name = "tank/other".into();
        assert!(refused(&mut base.clone(), &renamed).contains("incarnation changed"));

        let mut fake = base.clone();
        fake.properties.remove(&k.chunk(1));
        let error = refused(&mut fake, &attachment);
        assert!(error.contains("lacks zboot:attachment:"), "{error}");
        assert!(error.contains(":plan:0001, one of the 3 chunks"), "{error}");
        // The same count under other indices names what is missing.
        let extra = fake.properties[&first].clone();
        fake.properties.insert(k.chunk(3), extra.clone());
        assert!(refused(&mut fake, &attachment).contains(":plan:0001, one of the 3"));

        let mut fake = base.clone();
        fake.properties.insert(k.chunk(3), extra);
        assert!(refused(&mut fake, &attachment).contains("has 4 chunks where its record names 3"));

        let mut fake = base.clone();
        fake.properties.get_mut(&first).unwrap().source = "inherited from tank".into();
        assert!(refused(&mut fake, &attachment).contains("not locally owned"));
        let mut fake = base.clone();
        fake.properties.get_mut(&first).unwrap().source = "received".into();
        assert!(refused(&mut fake, &attachment).contains("not locally owned"));

        let mut fake = base.clone();
        fake.properties
            .get_mut(&first)
            .unwrap()
            .value
            .replace_range(0..2, "00");
        assert!(refused(&mut fake, &attachment).contains("checksum mismatch"));
        let mut other = attachment.clone();
        other.sha256 = digest(b"other");
        assert!(refused(&mut base.clone(), &other).contains("checksum mismatch"));
        let mut fake = base.clone();
        fake.properties.get_mut(&first).unwrap().value = "A0".into();
        assert!(refused(&mut fake, &attachment).contains("invalid chunk encoding"));
        let mut fake = base.clone();
        fake.properties.insert(
            format!("{}zz", k.0),
            NativeProperty {
                value: "00".into(),
                source: "local".into(),
            },
        );
        assert!(refused(&mut fake, &attachment).contains("invalid attachment chunk property"));

        for bad in [0, MAX_CHUNKS + 1] {
            let mut named = attachment.clone();
            named.chunks = bad;
            assert!(refused(&mut base.clone(), &named).contains("invalid attachment name"));
        }
        let error = read::<Other>(&mut base.clone(), &k, &attachment)
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid typed attachment"), "{error}");
        assert!(
            read::<Plan>(&mut base.clone(), &key("pair"), &attachment).is_err(),
            "another slot is not this attachment"
        );
        assert!(decode::<Plan>(&attachment, &[]).is_err());
    }

    #[test]
    fn partial_ignored_and_cut_writes_are_rewritten_exactly() {
        let payload = plan("a");
        let k = key("plan");
        // A failed set whose kernel retry applied only some keys.
        for applied in 0..3 {
            let mut fake = Fake::new();
            fake.partial = Some((1, applied));
            assert!(write(&mut fake, &endpoint(), &k, &payload, None).is_err());
            assert_eq!(fake.chunks(&k).len(), applied);
            fake.restart();
            let attachment = write(&mut fake, &endpoint(), &k, &payload, None).unwrap();
            assert_eq!(read::<Plan>(&mut fake, &k, &attachment).unwrap(), payload);
            assert_eq!(fake.chunks(&k).len(), 3);
        }
        // The same in a later batch, and with the read-back failing too.
        let big = Plan {
            source: "big".into(),
            members: vec!["y".repeat(CHUNK_BYTES); 20],
        };
        for stops in [false, true] {
            let mut fake = Fake::new();
            fake.partial = Some((2, 3));
            fake.partial_stops = stops;
            assert!(write(&mut fake, &endpoint(), &k, &big, None).is_err());
            assert_eq!(fake.effects, vec![Effect::Set(16), Effect::Set(5)]);
            assert_eq!(fake.chunks(&k).len(), 19);
            fake.restart();
            let attachment = write(&mut fake, &endpoint(), &k, &big, None).unwrap();
            assert_eq!(read::<Plan>(&mut fake, &k, &attachment).unwrap(), big);
        }
        // A set that reports success without applying is caught on read-back.
        let mut fake = Fake::new();
        fake.ignored = Some(1);
        let error = write(&mut fake, &endpoint(), &k, &payload, None).unwrap_err();
        assert!(error.to_string().contains("lacks"), "{error}");
        fake.restart();
        write(&mut fake, &endpoint(), &k, &payload, None).unwrap();
        // Different leftovers, from an earlier unnamed write, never survive.
        let mut base = Fake::new();
        write(&mut base, &endpoint(), &k, &plan("old"), None).unwrap();
        base.properties
            .insert(k.chunk(7), base.properties[&k.chunk(0)].clone());
        base.restart();
        let mut normal = base.clone();
        write(&mut normal, &endpoint(), &k, &payload, None).unwrap();
        assert_eq!(
            normal.effects,
            vec![
                Effect::Inherit,
                Effect::Inherit,
                Effect::Inherit,
                Effect::Inherit,
                Effect::Set(3)
            ]
        );
        for cut in 1..=normal.effects.len() {
            for after in [false, true] {
                let mut fake = base.clone();
                fake.cut = Some((cut, after));
                assert!(write(&mut fake, &endpoint(), &k, &payload, None).is_err());
                fake.restart();
                let attachment = write(&mut fake, &endpoint(), &k, &payload, None).unwrap();
                assert_eq!(read::<Plan>(&mut fake, &k, &attachment).unwrap(), payload);
                assert_eq!(
                    fake.chunks(&k),
                    normal.chunks(&k),
                    "cut {cut} after={after}"
                );
            }
        }
        // A lost reply that applied is success; the read-back decides.
        for lost in 1..=normal.effects.len() {
            let mut fake = base.clone();
            fake.lost_reply = Some(lost);
            let attachment = write(&mut fake, &endpoint(), &k, &payload, None).unwrap();
            assert_eq!(read::<Plan>(&mut fake, &k, &attachment).unwrap(), payload);
        }
    }

    #[test]
    fn discard_and_removal_verify_every_chunk_is_gone() {
        let k = key("plan");
        let mut base = Fake::new();
        let attachment = write(&mut base, &endpoint(), &k, &plan("a"), None).unwrap();
        base.restart();
        // An unnamed, partial write is discarded.
        let mut partial = base.clone();
        partial.properties.remove(&k.chunk(2));
        remove(&mut partial, &endpoint(), &k, None).unwrap();
        assert!(partial.chunks(&k).is_empty());
        assert!(partial.properties.contains_key("zboot:mirror"));
        // A named attachment's retirement survives every cut and lost reply.
        let mut normal = base.clone();
        remove(&mut normal, &endpoint(), &k, Some(&attachment)).unwrap();
        assert_eq!(normal.effects, vec![Effect::Inherit; 3]);
        for cut in 1..=3 {
            for after in [false, true] {
                let mut fake = base.clone();
                fake.cut = Some((cut, after));
                assert!(remove(&mut fake, &endpoint(), &k, Some(&attachment)).is_err());
                fake.restart();
                remove(&mut fake, &endpoint(), &k, Some(&attachment)).unwrap();
                assert!(fake.chunks(&k).is_empty());
            }
            let mut fake = base.clone();
            fake.lost_reply = Some(cut);
            remove(&mut fake, &endpoint(), &k, Some(&attachment)).unwrap();
            assert!(fake.chunks(&k).is_empty());
        }
        // An inherit that reports success without effect stops the removal
        // there, so what is left is the last chunks and a retry finishes,
        // with or without the name.
        for named in [None, Some(&attachment)] {
            for ignored in 1..=3 {
                let mut fake = base.clone();
                fake.ignored = Some(ignored);
                let error = remove(&mut fake, &endpoint(), &k, named)
                    .unwrap_err()
                    .to_string();
                assert!(
                    error.contains("did not apply; nothing more was done"),
                    "{error}"
                );
                assert_eq!(fake.effects, vec![Effect::Inherit; ignored]);
                let left: Vec<_> = (ignored - 1..3).map(|i| k.chunk(i)).collect();
                assert_eq!(fake.chunks(&k), left);
                fake.restart();
                remove(&mut fake, &endpoint(), &k, Some(&attachment)).unwrap();
                assert!(fake.chunks(&k).is_empty());
            }
        }
        // A failed inherit that did not apply stops there too.
        let mut fake = base.clone();
        fake.ignored = Some(2);
        fake.lost_reply = Some(2);
        assert!(remove(&mut fake, &endpoint(), &k, None).is_err());
        assert_eq!(fake.chunks(&k), vec![k.chunk(1), k.chunk(2)]);
        fake.restart();
        remove(&mut fake, &endpoint(), &k, Some(&attachment)).unwrap();
        // Chunks this dataset does not own refuse before any effect.
        for source in ["inherited from tank", "received"] {
            let mut fake = base.clone();
            fake.properties.get_mut(&k.chunk(1)).unwrap().source = source.into();
            for named in [None, Some(&attachment)] {
                let error = remove(&mut fake, &endpoint(), &k, named).unwrap_err();
                assert!(error.to_string().contains("not local"), "{error}");
            }
            assert!(write(&mut fake, &endpoint(), &k, &plan("a"), None).is_err());
            assert!(fake.effects.is_empty());
        }
        // Removing nothing, or from another incarnation, changes nothing.
        let mut fake = Fake::new();
        remove(&mut fake, &endpoint(), &k, None).unwrap();
        remove(&mut fake, &endpoint(), &k, Some(&attachment)).unwrap();
        let mut fake = base.clone();
        fake.endpoint.identity.guid = Guid::new(999);
        assert!(remove(&mut fake, &endpoint(), &k, None).is_err());
        assert!(fake.effects.is_empty());
        assert_eq!(read::<Plan>(&mut base, &k, &attachment).unwrap(), plan("a"));
    }

    #[test]
    fn a_named_attachment_is_never_rewritten_or_removed_as_another() {
        let k = key("plan");
        let mut base = Fake::new();
        let named = write(&mut base, &endpoint(), &k, &plan("a"), None).unwrap();
        base.restart();
        // A write under a name only confirms it; it never discards.
        let mut fake = base.clone();
        let error = write(&mut fake, &endpoint(), &k, &plan("b"), Some(&named)).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("already named by its record; read it"),
            "{error}"
        );
        fake.properties.remove(&k.chunk(1));
        let error = write(&mut fake, &endpoint(), &k, &plan("a"), Some(&named)).unwrap_err();
        assert!(error.to_string().contains("lacks"), "{error}");
        let mut elsewhere = endpoint();
        elsewhere.name = "tank/other".into();
        assert!(write(&mut fake, &elsewhere, &k, &plan("a"), Some(&named)).is_err());
        assert!(fake.effects.is_empty());
        assert_eq!(fake.chunks(&k).len(), 2);
        // Retiring a name refuses chunks beyond it or a complete other set.
        let mut fake = base.clone();
        let extra = fake.properties[&k.chunk(0)].clone();
        fake.properties.insert(k.chunk(3), extra);
        let error = remove(&mut fake, &endpoint(), &k, Some(&named)).unwrap_err();
        assert!(error.to_string().contains("lies beyond"), "{error}");
        let mut fake = base.clone();
        write(&mut fake, &endpoint(), &k, &plan("b"), None).unwrap();
        fake.effects.clear();
        let error = remove(&mut fake, &endpoint(), &k, Some(&named)).unwrap_err();
        assert!(
            error.to_string().contains("differs from the one"),
            "{error}"
        );
        let mut fake = base.clone();
        fake.properties.get_mut(&k.chunk(2)).unwrap().value = "zz".into();
        assert!(remove(&mut fake, &endpoint(), &k, Some(&named)).is_err());
        assert!(fake.effects.is_empty());
        let mut fake = base.clone();
        assert!(remove(&mut fake, &elsewhere, &k, Some(&named)).is_err());
        assert!(fake.effects.is_empty());
        let mut fake = base.clone();
        let mut bad = named.clone();
        bad.chunks = 0;
        assert!(remove(&mut fake, &endpoint(), &k, Some(&bad)).is_err());
        assert!(fake.effects.is_empty());
        // A retirement cut part way is finished by the same name.
        let mut fake = base.clone();
        fake.properties.remove(&k.chunk(0));
        remove(&mut fake, &endpoint(), &k, Some(&named)).unwrap();
        assert!(fake.chunks(&k).is_empty());
    }

    #[test]
    fn a_name_binds_its_key_and_a_retirement_keeps_only_a_suffix() {
        const OTHER: &str = "abcdef01-2345-4678-9abc-def012345678";
        let (plan_key, pair_key) = (key("plan"), key("pair"));
        let other = Key::new(OTHER, "plan").unwrap();
        let mut base = Fake::new();
        let big = Plan {
            source: "big".into(),
            members: vec!["y".repeat(CHUNK_BYTES); 12],
        };
        let named = write(&mut base, &endpoint(), &plan_key, &big, None).unwrap();
        let pair = write(&mut base, &endpoint(), &pair_key, &plan("pair"), None).unwrap();
        write(&mut base, &endpoint(), &other, &plan("other"), None).unwrap();
        base.restart();
        let json = serde_json::to_string(&named).unwrap();
        assert!(
            json.starts_with(&format!(r#"{{"key":"{OP}:plan","#)),
            "{json}"
        );
        // Another slot, or another operation's key on the same dataset, never
        // reads, confirms or retires under this name.
        for wrong in [&pair_key, &other] {
            let mut fake = base.clone();
            let error = remove(&mut fake, &endpoint(), wrong, Some(&named)).unwrap_err();
            assert!(
                error.to_string().contains("the record names attachment"),
                "{error}"
            );
            assert!(read::<Plan>(&mut fake, wrong, &named).is_err());
            assert!(write(&mut fake, &endpoint(), wrong, &big, Some(&named)).is_err());
            assert!(fake.effects.is_empty());
            assert_eq!(fake.chunks(wrong).len(), 3);
        }
        assert_eq!(
            read::<Plan>(&mut base, &pair_key, &pair).unwrap(),
            plan("pair")
        );
        // A cut retirement keeps the last chunks; any other partial set refuses.
        let n = named.chunks;
        for gone in [vec![n - 1], vec![0, n - 1], vec![1], (1..n).collect()] {
            let mut fake = base.clone();
            for index in &gone {
                fake.properties.remove(&plan_key.chunk(*index));
            }
            let error = remove(&mut fake, &endpoint(), &plan_key, Some(&named)).unwrap_err();
            assert!(
                error.to_string().contains("other than the last"),
                "{gone:?}: {error}"
            );
            assert!(fake.effects.is_empty());
        }
        for kept in [1, n - 1] {
            let mut fake = base.clone();
            for index in 0..n - kept {
                fake.properties.remove(&plan_key.chunk(index));
            }
            remove(&mut fake, &endpoint(), &plan_key, Some(&named)).unwrap();
            assert!(fake.chunks(&plan_key).is_empty());
            assert_eq!(fake.chunks(&pair_key).len(), 3);
        }
        // The widest name sizes a record but matches no stored set.
        let widest = Attachment::widest(&plan_key, endpoint());
        assert!(serde_json::to_string(&widest).unwrap().len() > json.len());
        let mut fake = base.clone();
        assert!(read::<Plan>(&mut fake, &plan_key, &widest).is_err());
        assert!(remove(&mut fake, &endpoint(), &plan_key, Some(&widest)).is_err());
        assert!(write(&mut fake, &endpoint(), &plan_key, &big, Some(&widest)).is_err());
        assert!(fake.effects.is_empty());
        let mut bad = named.clone();
        bad.key = "plan".into();
        assert!(read::<Plan>(&mut fake, &plan_key, &bad).is_err());
    }

    #[test]
    fn an_ancestor_holding_the_same_key_refuses_every_use() {
        let k = key("plan");
        let mut fake = Fake::new();
        let named = write(&mut fake, &endpoint(), &k, &plan("a"), None).unwrap();
        fake.source(&k, "inherited from tank");
        fake.restart();
        let error = write(&mut fake, &endpoint(), &k, &plan("a"), None).unwrap_err();
        assert!(
            error.to_string().contains("belongs to one dataset"),
            "{error}"
        );
        assert!(read::<Plan>(&mut fake, &k, &named).is_err());
        assert!(remove(&mut fake, &endpoint(), &k, None).is_err());
        assert!(remove(&mut fake, &endpoint(), &k, Some(&named)).is_err());
        assert!(fake.effects.is_empty());
    }

    #[test]
    fn keys_and_sets_admit_only_attachment_chunks() {
        for (id, slot) in [
            ("12345678-1234-1234-9234-1234567890ab", "plan"),
            ("12345678-1234-4234-9234-1234567890AB", "plan"),
            ("0123456789abcde", "receipt"),
            ("0123456789ABCDEF", "receipt"),
            ("0123456789abcdef0", "receipt"),
            (OP, ""),
            (OP, "Plan"),
            (OP, "pl:an"),
            (OP, "abcdefghijklmnopq"),
        ] {
            assert!(Key::new(id, slot).is_err(), "{id} {slot}");
        }
        let chunk = key("plan").chunk(0);
        for values in [
            vec![],
            vec![("readonly".to_string(), "on".to_string())],
            vec![("zboot:operation".to_string(), "{}".into())],
            vec![(chunk.clone(), String::new())],
            vec![(chunk.clone(), "0".repeat(CHUNK_BYTES * 2 + 2))],
            vec![(format!("{PREFIX}{OP}:plan:{MAX_CHUNKS:04x}"), "00".into())],
        ] {
            assert!(validate_set(&values).is_err(), "{values:?}");
        }
        validate_set(&[(chunk, "00".into())]).unwrap();
        // Restore's records carry 16 hex digits instead of a UUID.
        let restore = Key::new("0123456789abcdef", "receipt").unwrap();
        assert_eq!(
            restore.prefix(),
            "zboot:attachment:0123456789abcdef:receipt:"
        );
        let mut fake = Fake::new();
        let receipt = write(&mut fake, &endpoint(), &restore, &plan("r"), None).unwrap();
        assert_eq!(
            read::<Plan>(&mut fake, &restore, &receipt).unwrap(),
            plan("r")
        );
        assert!(
            fake.chunks(&restore)
                .iter()
                .all(|k| k.starts_with(restore.prefix()))
        );
        remove(&mut fake, &endpoint(), &restore, Some(&receipt)).unwrap();
        assert!(fake.chunks(&restore).is_empty());
        // The native backend refuses semantic properties before any I/O.
        let error = NativeAttachment
            .set(&endpoint(), &[("mountpoint".into(), "/".into())])
            .unwrap_err()
            .to_string();
        assert!(error.contains("outside attachment namespace"), "{error}");
        assert!(NativeAttachment.inherit(&endpoint(), "zboot:pair").is_err());
        // An oversized payload is refused before any effect.
        let mut fake = Fake::new();
        let huge = Plan {
            source: String::new(),
            members: vec!["z".repeat(MAX_BYTES)],
        };
        assert!(write(&mut fake, &endpoint(), &key("plan"), &huge, None).is_err());
        assert!(fake.effects.is_empty());
    }
}
