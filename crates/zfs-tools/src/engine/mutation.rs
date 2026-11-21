//! Typed management-property effects with native identity verification. These
//! primitives bind exact endpoint identity and verify native value/source;
//! operation planners own role, fencing, loss and durable-intent admission.
use crate::engine::{
    Error,
    attachment::bound_properties,
    management::{self, Endpoint, MountMode, PairRecord, Placement},
    native::{self, NativeProperty},
};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PropertyKey {
    Pair,
    Pending,
    Placement,
    Readonly,
    Canmount,
    Mountpoint,
    Volmode,
    Cmdline,
    Staging,
}
impl PropertyKey {
    pub fn native(self) -> &'static str {
        match self {
            Self::Pair => management::PAIR_PROPERTY,
            Self::Pending => management::PENDING_PROPERTY,
            Self::Placement => management::PLACEMENT_PROPERTY,
            Self::Readonly => "readonly",
            Self::Canmount => "canmount",
            Self::Mountpoint => "mountpoint",
            Self::Volmode => "volmode",
            Self::Cmdline => "zboot:cmdline",
            Self::Staging => management::STAGING_PROPERTY,
        }
    }
    fn validate(self, endpoint: &Endpoint, value: &str) -> Result<(), Error> {
        match self {
            Self::Pair if PairRecord::parse(value)?.endpoint != *endpoint => {
                return Err(refuse("pair property does not bind the target endpoint"));
            }
            Self::Placement if Placement::parse(value)?.identity != endpoint.identity => {
                return Err(refuse("placement does not bind the target incarnation"));
            }
            Self::Pair | Self::Placement => {}
            Self::Pending | Self::Staging => {
                if !crate::engine::is_canonical_uuid_v4(value) {
                    return Err(refuse("management operation ID must be canonical UUID v4"));
                }
            }
            Self::Readonly if !matches!(value, "on" | "off") => {
                return Err(refuse("invalid readonly value"));
            }
            Self::Canmount if !matches!(value, "on" | "off" | "noauto") => {
                return Err(refuse("invalid canmount value"));
            }
            Self::Mountpoint
                if value.len() > 4096
                    || value.chars().any(char::is_control)
                    || !(matches!(value, "none" | "legacy") || value.starts_with('/')) =>
            {
                return Err(refuse("invalid bounded mountpoint"));
            }
            Self::Volmode if !matches!(value, "default" | "full" | "dev" | "none") => {
                return Err(refuse("invalid volmode value"));
            }
            Self::Cmdline if value.len() > 4096 || value.chars().any(char::is_control) => {
                return Err(refuse(
                    "kernel argument additions exceed supported text boundary",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "property", content = "value", rename_all = "snake_case")]
pub enum PropertyValue {
    Pair(PairRecord),
    Pending(String),
    Placement(Placement),
    Readonly(bool),
    Canmount(MountMode),
    Mountpoint(String),
    Volmode(String),
    Cmdline(String),
    Staging(String),
}
impl PropertyValue {
    pub fn key(&self) -> PropertyKey {
        match self {
            Self::Pair(_) => PropertyKey::Pair,
            Self::Pending(_) => PropertyKey::Pending,
            Self::Placement(_) => PropertyKey::Placement,
            Self::Readonly(_) => PropertyKey::Readonly,
            Self::Canmount(_) => PropertyKey::Canmount,
            Self::Mountpoint(_) => PropertyKey::Mountpoint,
            Self::Volmode(_) => PropertyKey::Volmode,
            Self::Cmdline(_) => PropertyKey::Cmdline,
            Self::Staging(_) => PropertyKey::Staging,
        }
    }
    pub fn encode(&self, endpoint: &Endpoint) -> Result<String, Error> {
        let value = match self {
            Self::Pair(record) => record.encode()?,
            Self::Placement(record) => record.encode()?,
            Self::Readonly(value) => if *value { "on" } else { "off" }.into(),
            Self::Canmount(mode) => mode.native().into(),
            Self::Pending(value)
            | Self::Cmdline(value)
            | Self::Staging(value)
            | Self::Mountpoint(value)
            | Self::Volmode(value) => value.clone(),
        };
        self.key().validate(endpoint, &value)?;
        Ok(value)
    }
}

// NativeMutation and its offline route tests share admission, command framing
// and exact value/source readback; attachment's bound properties bind the
// endpoint.
fn set_with(
    endpoint: &Endpoint,
    value: &PropertyValue,
    mut properties: impl FnMut(
        &Endpoint,
    ) -> Result<std::collections::BTreeMap<String, NativeProperty>, Error>,
    mut command: impl FnMut(&[String]) -> Result<String, Error>,
) -> Result<(), Error> {
    let encoded = value.encode(endpoint)?;
    let key = value.key().native();
    let before = properties(endpoint)?;
    if let Some(previous) = before.get(key) {
        match value {
            // The same operation's marker, inherited (a new copy inside its
            // receive container), becomes local; another operation's never
            // is overwritten.
            PropertyValue::Pending(_) | PropertyValue::Staging(_) if previous.value != encoded => {
                return Err(refuse(
                    "foreign pending or staging operation occupies the endpoint",
                ));
            }
            PropertyValue::Pair(expected) => {
                let current = PairRecord::parse(&previous.value)?;
                if previous.source != "local"
                    || current.pair_id != expected.pair_id
                    || current.endpoint != expected.endpoint
                    || current.peer != expected.peer
                {
                    return Err(refuse("pair property is occupied by different ownership"));
                }
            }
            _ => {}
        }
    }
    if before
        .get(key)
        .is_some_and(|property| property.source == "local" && property.value == encoded)
    {
        return Ok(());
    }

    let result = command(&[
        "set".into(),
        "-u".into(),
        format!("{key}={encoded}"),
        endpoint.name.clone(),
    ]);
    let after = properties(endpoint)?;
    if after
        .get(key)
        .is_some_and(|property| property.source == "local" && property.value == encoded)
    {
        Ok(())
    } else {
        Err(result.err().unwrap_or_else(|| {
            refuse(format!(
                "property set was not verified: {} {key}",
                endpoint.name
            ))
        }))
    }
}

// Native command framing and identity-bound observation are shared with
// offline route tests, as for semantic set above.
fn inherit_with(
    endpoint: &Endpoint,
    key: PropertyKey,
    received: bool,
    mut properties: impl FnMut(
        &Endpoint,
    ) -> Result<std::collections::BTreeMap<String, NativeProperty>, Error>,
    mut command: impl FnMut(&[String]) -> Result<String, Error>,
) -> Result<Option<NativeProperty>, Error> {
    if !matches!(
        key,
        PropertyKey::Mountpoint
            | PropertyKey::Readonly
            | PropertyKey::Canmount
            | PropertyKey::Volmode
    ) {
        return Err(refuse("unsupported receive placement property"));
    }
    properties(endpoint)?;
    let mut args = vec!["inherit".into()];
    if received {
        args.push("-S".into());
    }
    args.extend([key.native().into(), endpoint.name.clone()]);
    let result = command(&args);
    let mut after = properties(endpoint)?;
    let property = after.remove(key.native());
    if property.as_ref().is_some_and(|p| p.source == "local") {
        return Err(result
            .err()
            .unwrap_or_else(|| refuse("native placement inheritance was not verified")));
    }
    Ok(property)
}

#[derive(Default)]
pub struct NativeMutation {}
impl NativeMutation {
    pub fn new() -> Self {
        Self {}
    }
    pub fn set(&mut self, endpoint: &Endpoint, value: &PropertyValue) -> Result<(), Error> {
        set_with(endpoint, value, bound_properties, |args| {
            native::run_mutating("zfs", args)
        })
    }

    /// Restore an inherited/default or received native property after a
    /// verified inert receive. The caller keeps canmount=noauto during a
    /// mountpoint inherit, because native inherit has no -u option.
    pub fn inherit_native(
        &mut self,
        endpoint: &Endpoint,
        key: PropertyKey,
        received: bool,
    ) -> Result<Option<NativeProperty>, Error> {
        inherit_with(endpoint, key, received, bound_properties, |args| {
            native::run_mutating("zfs", args)
        })
    }

    /// Clear only the expected local value. An absent property is idempotent;
    /// inherited/received values are never removed. The caller must inspect the
    /// effective result because inheritance can reveal an existing parent value.
    pub fn inherit_exact(
        &mut self,
        endpoint: &Endpoint,
        key: PropertyKey,
        expected: &str,
    ) -> Result<Option<NativeProperty>, Error> {
        key.validate(endpoint, expected)?;
        let before = bound_properties(endpoint)?;
        match before.get(key.native()) {
            None => return Ok(None),
            Some(property) if property.source == "local" && property.value == expected => {}
            _ => {
                return Err(refuse(
                    "property value or native source changed before exact inherit",
                ));
            }
        }

        let result = native::run_mutating(
            "zfs",
            &["inherit".into(), key.native().into(), endpoint.name.clone()],
        );
        let mut after = bound_properties(endpoint)?;
        let effective = after.remove(key.native());
        if effective
            .as_ref()
            .is_some_and(|property| property.source == "local")
        {
            return Err(result
                .err()
                .unwrap_or_else(|| refuse("local property still present after exact inherit")));
        }
        Ok(effective)
    }
}
fn refuse(detail: impl Into<String>) -> Error {
    Error::Inconsistent(detail.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::attachment::AttachmentBackend;
    fn endpoint() -> Endpoint {
        Endpoint {
            name: "tank/data".into(),
            identity: crate::engine::DatasetIdentity {
                pool_guid: crate::engine::Guid::new(1),
                guid: crate::engine::Guid::new(2),
                createtxg: crate::engine::Txg::new(3),
                objsetid: crate::engine::ObjsetId::new(4),
            },
        }
    }
    #[test]
    fn boot_properties_use_native_semantic_set_and_exact_readback() {
        use std::{cell::RefCell, collections::BTreeMap};
        let endpoint = endpoint();
        let props = RefCell::new(BTreeMap::new());
        let commands = RefCell::new(Vec::new());
        for value in [
            PropertyValue::Mountpoint("/".into()),
            PropertyValue::Cmdline(String::new()),
        ] {
            set_with(
                &endpoint,
                &value,
                |observed| {
                    assert_eq!(observed, &endpoint);
                    Ok(props.borrow().clone())
                },
                |args| {
                    commands.borrow_mut().push(args.to_vec());
                    assert_eq!(args[0], "set");
                    assert_eq!(args[1], "-u");
                    assert_eq!(args[3], endpoint.name);
                    let (key, value) = args[2].split_once('=').unwrap();
                    props.borrow_mut().insert(
                        key.into(),
                        NativeProperty {
                            value: value.into(),
                            source: "local".into(),
                        },
                    );
                    Ok(String::new())
                },
            )
            .unwrap();
        }
        assert_eq!(
            commands
                .borrow()
                .iter()
                .map(|a| a[2].as_str())
                .collect::<Vec<_>>(),
            ["mountpoint=/", "zboot:cmdline="]
        );
        // The attachment backend refuses exactly these semantic writes,
        // including the valid empty command-line value, before any native I/O.
        for key in ["mountpoint", "zboot:be", "zboot:cmdline"] {
            let error = crate::engine::attachment::NativeAttachment
                .set(&endpoint, &[(key.into(), "1".into())])
                .unwrap_err()
                .to_string();
            assert!(error.contains("outside attachment namespace"));
        }
        for value in ["", "relative", "line\nbreak", &"/".repeat(4097)] {
            assert!(
                set_with(
                    &endpoint,
                    &PropertyValue::Mountpoint(value.into()),
                    |_| panic!("invalid value queried native state"),
                    |_| panic!("invalid value wrote native state")
                )
                .is_err()
            );
        }
        // A bound-property query failure prevents the command, and a command
        // success alone cannot replace verified local readback.
        assert!(
            set_with(
                &endpoint,
                &PropertyValue::Cmdline("quiet".into()),
                |_| Err(refuse("endpoint changed")),
                |_| panic!("changed endpoint written")
            )
            .is_err()
        );
        // An operation's own marker inherited from its receive container
        // becomes local; another operation's marker is never overwritten.
        let id = "11111111-1111-4111-8111-111111111111";
        let inherited = |value: &str| {
            BTreeMap::from([(
                "zboot:pending".to_string(),
                NativeProperty {
                    value: value.into(),
                    source: "inherited from tank/zboot-receive-x".into(),
                },
            )])
        };
        let mut queries = 0;
        let mut commands = 0;
        set_with(
            &endpoint,
            &PropertyValue::Pending(id.into()),
            |_| {
                queries += 1;
                Ok(if queries == 1 {
                    inherited(id)
                } else {
                    BTreeMap::from([(
                        "zboot:pending".into(),
                        NativeProperty {
                            value: id.into(),
                            source: "local".into(),
                        },
                    )])
                })
            },
            |_| {
                commands += 1;
                Ok(String::new())
            },
        )
        .unwrap();
        assert_eq!(commands, 1);
        let other = "22222222-2222-4222-8222-222222222222";
        let error = set_with(
            &endpoint,
            &PropertyValue::Pending(id.into()),
            |_| Ok(inherited(other)),
            |_| panic!("another operation's marker was overwritten"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("foreign pending"));
        for source in [None, Some("received")] {
            let mut queries = 0;
            assert!(
                set_with(
                    &endpoint,
                    &PropertyValue::Cmdline("quiet".into()),
                    |_| {
                        queries += 1;
                        Ok(if queries == 2 {
                            source
                                .map(|s| {
                                    BTreeMap::from([(
                                        "zboot:cmdline".into(),
                                        NativeProperty {
                                            value: "quiet".into(),
                                            source: s.into(),
                                        },
                                    )])
                                })
                                .unwrap_or_default()
                        } else {
                            BTreeMap::new()
                        })
                    },
                    |_| Ok(String::new())
                )
                .is_err()
            );
        }
    }

    #[test]
    fn canmount_received_inherit_route_restores_default_without_local_set() {
        use std::{cell::RefCell, collections::BTreeMap};
        let endpoint = endpoint();
        let props = RefCell::new(BTreeMap::from([(
            "canmount".into(),
            NativeProperty {
                value: "noauto".into(),
                source: "local".into(),
            },
        )]));
        let mut commands = vec![];
        let restored = inherit_with(
            &endpoint,
            PropertyKey::Canmount,
            true,
            |ep| {
                assert_eq!(ep, &endpoint);
                Ok(props.borrow().clone())
            },
            |args| {
                commands.push(args.to_vec());
                assert_eq!(args, ["inherit", "-S", "canmount", "tank/data"]);
                props.borrow_mut().insert(
                    "canmount".into(),
                    NativeProperty {
                        value: "on".into(),
                        source: "default".into(),
                    },
                );
                Ok(String::new())
            },
        )
        .unwrap()
        .unwrap();
        assert_eq!(restored.value, "on");
        assert_eq!(restored.source, "default");
        assert_eq!(commands.len(), 1);
        // libzfs rejects the plain-inherit route for this non-inheritable
        // property; command success is never fabricated from a receipt.
        props.borrow_mut().insert(
            "canmount".into(),
            NativeProperty {
                value: "noauto".into(),
                source: "local".into(),
            },
        );
        assert!(
            inherit_with(
                &endpoint,
                PropertyKey::Canmount,
                false,
                |_| Ok(props.borrow().clone()),
                |args| {
                    assert_eq!(args, ["inherit", "canmount", "tank/data"]);
                    Err(refuse("property is not inheritable"))
                }
            )
            .is_err()
        );
        assert_eq!(props.borrow()["canmount"].source, "local");
    }

    #[test]
    fn typed_values_bind_identity_and_reject_unbounded_or_executable_structure() {
        let endpoint = endpoint();
        assert_eq!(
            PropertyValue::Readonly(true).encode(&endpoint).unwrap(),
            "on"
        );
        assert_eq!(
            PropertyValue::Canmount(MountMode::NoAuto)
                .encode(&endpoint)
                .unwrap(),
            "noauto"
        );
        assert!(
            PropertyValue::Pending("not-an-operation".into())
                .encode(&endpoint)
                .is_err()
        );
        assert!(
            PropertyValue::Staging("12345678-1234-1234-9234-1234567890ab".into())
                .encode(&endpoint)
                .is_err()
        );
        assert!(
            PropertyValue::Cmdline("line\nbreak".into())
                .encode(&endpoint)
                .is_err()
        );
        assert!(
            PropertyValue::Cmdline("x".repeat(4097))
                .encode(&endpoint)
                .is_err()
        );
        assert_eq!(
            PropertyValue::Cmdline("literal=$(not executed)".into())
                .encode(&endpoint)
                .unwrap(),
            "literal=$(not executed)"
        );
        let placement = Placement {
            schema_version: 1,
            identity: crate::engine::DatasetIdentity {
                objsetid: crate::engine::ObjsetId::new(999),
                ..endpoint.identity.clone()
            },
            readonly: false,
            canmount: Some(MountMode::On),
            volmode: None,
        };
        assert!(
            PropertyValue::Placement(placement)
                .encode(&endpoint)
                .is_err()
        );
    }
}
