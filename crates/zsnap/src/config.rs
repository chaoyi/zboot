use crate::{Policy, parse_policies};
use anyhow::{Result, bail};
use std::collections::BTreeMap;

/// Native assignment property shared by policy observation and execution.
pub const POLICY_PROPERTY: &str = "zsnap:policy";
pub const DEFAULT_POLICIES: &str = include_str!("policies.toml");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub policies: BTreeMap<String, Policy>,
}

impl Config {
    /// Built-in definitions with complete named-policy replacements from text.
    /// The caller loads any file. Invalid input never produces a partial config.
    pub fn from_override(text: Option<&str>) -> Result<Self> {
        let mut policies = parse_policies(DEFAULT_POLICIES)?;
        if let Some(text) = text {
            policies.extend(parse_policies(text)?);
        }
        Ok(Self { policies })
    }

    /// Resolve an observed effective property, including inherited values.
    /// Unknown policy names are errors, not an empty retention policy.
    pub fn assignment(&self, value: &str) -> Result<Assignment> {
        let value = value.trim();
        if crate::is_disabled_policy(value) {
            return Ok(Assignment::Disabled);
        }
        if !self.policies.contains_key(value) {
            bail!("unknown policy {value:?}");
        }
        Ok(Assignment::Policy(value.to_owned()))
    }
}

/// A pure interpretation of an observed property. Unassigning (inherit) is a
/// distinct future native operation; it may reveal an ancestor's policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Assignment {
    Disabled,
    Policy(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_complete_named_override() {
        let defaults = Config::from_override(None).unwrap();
        assert_eq!(defaults.policies.len(), 4);
        assert_eq!(defaults.policies["guard"].keep.within, Some(1800));
        let changed = Config::from_override(Some(
            "[policy.guard]\nfrequency = '1h'\nkeep = { last = 3 }",
        ))
        .unwrap();
        assert_eq!(changed.policies.len(), 4);
        assert_eq!(changed.policies["guard"].keep.last, Some(3));
        assert_eq!(changed.policies["guard"].keep.within, None);
        assert_eq!(defaults.policies["undo"], changed.policies["undo"]);
    }

    #[test]
    fn disabled_unknown_and_inherited_effective_assignments() {
        let config = Config::from_override(None).unwrap();
        for disabled in ["", "-", "none", " none "] {
            assert_eq!(config.assignment(disabled).unwrap(), Assignment::Disabled);
        }
        assert_eq!(
            config.assignment(" guard ").unwrap(),
            Assignment::Policy("guard".into())
        );
        assert!(config.assignment("missing").is_err());
        for name in ["none", "-", "", " guard "] {
            assert!(
                parse_policies(&format!(
                    "[policy.'{name}']\nfrequency='1m'\nkeep={{last=1}}"
                ))
                .is_err()
            );
        }
    }
}
