//! Read-only export proof from all four native ZFS labels. The small accepted
//! text surface is grounded in OpenZFS zdb dump_label/dump_nvlist; unknown or
//! partial label sets refuse. No import, clear-label or repair occurs here.
use super::refuse;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io};
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub pool: String,
    pub pool_guid: String,
    pub vdev_guid: String,
    pub txg: u64,
    pub exported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostid: Option<u32>,
}
fn positive(value: &str) -> bool {
    value
        .parse::<u64>()
        .is_ok_and(|v| v != 0 && v.to_string() == value)
}
impl Evidence {
    pub fn validate(&self) -> io::Result<()> {
        zfs_tools::engine::validate_dataset_name(&self.pool).map_err(refuse)?;
        if self.pool.contains('/')
            || !positive(&self.pool_guid)
            || !positive(&self.vdev_guid)
            || self.txg == 0
        {
            return Err(refuse("invalid native pool label evidence"));
        }
        Ok(())
    }
    pub fn same_incarnation(&self, prior: &Self) -> bool {
        self.pool == prior.pool
            && self.pool_guid == prior.pool_guid
            && self.vdev_guid == prior.vdev_guid
            && self.txg >= prior.txg
    }
}
pub fn parse(text: &str) -> io::Result<Evidence> {
    if text.len() > 2 * 1024 * 1024 {
        return Err(refuse("native pool labels exceed supported bound"));
    }
    let mut labels: BTreeMap<u32, BTreeMap<String, String>> = BTreeMap::new();
    let mut current = None;
    for line in text.lines() {
        if let Some(tail) = line.strip_prefix("LABEL ") {
            let number = tail
                .trim()
                .parse::<u32>()
                .map_err(|_| refuse("native pool label checksum failed or header changed"))?;
            if number > 3 || labels.insert(number, BTreeMap::new()).is_some() {
                return Err(refuse("duplicate or invalid native pool label"));
            }
            current = Some(number);
            continue;
        }
        let Some(number) = current else {
            continue;
        };
        let Some(root) = line.strip_prefix("    ") else {
            continue;
        };
        if root.starts_with(char::is_whitespace) {
            continue;
        }
        let Some((key, value)) = root.split_once(": ") else {
            continue;
        };
        if [
            "name",
            "state",
            "pool_guid",
            "guid",
            "top_guid",
            "txg",
            "vdev_children",
            "hostid",
        ]
        .contains(&key)
            && labels
                .get_mut(&number)
                .unwrap()
                .insert(key.into(), value.into())
                .is_some()
        {
            return Err(refuse("duplicate native label identity field"));
        }
    }
    if labels.keys().copied().collect::<Vec<_>>() != [0, 1, 2, 3] {
        return Err(refuse("all four native pool labels must be readable"));
    }
    let first = &labels[&0];
    if labels.values().any(|v| v != first) {
        return Err(refuse(
            "native pool labels disagree on identity or export state",
        ));
    }
    let field = |key: &str| {
        first
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| refuse(format!("native pool label omitted {key}")))
    };
    let name = field("name")?;
    let pool = name
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .ok_or_else(|| refuse("native pool label name is not quoted"))?;
    let state = field("state")?;
    if !["0", "1"].contains(&state)
        || field("vdev_children")? != "1"
        || field("guid")? != field("top_guid")?
    {
        return Err(refuse(
            "native pool labels do not describe one active/exported direct vdev",
        ));
    }
    let value = Evidence {
        pool: pool.into(),
        pool_guid: field("pool_guid")?.into(),
        vdev_guid: field("guid")?.into(),
        txg: field("txg")?.parse().map_err(refuse)?,
        exported: state == "1",
        hostid: first
            .get("hostid")
            .map(|value| {
                value
                    .parse::<u32>()
                    .map_err(|_| refuse("invalid native pool label hostid"))
            })
            .transpose()?,
    };
    if value.hostid == Some(0) {
        return Err(refuse("native pool label hostid is zero"));
    }
    value.validate()?;
    Ok(value)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(state: u8) -> String {
        (0..4).map(|i|format!("------------------------------------\nLABEL {i}\n------------------------------------\n    name: 'owned pool'\n    state: {state}\n    txg: 24\n    pool_guid: 123\n    top_guid: 456\n    guid: 456\n    vdev_children: 1\n    hostid: 16909060\n    vdev_tree:\n        type: 'disk'\n        guid: 456\n    labels = 0 1 2 3\n")).collect()
    }
    #[test]
    fn export_requires_four_matching_checksum_valid_native_labels() {
        let good = fixture(1);
        let p = parse(&good).unwrap();
        assert!(p.exported);
        assert_eq!(p.pool, "owned pool");
        assert_eq!(p.pool_guid, "123");
        assert_eq!(p.hostid, Some(16909060));
        assert!(!parse(&fixture(0)).unwrap().exported);
        for bad in [
            good.replace("LABEL 2", "LABEL 2 (Bad label cksum)"),
            good.replacen("    state: 1", "    state: 0", 1),
            good.replacen("    pool_guid: 123", "    pool_guid: 124", 1),
            good.replace("    state: 1", "    state: 2"),
            good.replace("    vdev_children: 1", "    vdev_children: 2"),
            good.replace("LABEL 3", "LABEL 2"),
            good.replace("    guid: 456", "    guid: 789"),
            good.replacen("    hostid: 16909060", "    hostid: 16909061", 1),
            good.replace("    hostid: 16909060", "    hostid: 0"),
        ] {
            assert!(parse(&bad).is_err());
        }
        assert_eq!(
            parse(&good.replace("    hostid: 16909060\n", ""))
                .unwrap()
                .hostid,
            None
        );
    }
}
