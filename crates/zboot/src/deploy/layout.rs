//! One GPT planner for the reviewed ESP/swap choices and aligned remaining ZFS space.
use super::refuse;
use crate::device::{DiskIdentity, PartitionIdentity};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io;

pub const ESP_TYPE: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
pub const ZFS_TYPE: &str = "6a898cc3-1dd2-11b2-99a6-080020736631";
pub const SWAP_TYPE: &str = "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f";
const MIB: u64 = 1024 * 1024;
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Layout {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap: Option<SwapPartition>,
    pub disk_uuid: String,
    pub esp_uuid: String,
    pub zfs_uuid: String,
    pub fat_id: String,
    pub esp_start: u64,
    pub esp_sectors: u64,
    pub zfs_start: u64,
    pub zfs_sectors: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwapPartition {
    pub uuid: String,
    pub start: u64,
    pub sectors: u64,
}
impl Layout {
    pub fn selected(
        disk: &DiskIdentity,
        esp_bytes: Option<u64>,
        swap_bytes: Option<u64>,
        id: &str,
    ) -> io::Result<Self> {
        if ![512, 4096].contains(&disk.logical_sector)
            || esp_bytes.is_some_and(|b| b == 0 || !b.is_multiple_of(MIB))
            || swap_bytes.is_some_and(|b| b == 0 || !b.is_multiple_of(MIB))
        {
            return Err(refuse(
                "partition sizes must be positive whole MiB with 512/4096 byte sectors",
            ));
        }
        let unit = MIB / disk.logical_sector;
        let esp_sectors = esp_bytes.unwrap_or(0) / disk.logical_sector;
        let swap_start = unit
            .checked_add(esp_sectors)
            .ok_or_else(|| refuse("ESP size overflow"))?;
        let swap_sectors = swap_bytes.unwrap_or(0) / disk.logical_sector;
        let zfs_start = swap_start
            .checked_add(swap_sectors)
            .ok_or_else(|| refuse("swap size overflow"))?;
        let end = (disk.bytes / MIB)
            .checked_sub(1)
            .ok_or_else(|| refuse("disk too small"))?
            * unit;
        let out = Self {
            disk_uuid: derived_uuid(id.as_bytes(), "gpt-disk"),
            esp_uuid: derived_uuid(id.as_bytes(), "gpt-esp"),
            zfs_uuid: derived_uuid(id.as_bytes(), "gpt-zfs"),
            fat_id: derived_uuid(id.as_bytes(), "fat-esp").replace('-', "")[..8].to_uppercase(),
            esp_start: unit,
            esp_sectors,
            zfs_start,
            zfs_sectors: end
                .checked_sub(zfs_start)
                .ok_or_else(|| refuse("selected partitions leave no ZFS space"))?,
            swap: swap_bytes.map(|_| SwapPartition {
                uuid: derived_uuid(id.as_bytes(), "gpt-swap"),
                start: swap_start,
                sectors: swap_sectors,
            }),
        };
        out.validate(disk)?;
        Ok(out)
    }
    pub fn specs(&self) -> Vec<(u64, u64, &str, &str, &str)> {
        let mut parts = Vec::new();
        if self.esp_sectors != 0 {
            parts.push((
                self.esp_start,
                self.esp_sectors,
                ESP_TYPE,
                self.esp_uuid.as_str(),
                "zboot-esp",
            ));
        }
        if let Some(swap) = &self.swap {
            parts.push((
                swap.start,
                swap.sectors,
                SWAP_TYPE,
                swap.uuid.as_str(),
                "zboot-swap",
            ));
        }
        parts.push((
            self.zfs_start,
            self.zfs_sectors,
            ZFS_TYPE,
            self.zfs_uuid.as_str(),
            "zboot-zfs",
        ));
        parts
    }
    pub fn partition_args(&self, disk: &DiskIdentity) -> io::Result<Vec<String>> {
        self.validate(disk)?;
        let mut args = vec![
            "--clear".into(),
            format!("--set-alignment={}", MIB / disk.logical_sector),
            format!("--disk-guid={}", self.disk_uuid),
        ];
        for (i, (start, sectors, kind, id, name)) in self.specs().into_iter().enumerate() {
            let number = i + 1;
            args.extend([
                format!("--new={number}:{start}:{}", start + sectors - 1),
                format!("--typecode={number}:{kind}"),
                format!("--partition-guid={number}:{id}"),
                format!("--change-name={number}:{name}"),
            ]);
        }
        args.push(disk.path.clone());
        Ok(args)
    }
    pub fn validate(&self, disk: &DiskIdentity) -> io::Result<()> {
        let ids = [&self.disk_uuid, &self.esp_uuid, &self.zfs_uuid];
        if ids.iter().any(|id| uuid::Uuid::parse_str(id).is_err())
            || ids[0] == ids[1]
            || ids[1] == ids[2]
            || ids[0] == ids[2]
            || self.fat_id.len() != 8
            || !self.fat_id.bytes().all(|b| b.is_ascii_hexdigit())
            || ![512, 4096].contains(&disk.logical_sector)
            || !disk.physical_sector.is_power_of_two()
            || disk.physical_sector > MIB
            || !disk.bytes.is_multiple_of(disk.logical_sector)
        {
            return Err(refuse("invalid deploy layout identity"));
        }
        let unit = MIB / disk.logical_sector;
        if self.esp_start != unit
            || !self.esp_sectors.is_multiple_of(unit)
            || self.esp_sectors != 0 && !(256 * unit..=4096 * unit).contains(&self.esp_sectors)
            || disk.logical_sector == 4096 && self.esp_sectors != 0 && self.esp_sectors < 512 * unit
            || self
                .esp_start
                .checked_add(self.esp_sectors)
                .and_then(|v| v.checked_add(self.swap.as_ref().map_or(0, |s| s.sectors)))
                != Some(self.zfs_start)
            || self.swap.as_ref().is_some_and(|s| {
                s.start != self.esp_start + self.esp_sectors
                    || s.sectors == 0
                    || !s.sectors.is_multiple_of(unit)
                    || uuid::Uuid::parse_str(&s.uuid).is_err()
                    || ids.contains(&&s.uuid)
            })
            || self.zfs_sectors < 2 * 1024 * unit
            || !self.zfs_sectors.is_multiple_of(unit)
            || self
                .zfs_start
                .checked_add(self.zfs_sectors)
                .and_then(|v| v.checked_mul(disk.logical_sector))
                .is_none_or(|v| v > disk.bytes.saturating_sub(MIB))
        {
            return Err(refuse("unsupported deploy partition geometry"));
        }
        Ok(())
    }
    pub fn fat_uuid(&self) -> String {
        format!("{}-{}", &self.fat_id[..4], &self.fat_id[4..])
    }
    pub fn verify_json(&self, disk: &DiskIdentity, text: &str) -> io::Result<Vec<String>> {
        self.validate(disk)?;
        let value: serde_json::Value = serde_json::from_str(text).map_err(refuse)?;
        let table = &value["partitiontable"];
        let id = table["id"].as_str().unwrap_or("");
        let parts = table["partitions"]
            .as_array()
            .ok_or_else(|| refuse("GPT partition inventory omitted"))?;
        if table["label"] != "gpt"
            || !id.eq_ignore_ascii_case(&self.disk_uuid)
            || table["device"] != disk.path
            || table["unit"] != "sectors"
            || table["sectorsize"] != disk.logical_sector
            || parts.len() != self.specs().len()
        {
            return Err(refuse("native GPT does not match declared deploy layout"));
        }
        let mut paths = Vec::new();
        for (i, (start, size, kind, id, _)) in self.specs().into_iter().enumerate() {
            let part = &parts[i];
            let path = part["node"]
                .as_str()
                .filter(|p| p.starts_with("/dev/"))
                .ok_or_else(|| refuse("GPT partition path missing"))?;
            if part["start"] != start
                || part["size"] != size
                || !part["type"]
                    .as_str()
                    .unwrap_or("")
                    .eq_ignore_ascii_case(kind)
                || !part["uuid"].as_str().unwrap_or("").eq_ignore_ascii_case(id)
            {
                return Err(refuse("GPT partition geometry or identity changed"));
            }
            paths.push(path.to_owned());
        }
        Ok(paths)
    }
    pub fn verify_partition(
        &self,
        disk: &DiskIdentity,
        value: &PartitionIdentity,
        esp: bool,
        formatted: bool,
    ) -> io::Result<()> {
        let (number, id, kind, sectors) = if esp {
            (1, &self.esp_uuid, ESP_TYPE, self.esp_sectors)
        } else {
            (
                self.specs().len() as u32,
                &self.zfs_uuid,
                ZFS_TYPE,
                self.zfs_sectors,
            )
        };
        if &value.disk != disk
            || value.number != number
            || value.readonly
            || value.partition.bytes != sectors * disk.logical_sector
            || value
                .partition
                .partition_uuid
                .as_deref()
                .is_none_or(|s| !s.eq_ignore_ascii_case(id))
            || value
                .partition_type
                .as_deref()
                .is_none_or(|s| !s.eq_ignore_ascii_case(kind))
            || esp
                && formatted
                && (value.partition.filesystem.as_deref() != Some("vfat")
                    || value
                        .partition
                        .filesystem_uuid
                        .as_deref()
                        .is_none_or(|s| !s.eq_ignore_ascii_case(&self.fat_uuid())))
        {
            return Err(refuse("deploy partition incarnation changed"));
        }
        Ok(())
    }
}
pub(super) fn derived_uuid(seed: &[u8], domain: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"zboot-deploy-v1\0");
    hash.update(domain.as_bytes());
    hash.update([0]);
    hash.update(seed);
    let mut bytes: [u8; 16] = hash.finalize()[..16].try_into().unwrap();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid::Uuid::from_bytes(bytes).to_string()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn disk(sector: u64) -> DiskIdentity {
        DiskIdentity {
            path: "/dev/vda".into(),
            device_number: "252:0".into(),
            sysfs_path: "/sys/devices/test/vda".into(),
            bytes: 8 * 1024 * MIB,
            logical_sector: sector,
            physical_sector: 4096,
            serial: Some("owned".into()),
            wwn: None,
            model: None,
        }
    }
    #[test]
    fn geometry_accounts_for_native_sector_size_and_both_gpt_ends() {
        for sector in [512, 4096] {
            let d = disk(sector);
            let l = Layout::selected(&d, Some(512 * MIB), None, "geometry").unwrap();
            assert_eq!(l.esp_start * sector, MIB);
            assert_eq!(l.esp_sectors * sector, 512 * MIB);
            assert_eq!((l.zfs_start + l.zfs_sectors) * sector, d.bytes - MIB);
            l.validate(&d).unwrap();
        }
        let selected = |d: &DiskIdentity, esp_mib: u64| {
            Layout::selected(d, Some(esp_mib * MIB), None, "geometry")
        };
        assert!(selected(&disk(1024), 512).is_err());
        assert!(selected(&disk(512), 32).is_err());
        let mut d = disk(512);
        d.bytes = 2 * 1024 * MIB;
        assert!(selected(&d, 512).is_err());
    }
    #[test]
    fn external_esp_does_not_reserve_phantom_esp_capacity() {
        for sector in [512, 4096] {
            let mut disk = disk(sector);
            disk.bytes = 2304 * MIB;
            let layout = Layout::selected(&disk, None, None, "small-external").unwrap();
            assert_eq!(layout.esp_sectors, 0);
            assert_eq!(layout.zfs_start * sector, MIB);
            assert_eq!(layout.zfs_sectors * sector, 2302 * MIB);
            assert_eq!(layout.specs().len(), 1);
            assert!(Layout::selected(&disk, Some(512 * MIB), None, "small-on-target").is_err());
            disk.bytes = 2050 * MIB;
            assert!(Layout::selected(&disk, None, None, "minimum-external").is_ok());
            disk.bytes -= MIB;
            assert!(Layout::selected(&disk, None, None, "undersized-external").is_err());
            disk.bytes = 0;
            assert!(Layout::selected(&disk, None, None, "empty-external").is_err());
        }
    }
    #[test]
    fn selected_boot_and_swap_are_one_exact_gpt_write_set() {
        for sector in [512, 4096] {
            let mut disk = disk(sector);
            disk.bytes = 64 * 1024 * MIB;
            for esp in [None, Some(512 * MIB)] {
                let layout =
                    Layout::selected(&disk, esp, Some(32 * 1024 * MIB), "fixture").unwrap();
                let specs = layout.specs();
                assert_eq!(specs.len(), if esp.is_some() { 3 } else { 2 });
                assert_eq!(
                    layout.swap.as_ref().unwrap().sectors * sector,
                    32 * 1024 * MIB
                );
                assert_eq!(
                    layout.zfs_start * sector,
                    MIB + esp.unwrap_or(0) + 32 * 1024 * MIB
                );
                assert_eq!(
                    (layout.zfs_start + layout.zfs_sectors) * sector,
                    disk.bytes - MIB
                );
                let arguments = layout.partition_args(&disk).unwrap();
                assert_eq!(
                    arguments.iter().filter(|a| a.starts_with("--new=")).count(),
                    specs.len()
                );
                assert_eq!(
                    arguments.iter().any(|a| a.contains(ESP_TYPE)),
                    esp.is_some()
                );
                let parts: Vec<_> = specs.iter().enumerate().map(|(i, (start, size, kind, id, _))| serde_json::json!({"node":format!("/dev/vda{}", i + 1),"start":start,"size":size,"type":kind,"uuid":id})).collect();
                let table = serde_json::json!({"partitiontable":{"label":"gpt","id":layout.disk_uuid,"device":disk.path,"unit":"sectors","sectorsize":sector,"partitions":parts}});
                layout.verify_json(&disk, &table.to_string()).unwrap();
                for field in ["uuid", "start", "size", "type"] {
                    let mut changed = table.clone();
                    changed["partitiontable"]["partitions"][usize::from(esp.is_some())][field] =
                        "changed".into();
                    assert!(layout.verify_json(&disk, &changed.to_string()).is_err());
                }
            }
            assert!(Layout::selected(&disk, None, Some(disk.bytes), "fixture").is_err());
            assert!(Layout::selected(&disk, None, Some(0), "fixture").is_err());
            assert!(Layout::selected(&disk, Some(512 * MIB + 1), None, "fixture").is_err());
        }
    }
    #[test]
    fn every_partition_identity_and_geometry_field_is_bound() {
        let d = disk(512);
        let l = Layout::selected(&d, Some(512 * MIB), None, "bound").unwrap();
        let value = serde_json::json!({"partitiontable":{"label":"gpt","id":l.disk_uuid,"device":d.path,"unit":"sectors","sectorsize":512,"partitions":[{"node":"/dev/vda1","start":l.esp_start,"size":l.esp_sectors,"type":ESP_TYPE,"uuid":l.esp_uuid},{"node":"/dev/vda2","start":l.zfs_start,"size":l.zfs_sectors,"type":ZFS_TYPE,"uuid":l.zfs_uuid}]}});
        assert!(l.verify_json(&d, &value.to_string()).is_ok());
        for field in ["start", "size", "type", "uuid"] {
            let mut bad = value.clone();
            bad["partitiontable"]["partitions"][1][field] = serde_json::json!("changed");
            assert!(l.verify_json(&d, &bad.to_string()).is_err());
        }
    }
}
