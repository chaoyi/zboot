//! `dist/dist.sh` passes the hash of its frozen source manifest as
//! ZBOOT_SOURCE_SHA256 and the UTC time of its inputs' last commit as
//! ZBOOT_SOURCE_TIME; build.rs embeds the digest's first 12 digits and the
//! Debian package version they make. A plain Cargo build identifies itself as
//! unassembled.

pub const VERSION: &str = env!("ZBOOT_DISPLAY_VERSION");
pub const SOURCE_SHA256_PREFIX: &str = env!("ZBOOT_SOURCE_SHA256_PREFIX");
/// `CRATE+gitYYYYMMDDHHMMSS.SOURCE`, the version of the package `zboot`
/// (`CRATE+unassembled` for a plain Cargo build).
pub const PACKAGE_VERSION: &str = env!("ZBOOT_PACKAGE_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_and_source_label_match() {
        assert!(VERSION.starts_with(concat!(env!("CARGO_PKG_VERSION"), " (source ")));
        assert!(VERSION.ends_with(&format!("{SOURCE_SHA256_PREFIX})")));
        assert!(
            SOURCE_SHA256_PREFIX == "unassembled"
                || (SOURCE_SHA256_PREFIX.len() == 12
                    && SOURCE_SHA256_PREFIX
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
        );
        let tail = PACKAGE_VERSION
            .strip_prefix(concat!(env!("CARGO_PKG_VERSION"), "+"))
            .unwrap();
        if SOURCE_SHA256_PREFIX == "unassembled" {
            assert_eq!(tail, "unassembled");
        } else {
            let (time, source) = tail.strip_prefix("git").unwrap().split_once('.').unwrap();
            assert!(time.len() == 14 && time.bytes().all(|b| b.is_ascii_digit()));
            assert_eq!(source, SOURCE_SHA256_PREFIX);
        }
    }
}
