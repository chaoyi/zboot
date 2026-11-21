use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=ZBOOT_SOURCE_SHA256");
    println!("cargo:rerun-if-env-changed=ZBOOT_SOURCE_TIME");
    let version = env::var("CARGO_PKG_VERSION").expect("Cargo supplies the package version");
    let source = env::var("ZBOOT_SOURCE_SHA256").ok();
    let time = env::var("ZBOOT_SOURCE_TIME").ok();
    let short = match source.as_deref() {
        Some(hash)
            if hash.len() == 64
                && hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            &hash[..12]
        }
        Some(_) => panic!("ZBOOT_SOURCE_SHA256 must be a lowercase SHA-256 digest"),
        None => "unassembled",
    };
    // dist/dist.sh passes both: the UTC time of the inputs' last commit,
    // YYYYMMDDHHMMSS, orders successive packages (docs/BUILD.md).
    let package = match (source.is_some(), time.as_deref()) {
        (true, Some(time)) if time.len() == 14 && time.bytes().all(|b| b.is_ascii_digit()) => {
            format!("{version}+git{time}.{short}")
        }
        (false, None) => format!("{version}+{short}"),
        _ => panic!("ZBOOT_SOURCE_TIME must be YYYYMMDDHHMMSS, given with ZBOOT_SOURCE_SHA256"),
    };
    println!("cargo:rustc-env=ZBOOT_SOURCE_SHA256_PREFIX={short}");
    println!("cargo:rustc-env=ZBOOT_DISPLAY_VERSION={version} (source {short})");
    println!("cargo:rustc-env=ZBOOT_PACKAGE_VERSION={package}");
}
