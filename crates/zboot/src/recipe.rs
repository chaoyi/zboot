//! Hand recipes: the shell command lines zboot prints for an operator to end
//! an operation it cannot end itself. Every dataset, pool, snapshot, key and
//! tag in them is one quoted shell word, and each step of a recipe runs only
//! if the one before succeeded.
use zfs_tools::engine::{attachment, intent, management};

/// WORD as one POSIX shell word: single-quoted, with a quote inside written
/// as `'"'"'`, so that no backslash appears and display escaping leaves it.
pub(crate) fn quote(word: &str) -> String {
    format!("'{}'", word.replace('\'', "'\"'\"'"))
}
/// `zfs inherit KEY DATASET`.
pub(crate) fn inherit(key: &str, dataset: &str) -> String {
    format!("zfs inherit {} {}", quote(key), quote(dataset))
}
/// Save every property set locally on DATASET to FILE.
pub(crate) fn save_properties(dataset: &str, file: &str) -> String {
    format!(
        "zfs get -H -s local all {} > {}",
        quote(dataset),
        quote(file)
    )
}
/// Inherit every property set locally on DATASET whose name starts with
/// PREFIX, which holds no regular-expression character. `xargs -I` puts
/// each name where `{}` stands in any argument, so its placeholder is one
/// no dataset name can hold; it is quoted for shells such as fish.
fn inherit_prefixed(dataset: &str, prefix: &str) -> String {
    let dataset = quote(dataset);
    format!(
        "zfs get -H -o property -s local all {dataset} | grep {} \
         | xargs -I '{{}}' zfs inherit '{{}}' {dataset}",
        quote(&format!("^{prefix}"))
    )
}
/// Remove POOL's operation record while it still names ID.
fn clear_record(pool: &str, id: &str) -> String {
    let (record, pool) = (quote(intent::PROPERTY), quote(pool));
    format!(
        "zfs get -H -o value {record} {pool} | grep -qF {} && zfs inherit {record} {pool}",
        quote(&format!("\"id\":\"{id}\""))
    )
}
/// The attachments of operation ID on DATASET.
fn attachments(dataset: &str, id: &str) -> String {
    inherit_prefixed(dataset, &format!("{}{id}:", attachment::PREFIX))
}

/// End transfer ID on its SOURCE alone: release its holds TAG on HELD,
/// remove its pending marker there if PENDING, then its attachments, and
/// last the record on POOL, while that still names ID.
pub(crate) fn source_only(
    source: &str,
    pool: &str,
    tag: &str,
    held: &[&str],
    pending: bool,
    id: &str,
) -> String {
    let mut steps = Vec::new();
    if !held.is_empty() {
        let held: Vec<String> = held.iter().map(|name| quote(name)).collect();
        steps.push(format!("zfs release {} {}", quote(tag), held.join(" ")));
    }
    if pending {
        steps.push(inherit(management::PENDING_PROPERTY, source));
    }
    steps.push(attachments(source, id));
    steps.push(clear_record(pool, id));
    steps.join(" && ")
}
/// End released transfer ID by hand: its attachments on HOLDER, then its
/// record on POOL, while that still names ID.
pub(crate) fn released(holder: &str, pool: &str, id: &str) -> String {
    [attachments(holder, id), clear_record(pool, id)].join(" && ")
}
/// End catch-up ID on its TARGET alone: remove its MARKERS there, then its
/// attachments, and last its record on POOL, while that still names ID.
pub(crate) fn target_only(target: &str, pool: &str, markers: &[&str], id: &str) -> String {
    let mut steps: Vec<String> = markers.iter().map(|key| inherit(key, target)).collect();
    steps.push(attachments(target, id));
    steps.push(clear_record(pool, id));
    steps.join(" && ")
}
/// Remove attachment NAME (`ID:SLOT`) from DATASET: every chunk of it set
/// locally there.
pub(crate) fn orphan_cleanup(dataset: &str, name: &str) -> String {
    inherit_prefixed(dataset, &format!("{}{name}:", attachment::PREFIX))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    const ID: &str = "11111111-1111-4111-8111-111111111111";
    const OTHER: &str = "22222222-2222-4222-8222-222222222222";
    /// A pool and a dataset whose names hold a space and a quote, and the
    /// dataset's the word `KEY` too.
    const POOL: &str = "p o'l";
    const DATASET: &str = "p o'l/da'ta KEY set";
    /// What the recipes run besides `zfs`, linked from the system's own
    /// directories into the stub's: the shell's PATH holds that alone.
    const TOOLS: [&str; 3] = ["cat", "grep", "xargs"];

    /// A private directory holding a stub `zfs`, which logs the argv of
    /// each call and answers `get`: the lines of `properties` for a
    /// dataset's properties, and those of `record` for a pool's record.
    /// Nothing else on the host's PATH is reachable from it, so no real
    /// `zfs` ever runs.
    struct Shell(PathBuf);
    impl Shell {
        fn new(name: &str, properties: &[String], record: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("zboot-recipe-{}-{name}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let lines =
                |lines: &[String]| lines.iter().map(|l| format!("{l}\n")).collect::<String>();
            std::fs::write(dir.join("properties"), lines(properties)).unwrap();
            std::fs::write(dir.join("record"), format!("{record}\n")).unwrap();
            let stub = dir.join("zfs");
            std::fs::write(
                &stub,
                "#!/bin/sh\n\
                 for a in \"$@\"; do printf '%s\\037' \"$a\"; done >> \"$ZT_DIR/log\"\n\
                 printf '\\n' >> \"$ZT_DIR/log\"\n\
                 if [ \"$1\" = get ]; then\n\
                 \x20 if [ \"$4\" = value ]; then cat \"$ZT_DIR/record\"; \
                 else cat \"$ZT_DIR/properties\"; fi\n\
                 fi\n",
            )
            .unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            for tool in TOOLS {
                let found = ["/usr/bin", "/bin"]
                    .iter()
                    .map(|system| Path::new(system).join(tool))
                    .find(|path| path.is_file())
                    .unwrap_or_else(|| panic!("no system {tool}"));
                std::os::unix::fs::symlink(found, dir.join(tool)).unwrap();
            }
            Self(dir)
        }
        /// Run RECIPE as a shell would, in this directory: its exit status
        /// and the argv of every `zfs` call in order.
        fn run(&self, recipe: &str) -> (i32, Vec<Vec<String>>) {
            let status = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(recipe)
                .current_dir(&self.0)
                .env_clear()
                .env("PATH", &self.0)
                .env("LC_ALL", "C")
                .env("ZT_DIR", &self.0)
                .status()
                .unwrap();
            let log = std::fs::read_to_string(self.0.join("log")).unwrap_or_default();
            let calls = log
                .lines()
                .map(|line| {
                    line.split('\x1f')
                        .filter(|arg| !arg.is_empty())
                        .map(String::from)
                        .collect()
                })
                .collect();
            (status.code().unwrap(), calls)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Shell {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn argv(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }
    /// The chunk properties a `get` of DATASET answers: two of ID's plan,
    /// one of another operation and one of no attachment.
    fn chunks() -> Vec<String> {
        vec![
            format!("{}{ID}:plan:0000", attachment::PREFIX),
            format!("{}{OTHER}:plan:0000", attachment::PREFIX),
            "zboot:pair".into(),
            format!("{}{ID}:plan:0001", attachment::PREFIX),
        ]
    }
    fn record(id: &str) -> String {
        format!(r#"{{"schema_version":1,"id":"{id}","kind":"sync","step":0,"state":{{}}}}"#)
    }
    /// What removing ID's attachments from DATASET calls.
    fn removal() -> Vec<Vec<String>> {
        vec![
            argv(&["get", "-H", "-o", "property", "-s", "local", "all", DATASET]),
            argv(&[
                "inherit",
                &format!("{}{ID}:plan:0000", attachment::PREFIX),
                DATASET,
            ]),
            argv(&[
                "inherit",
                &format!("{}{ID}:plan:0001", attachment::PREFIX),
                DATASET,
            ]),
        ]
    }
    /// What removing POOL's record calls, and the exit status, when the
    /// record names ID or another operation.
    fn cleared(names_id: bool) -> (i32, Vec<Vec<String>>) {
        let mut calls = vec![argv(&["get", "-H", "-o", "value", intent::PROPERTY, POOL])];
        if names_id {
            calls.push(argv(&["inherit", intent::PROPERTY, POOL]));
        }
        (if names_id { 0 } else { 1 }, calls)
    }

    #[test]
    fn every_recipe_runs_in_a_real_shell_with_its_names_as_single_words() {
        let snapshots = [format!("{DATASET}@s 1"), format!("{DATASET}@it's")];
        let held: Vec<&str> = snapshots.iter().map(String::as_str).collect();
        let tag = format!("zboot:transfer:{ID}");
        let markers = [management::PENDING_PROPERTY, management::STAGING_PROPERTY];
        let recipes: [(&str, String, Vec<Vec<String>>); 3] = [
            (
                "source",
                source_only(DATASET, POOL, &tag, &held, true, ID),
                vec![
                    argv(&["release", &tag, &snapshots[0], &snapshots[1]]),
                    argv(&["inherit", management::PENDING_PROPERTY, DATASET]),
                ],
            ),
            ("released", released(DATASET, POOL, ID), vec![]),
            (
                "target",
                target_only(DATASET, POOL, &markers, ID),
                markers
                    .iter()
                    .map(|key| argv(&["inherit", key, DATASET]))
                    .collect(),
            ),
        ];
        for (name, recipe, first) in recipes {
            for names_id in [true, false] {
                let shell = Shell::new(name, &chunks(), &record(if names_id { ID } else { OTHER }));
                let (status, calls) = shell.run(&recipe);
                let (expected, tail) = cleared(names_id);
                let mut want = first.clone();
                want.extend(removal());
                want.extend(tail);
                assert_eq!(
                    (status, calls),
                    (expected, want),
                    "{name} {names_id}: {recipe}"
                );
            }
        }
        // An orphan's removal, and a step of restore's hand procedures.
        let shell = Shell::new("orphan", &chunks(), &record(ID));
        let (status, calls) = shell.run(&orphan_cleanup(DATASET, &format!("{ID}:plan")));
        assert_eq!((status, calls), (0, removal()));
        let shell = Shell::new("inherit", &[], &record(ID));
        let key = format!("{}{ID}:receipt:0000", attachment::PREFIX);
        let (status, calls) = shell.run(&inherit(&key, DATASET));
        assert_eq!(
            (status, calls),
            (0, vec![argv(&["inherit", &key, DATASET])])
        );
        let shell = Shell::new("save", &chunks(), &record(ID));
        let file = "restore it's.properties";
        let (status, calls) = shell.run(&save_properties(DATASET, file));
        assert_eq!(
            (status, calls),
            (0, vec![argv(&["get", "-H", "-s", "local", "all", DATASET])])
        );
        assert_eq!(
            std::fs::read_to_string(shell.path().join(file)).unwrap(),
            chunks()
                .iter()
                .map(|l| format!("{l}\n"))
                .collect::<String>()
        );
    }

    #[test]
    fn a_quoted_word_is_its_text_and_never_holds_a_backslash() {
        for word in ["plain", "a b", "it's", "''", "a'b'c"] {
            let quoted = quote(word);
            assert!(!quoted.contains('\\'), "{quoted}");
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("printf %s {quoted}"))
                .env_clear()
                .env("LC_ALL", "C")
                .output()
                .unwrap();
            assert_eq!(String::from_utf8(out.stdout).unwrap(), word);
        }
    }
}
