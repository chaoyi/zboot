//! Selection normalization never performs a native effect or silently expands loss.
use crate::history::contains_dataset;
use std::collections::BTreeSet;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Invalid {
    #[error("invalid dataset selection: {0}")]
    Name(String),
}
fn name(value: &str) -> Result<(), Invalid> {
    zfs_tools::engine::validate_dataset_name(value).map_err(|_| Invalid::Name(value.into()))
}

pub fn normalize_roots(roots: &[String]) -> Result<Vec<String>, Invalid> {
    let mut sorted = BTreeSet::new();
    for root in roots {
        name(root)?;
        sorted.insert(root.clone());
    }
    let mut result: Vec<String> = Vec::new();
    for root in sorted {
        if !result.iter().any(|parent| contains_dataset(parent, &root)) {
            result.push(root);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roots_normalize_without_confusing_sibling_prefixes() {
        let roots = vec![
            "a/home/child".into(),
            "a/home2".into(),
            "a/home".into(),
            "a/home".into(),
        ];
        assert_eq!(normalize_roots(&roots).unwrap(), vec!["a/home", "a/home2"]);
        let mut reverse = roots.clone();
        reverse.reverse();
        assert_eq!(normalize_roots(&roots), normalize_roots(&reverse));
    }
    #[test]
    fn malformed_names_refuse() {
        for bad in ["-r", "pool//a", "pool/../x", "pool/a@b", "pool/a\nother"] {
            assert!(normalize_roots(&[bad.into()]).is_err());
        }
    }
}
