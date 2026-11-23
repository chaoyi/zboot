//! The menu SSH host key as six words a person can read off the console.
//!
//! Word N is bits 11(N-1)..11N of the host key's SHA-256 digest (the bytes
//! `SHA256:` fingerprints encode), indexing the BIP-39 English list. Fleet's
//! deploy controller derives the same words from the key it scanned, shows
//! words 1-5 and asks the operator to type word 6. The list is the public BIP-39 file; Fleet
//! embeds a byte-identical copy and pins the same SHA-256.

/// Words displayed; 66 of the digest's 256 bits.
pub(super) const COUNT: usize = 6;

const LIST: &str = include_str!("bip39-english.txt");

/// SHA-256 of `bip39-english.txt`, the published BIP-39 English list. Fleet
/// pins the same value for its copy.
#[cfg(test)]
const LIST_SHA256: &str = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";

fn word(index: usize) -> &'static str {
    LIST.lines().nth(index).expect("2048-word list")
}

/// Standard base64 without padding, as `ssh-keygen -E sha256` prints it.
fn digest(fingerprint: &str) -> Option<[u8; 32]> {
    let text = fingerprint.strip_prefix("SHA256:")?;
    if text.len() != 43 {
        return None;
    }
    let mut bits: u32 = 0;
    let mut held = 0;
    let mut out = Vec::with_capacity(33);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        bits = (bits << 6) | u32::from(value);
        held += 6;
        if held >= 8 {
            held -= 8;
            out.push((bits >> held) as u8);
            bits &= (1 << held) - 1;
        }
    }
    // 43 characters carry 258 bits: 32 bytes and two zero bits.
    if bits != 0 {
        return None;
    }
    out.try_into().ok()
}

/// The six words of an `SHA256:` host key fingerprint.
pub(super) fn words(fingerprint: &str) -> Option<[&'static str; COUNT]> {
    let digest = digest(fingerprint)?;
    let mut prefix = [0u8; 16];
    prefix.copy_from_slice(&digest[..16]);
    let head = u128::from_be_bytes(prefix);
    Some(std::array::from_fn(|position| {
        word(((head >> (128 - 11 * (position + 1))) & 0x7ff) as usize)
    }))
}

/// `Host key words: 1 amber 2 river ...`, numbered so a position can be asked.
pub(super) fn line(fingerprint: &str) -> Option<String> {
    let words = words(fingerprint)?;
    let numbered: Vec<String> = words
        .iter()
        .enumerate()
        .map(|(index, word)| format!("{} {word}", index + 1))
        .collect();
    Some(format!("Host key words: {}", numbered.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// Shared with Fleet's controller tests: the same key, fingerprint and
    /// words, computed independently from `ssh-keygen -lf` and the BIP-39 list.
    const VECTOR_FINGERPRINT: &str = "SHA256:7R47Vfjv11EU/pHF5UnS60ljM38uX1q9DzZX0HLvBCg";
    const VECTOR_WORDS: [&str; COUNT] = ["unfair", "vault", "step", "vault", "word", "possible"];

    #[test]
    fn the_list_is_the_published_bip39_english_list() {
        let hex: String = Sha256::digest(LIST.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(hex, LIST_SHA256);
        let words: Vec<_> = LIST.lines().collect();
        assert_eq!(words.len(), 2048);
        assert_eq!((words[0], words[2047]), ("abandon", "zoo"));
    }

    #[test]
    fn words_follow_the_digest_bits() {
        assert_eq!(words(VECTOR_FINGERPRINT), Some(VECTOR_WORDS));
        assert_eq!(
            words(&format!("SHA256:{}", "A".repeat(43))),
            Some(["abandon"; COUNT])
        );
        // The first bit alone selects word 1024 for the first position.
        assert_eq!(
            words(&format!("SHA256:g{}", "A".repeat(42))).unwrap()[0],
            word(1024)
        );
        assert_eq!(
            line(VECTOR_FINGERPRINT).as_deref(),
            Some("Host key words: 1 unfair 2 vault 3 step 4 vault 5 word 6 possible")
        );
    }

    #[test]
    fn malformed_fingerprints_have_no_words() {
        for bad in [
            "7R47Vfjv11EU/pHF5UnS60ljM38uX1q9DzZX0HLvBCg",
            "SHA256:7R47Vfjv11EU/pHF5UnS60ljM38uX1q9DzZX0HLvBC",
            "SHA256:7R47Vfjv11EU/pHF5UnS60ljM38uX1q9DzZX0HLvBCg=",
            "SHA256:7R47Vfjv11EU-pHF5UnS60ljM38uX1q9DzZX0HLvBCg",
            // Non-canonical trailing bits.
            "SHA256:7R47Vfjv11EU/pHF5UnS60ljM38uX1q9DzZX0HLvBCh",
        ] {
            assert_eq!(words(bad), None, "{bad}");
        }
    }
}
