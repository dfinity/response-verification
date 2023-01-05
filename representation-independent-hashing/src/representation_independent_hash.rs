use crate::hash::hash;
use sha2::{Digest, Sha256};

/// A partial implementation of [`Representation Independent Hash`] that only supports UTF-8 strings as values.
///
/// [`Representation Independent Hash`]: https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map
pub fn representation_independent_hash(map: &Vec<(String, String)>) -> [u8; 32] {
    let mut hashes: Vec<_> = map
        .iter()
        .map(|(key, value)| (hash(key.as_bytes()), hash(value.as_bytes())))
        .collect();

    hashes.sort_unstable();

    let mut hasher = Sha256::new();
    for (key_hash, value_hash) in hashes.iter() {
        hasher.update(&key_hash[..]);
        hasher.update(&value_hash[..]);
    }

    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_key_value_map() {
        let map: Vec<(String, String)> = vec![
            ("name".into(), "foo".into()),
            ("message".into(), "Hello World!".into()),
        ];
        let expected_hash =
            hex::decode("5a96cb30cabb504654358b7d726b3d7e2d6cc8f4f33aa27aaa5189158115cacc")
                .unwrap();

        let result = representation_independent_hash(&map);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn handles_duplicate_keys() {
        let map: Vec<(String, String)> = vec![
            ("name".into(), "foo".into()),
            ("name".into(), "bar".into()),
            ("message".into(), "Hello World!".into()),
        ];
        let expected_hash =
            hex::decode("435f77c9bdeca5dba4a4b8a34e4f732b4311f1fc252ec6d4e8ee475234b170f9")
                .unwrap();

        let result = representation_independent_hash(&map);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn hash_reordered_key_value_map() {
        let map: Vec<(String, String)> = vec![
            ("name".into(), "foo".into()),
            ("message".into(), "Hello World!".into()),
            ("name".into(), "bar".into()),
        ];
        let reordered_map: Vec<(String, String)> = vec![
            ("message".into(), "Hello World!".into()),
            ("name".into(), "bar".into()),
            ("name".into(), "foo".into()),
        ];

        let result = representation_independent_hash(&map);
        let reordered_result = representation_independent_hash(&reordered_map);

        assert_eq!(result, reordered_result);
    }
}
