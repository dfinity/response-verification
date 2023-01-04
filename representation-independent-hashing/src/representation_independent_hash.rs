use crate::hash::hash;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub fn representation_independent_hash(map: HashMap<String, String>) -> [u8; 32] {
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
        let map: HashMap<String, String> = HashMap::from([
            ("name".into(), "foo".into()),
            ("message".into(), "Hello World!".into()),
        ]);
        let expected_hash: [u8; 32] = [
            90, 150, 203, 48, 202, 187, 80, 70, 84, 53, 139, 125, 114, 107, 61, 126, 45, 108, 200,
            244, 243, 58, 162, 122, 170, 81, 137, 21, 129, 21, 202, 204,
        ];

        let result = representation_independent_hash(map);

        assert_eq!(result, expected_hash);
    }

    #[test]
    fn hash_reordered_key_value_map() {
        let map: HashMap<String, String> = HashMap::from([
            ("name".into(), "foo".into()),
            ("message".into(), "Hello World!".into()),
        ]);
        let reordered_map: HashMap<String, String> = HashMap::from([
            ("message".into(), "Hello World!".into()),
            ("name".into(), "foo".into()),
        ]);

        let result = representation_independent_hash(map);
        let reordered_result = representation_independent_hash(reordered_map);

        assert_eq!(result, reordered_result);
    }
}
