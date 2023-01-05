use crate::hash::hash;
use sha2::{Digest, Sha256};

pub enum Value {
    String(String),
    Number(u64),
}

/// A partial implementation of [`Representation Independent Hash`] that only supports
/// UTF-8 strings or numbers as values.
///
/// [`Representation Independent Hash`]: https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map
pub fn representation_independent_hash(map: &Vec<(String, Value)>) -> [u8; 32] {
    let mut hashes: Vec<_> = map
        .iter()
        .map(|(key, value)| (hash(key.as_bytes()), hash_value(value)))
        .collect();

    hashes.sort_unstable();

    let mut hasher = Sha256::new();
    for (key_hash, value_hash) in hashes.iter() {
        hasher.update(&key_hash[..]);
        hasher.update(&value_hash[..]);
    }

    hasher.finalize().into()
}

fn hash_value(value: &Value) -> [u8; 32] {
    match value {
        Value::String(value) => hash(value.as_bytes()),
        Value::Number(value) => {
            let mut hasher = Sha256::new();
            leb128::write::unsigned(&mut hasher, value.to_owned()).unwrap();
            hasher.finalize().into()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_key_value_map() {
        let map: Vec<(String, Value)> = vec![
            ("name".into(), Value::String("foo".into())),
            ("message".into(), Value::String("Hello World!".into())),
            ("answer".into(), Value::Number(42)),
        ];
        let expected_hash =
            hex::decode("b0c6f9191e37dceafdfc47fbfc7e9cc95f21c7b985c2f7ba5855015c2a8f13ac")
                .unwrap();

        let result = representation_independent_hash(&map);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn handles_duplicate_keys() {
        let map: Vec<(String, Value)> = vec![
            ("name".into(), Value::String("foo".into())),
            ("name".into(), Value::String("bar".into())),
            ("message".into(), Value::String("Hello World!".into())),
        ];
        let expected_hash =
            hex::decode("435f77c9bdeca5dba4a4b8a34e4f732b4311f1fc252ec6d4e8ee475234b170f9")
                .unwrap();

        let result = representation_independent_hash(&map);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn hash_reordered_key_value_map() {
        let map: Vec<(String, Value)> = vec![
            ("name".into(), Value::String("foo".into())),
            ("message".into(), Value::String("Hello World!".into())),
            ("name".into(), Value::String("bar".into())),
        ];
        let reordered_map: Vec<(String, Value)> = vec![
            ("message".into(), Value::String("Hello World!".into())),
            ("name".into(), Value::String("bar".into())),
            ("name".into(), Value::String("foo".into())),
        ];

        let result = representation_independent_hash(&map);
        let reordered_result = representation_independent_hash(&reordered_map);

        assert_eq!(result, reordered_result);
    }
}
