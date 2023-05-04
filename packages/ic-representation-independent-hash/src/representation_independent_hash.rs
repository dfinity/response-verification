use crate::{hash, Sha256Digest};
use sha2::{Digest, Sha256};

/// Represents a value to be hashed. Only UTF-8 strings, bytes and unsigned numbers are currently supported.
#[derive(Debug, Clone)]
pub enum Value {
    /// An UTF-8 string to be hashed.
    String(String),
    /// A number to be hashed.
    Number(u64),
    Bytes(Vec<u8>),
}

/// A partial implementation of [`Representation Independent Hash`] that only supports
/// UTF-8 strings or numbers as values.
///
/// [`Representation Independent Hash`]: https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map
pub fn representation_independent_hash(map: &[(String, Value)]) -> Sha256Digest {
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

fn hash_value(value: &Value) -> Sha256Digest {
    match value {
        Value::String(value) => hash(value.as_bytes()),
        Value::Bytes(value) => hash(&value),
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

    #[test]
    fn hash_bytes() {
        let map: Vec<(String, Value)> =
            vec![("bytes".into(), Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]))];
        let expected_hash =
            hex::decode("546729666d96a712bd94f902a0388e33f9a19a335c35bc3d95b0221a4a574455")
                .unwrap();

        let result = representation_independent_hash(&map);

        assert_eq!(result, expected_hash.as_slice());
    }
}
