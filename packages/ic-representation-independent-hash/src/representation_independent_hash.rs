use crate::{hash, Sha256Digest};
use sha2::{Digest, Sha256};

/// Represents a value to be hashed. Only UTF-8 strings, bytes, unsigned numbers, and arrays are currently supported.
#[derive(Debug, Clone)]
pub enum Value {
    /// An UTF-8 string to be hashed.
    String(String),
    /// A number to be hashed.
    Number(u64),
    /// Bytes to be hashed.
    Bytes(Vec<u8>),
    /// An array of values to be hashed.
    Array(Vec<Value>),
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
        Value::Bytes(value) => hash(value),
        Value::Number(value) => {
            let mut hasher = Sha256::new();
            leb128::write::unsigned(&mut hasher, value.to_owned()).unwrap();
            hasher.finalize().into()
        }
        Value::Array(elements) => hash_array(elements),
    }
}

// Arrays are hashed by hashing the concatenation of the hashes of the array elements.
fn hash_array(elements: &[Value]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    elements
        .iter()
        // Hash the encoding of all the array elements.
        .for_each(|e| hasher.update(&hash_value(e)[..]));
    hasher.finalize().into() // hash the concatenation of the hashes.
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

    fn from_hex(hex: &str) -> Vec<u8> {
        hex::decode(hex).unwrap()
    }

    #[test]
    fn hash_array_reference_1() {
        let array = vec![Value::String("a".to_string())];
        // hash(hash("a"))
        let expected = from_hex("bf5d3affb73efd2ec6c36ad3112dd933efed63c4e1cbffcfa88e2759c144f2d8");
        assert_eq!(hash_array(&array), expected.as_slice());
        assert_eq!(hash_value(&Value::Array(array)), expected.as_slice());
    }

    #[test]
    fn hash_array_reference_2() {
        let array = vec![
            Value::String("a".to_string()),
            Value::String("b".to_string()),
        ];
        // hash(concat(hash("a"), hash("b"))
        let expected = from_hex("e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a");
        assert_eq!(hash_array(&array), expected.as_slice());
        assert_eq!(hash_value(&Value::Array(array)), expected.as_slice());
    }

    #[test]
    fn hash_array_reference_3() {
        let array = vec![
            Value::Bytes(vec![97]), // "a" as a byte string.
            Value::String("b".to_string()),
        ];
        // hash(concat(hash("a"), hash("b"))
        let expected = from_hex("e5a01fee14e0ed5c48714f22180f25ad8365b53f9779f79dc4a3d7e93963f94a");
        assert_eq!(hash_array(&array), expected.as_slice());
        assert_eq!(hash_value(&Value::Array(array)), expected.as_slice());
    }

    #[test]
    fn hash_array_reference_4() {
        let array = vec![Value::Array(vec![Value::String("a".to_string())])];
        // hash(hash(hash("a"))
        let expected = from_hex("eb48bdfa15fc43dbea3aabb1ee847b6e69232c0f0d9705935e50d60cce77877f");
        assert_eq!(hash_array(&array), expected.as_slice());
        assert_eq!(hash_value(&Value::Array(array)), expected.as_slice());
    }

    #[test]
    fn hash_array_reference_5() {
        let array = vec![Value::Array(vec![
            Value::String("a".to_string()),
            Value::String("b".to_string()),
        ])];
        // hash(hash(concat(hash("a"), hash("b")))
        let expected = from_hex("029fd80ca2dd66e7c527428fc148e812a9d99a5e41483f28892ef9013eee4a19");
        assert_eq!(hash_array(&array), expected.as_slice());
        assert_eq!(hash_value(&Value::Array(array)), expected.as_slice());
    }

    #[test]
    fn hash_array_reference_6() {
        let array = vec![
            Value::Array(vec![
                Value::String("a".to_string()),
                Value::String("b".to_string()),
            ]),
            Value::Bytes(vec![97]), // "a" in bytes
        ];
        // hash(concat(hash(concat(hash("a"), hash("b")), hash(100))
        let expected = from_hex("aec3805593d9ec6df50da070597f73507050ce098b5518d0456876701ada7bb7");
        assert_eq!(hash_array(&array), expected.as_slice());
        assert_eq!(hash_value(&Value::Array(array)), expected.as_slice());
    }
}
