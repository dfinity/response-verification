use ic_crypto_sha::Sha256;

pub fn hash(stuff: Vec<String>) -> [u8; 32] {
    let mut hashes = Vec::new();

    for s in stuff {
        let h: [u8; 32] = Sha256::hash(s.as_bytes());
        hashes.push(h);
    }

    hashes.sort();

    let mut hasher = Sha256::new();
    for hash in hashes {
        hasher.write(&hash);
    }

    // Concatenate domain with representation-independent hash.
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let things = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let expected = [
            70, 196, 207, 59, 233, 6, 50, 50, 5, 224, 124, 186, 253, 173, 126, 137, 39, 87, 17,
            145, 33, 156, 158, 72, 176, 82, 221, 201, 6, 212, 68, 149,
        ];
        assert_eq!(hash(things), expected);
    }
}
