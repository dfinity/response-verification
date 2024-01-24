//! # Representation Independent Hash

#![deny(missing_docs, missing_debug_implementations, rustdoc::all, clippy::all)]

/// Type alias for a SHA-256 hash.
pub type Sha256Digest = [u8; 32];

mod representation_independent_hash;
pub use representation_independent_hash::*;

use sha2::{Digest, Sha256};

/// Calculates the SHA-256 hash of the given slice.
pub fn hash(data: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_text() {
        let text = "Hello World!";
        let expected_hash: Sha256Digest = [
            127, 131, 177, 101, 127, 241, 252, 83, 185, 45, 193, 129, 72, 161, 214, 93, 252, 45,
            75, 31, 163, 214, 119, 40, 74, 221, 210, 0, 18, 109, 144, 105,
        ];

        let result = hash(text.as_bytes());

        assert_eq!(result, expected_hash);
    }
}
