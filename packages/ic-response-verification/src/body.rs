use flate2::read::{DeflateDecoder, GzDecoder};
use ic_certification::hash_tree::Sha256Digest;
use sha2::{Digest, Sha256};
use std::io::Read;

// The limit of a buffer we should decompress ~10mb.
const MAX_CHUNK_SIZE_TO_DECOMPRESS: usize = 1024;
const MAX_CHUNKS_TO_DECOMPRESS: u64 = 10_240;

pub fn decode_body_to_sha256(body: &[u8], encoding: Option<String>) -> Option<Sha256Digest> {
    return match encoding.as_deref() {
        Some("gzip") => decode_body(GzDecoder::new(body)),
        Some("deflate") => decode_body(DeflateDecoder::new(body)),
        _ => {
            let mut sha256 = Sha256::new();
            sha256.update(body);
            Some(sha256.finalize().into())
        }
    };
}

fn decode_body<D: Read>(mut decoder: D) -> Option<Sha256Digest> {
    let mut sha256 = Sha256::new();
    let mut decoded = [0u8; MAX_CHUNK_SIZE_TO_DECOMPRESS];

    for _ in 0..MAX_CHUNKS_TO_DECOMPRESS {
        let bytes = decoder.read(&mut decoded).ok()?;

        if bytes == 0 {
            return Some(sha256.finalize().into());
        }

        sha256.update(&decoded[0..bytes]);
    }

    if decoder.bytes().next().is_some() {
        // [TODO] throw "body too big" exception here
        return None;
    }

    Some(sha256.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_utils::hex_decode;
    use flate2::write::{DeflateEncoder, GzEncoder};
    use flate2::Compression;
    use std::io::Write;

    const BODY: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
    const BODY_SHA: &str = "66840dda154e8a113c31dd0ad32f7f3a366a80e8136979d8f5a101d3d29d6f72";

    #[test]
    fn decode_simple_body() {
        let result = decode_body_to_sha256(BODY, None).unwrap();
        let expected = hex_decode(BODY_SHA);

        assert_eq!(result, expected.as_slice());
    }

    #[test]
    fn decode_gzip_body() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(BODY).unwrap();
        let encoded_body = encoder.finish().unwrap();

        let result = decode_body_to_sha256(encoded_body.as_slice(), Some("gzip".into())).unwrap();
        let expected = hex_decode(BODY_SHA);

        assert_eq!(result, expected.as_slice());
    }

    #[test]
    fn decode_deflate_body() {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(BODY).unwrap();
        let encoded_body = encoder.finish().unwrap();

        let result =
            decode_body_to_sha256(encoded_body.as_slice(), Some("deflate".into())).unwrap();
        let expected = hex_decode(BODY_SHA);

        assert_eq!(result, expected.as_slice());
    }
}
