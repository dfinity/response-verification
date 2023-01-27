use flate2::read::{DeflateDecoder, GzDecoder};
use std::io::Read;

// The limit of a buffer we should decompress ~10mb.
const MAX_CHUNK_SIZE_TO_DECOMPRESS: usize = 1024;
const MAX_CHUNKS_TO_DECOMPRESS: u64 = 10_240;

pub fn decode_body(body: &Vec<u8>, encoding: &Option<String>) -> Option<Vec<u8>> {
    return match encoding.as_deref() {
        Some("gzip") => body_from_decoder(GzDecoder::new(body.as_slice())),
        Some("deflate") => body_from_decoder(DeflateDecoder::new(body.as_slice())),
        _ => Some(body.to_owned()),
    };
}

fn body_from_decoder<D: Read>(mut decoder: D) -> Option<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut buffer = [0u8; MAX_CHUNK_SIZE_TO_DECOMPRESS];

    for _ in 0..MAX_CHUNKS_TO_DECOMPRESS {
        let bytes = decoder.read(&mut buffer).ok()?;

        if bytes == 0 {
            return Some(decoded);
        }

        decoded.extend_from_slice(&buffer[..bytes]);
    }

    if decoder.bytes().next().is_some() {
        // [TODO] throw "body too big" exception here
        return None;
    }

    Some(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::{DeflateEncoder, GzEncoder};
    use flate2::Compression;
    use std::io::Write;

    const BODY: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];

    #[test]
    fn decode_simple_body() {
        let result = decode_body(&BODY.into(), &None).unwrap();

        assert_eq!(result.as_slice(), BODY);
    }

    #[test]
    fn decode_gzip_body() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(BODY).unwrap();
        let encoded_body = encoder.finish().unwrap();

        let result = decode_body(&encoded_body, &Some("gzip".into())).unwrap();

        assert_eq!(result.as_slice(), BODY);
    }

    #[test]
    fn decode_deflate_body() {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(BODY).unwrap();
        let encoded_body = encoder.finish().unwrap();

        let result = decode_body(&encoded_body, &Some("deflate".into())).unwrap();

        assert_eq!(result.as_slice(), BODY);
    }
}
