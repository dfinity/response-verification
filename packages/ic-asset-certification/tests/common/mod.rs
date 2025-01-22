use ic_asset_certification::ASSET_CHUNK_SIZE;
use ic_response_verification_test_utils::hash;
use rand_chacha::{
    rand_core::{RngCore, SeedableRng},
    ChaCha20Rng,
};

pub fn asset_chunk(asset_body: &[u8], chunk_number: usize) -> &[u8] {
    let start = chunk_number * ASSET_CHUNK_SIZE;
    let end = start + ASSET_CHUNK_SIZE;
    &asset_body[start..end.min(asset_body.len())]
}

pub fn asset_body(asset_name: &str, asset_size: usize) -> Vec<u8> {
    let mut rng = ChaCha20Rng::from_seed(hash(asset_name));
    let mut body = vec![0u8; asset_size];
    rng.fill_bytes(&mut body);

    body
}

#[macro_export]
macro_rules! assert_contains {
    ($vec:expr, $elems:expr) => {
        for elem in $elems {
            assert!(
                $vec.contains(&elem),
                "assertion failed: Expected vector {:?} to contain element {:?}",
                $vec,
                elem
            );
        }
    };
}

#[macro_export]
macro_rules! assert_response_eq {
    ($actual:expr, $expected:expr) => {
        let actual: &ic_http_certification::HttpResponse = &$actual;
        let expected: &ic_http_certification::HttpResponse = &$expected;

        assert_eq!(actual.status_code(), expected.status_code());
        assert_eq!(actual.body(), expected.body());
        assert_contains!(actual.headers(), expected.headers());
    };
}

#[macro_export]
macro_rules! assert_verified_response_eq {
    ($actual:expr, $expected:expr) => {
        let actual: &ic_response_verification::types::VerifiedResponse = &$actual;
        let expected: &ic_http_certification::HttpResponse = &$expected;

        assert_eq!(actual.status_code, Some(expected.status_code().as_u16()));
        assert_eq!(actual.body, expected.body());
        assert_contains!(actual.headers, expected.headers());
    };
}
