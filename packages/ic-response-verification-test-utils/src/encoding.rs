use base64::{engine::general_purpose, Engine as _};
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;
use serde::Serialize;
use std::io::Write;

pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

pub fn hex_decode(data: &str) -> Vec<u8> {
    hex::decode(data).unwrap()
}

pub fn cbor_encode<T: Serialize>(payload: &T) -> Vec<u8> {
    let mut serializer = serde_cbor::Serializer::new(Vec::new());
    serializer.self_describe().unwrap();
    payload.serialize(&mut serializer).unwrap();
    serializer.into_inner()
}

pub fn leb_encode_timestamp(timestamp: u128) -> Vec<u8> {
    let mut encoded_time = vec![];
    leb128::write::unsigned(&mut encoded_time, timestamp as u64).unwrap();
    encoded_time
}

pub fn gzip_encode(data: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();

    encoder.finish().unwrap()
}

pub fn deflate_encode(data: &[u8]) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).unwrap();

    encoder.finish().unwrap()
}
