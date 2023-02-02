use base64::{engine::general_purpose, Engine as _};
use serde::Serialize;

pub fn base64_encode<T>(data: &T) -> String
where
    T: AsRef<[u8]>,
{
    general_purpose::STANDARD.encode(data)
}

pub fn serialize_to_cbor<T: Serialize>(payload: &T) -> Vec<u8> {
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
