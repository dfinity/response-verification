use crate::error::{CertificationTestError, CertificationTestResult};
use serde::Serialize;

pub(crate) fn serialize_to_cbor<T: Serialize>(payload: &T) -> Vec<u8> {
    let mut serializer = serde_cbor::Serializer::new(Vec::new());
    serializer.self_describe().unwrap();
    payload.serialize(&mut serializer).unwrap();
    serializer.into_inner()
}

pub(crate) fn leb_encode_timestamp(timestamp: u128) -> CertificationTestResult<Vec<u8>> {
    let mut encoded_time = vec![];

    leb128::write::unsigned(&mut encoded_time, timestamp as u64)
        .map_err(|_| CertificationTestError::TimestampLebEncodingFailed)?;

    Ok(encoded_time)
}
