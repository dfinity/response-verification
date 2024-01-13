use ic_crypto_internal_threshold_sig_bls12381::api::threshold_sign_error::ClibThresholdSignError;
use ic_crypto_tree_hash::TreeHashError;
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Error, Debug)]
pub enum CertificationTestError {
    #[error("could not hash tree")]
    UnableToHashTree,

    #[error("could not generate witness")]
    WitnessGenerationFailed,

    #[error("could not sign message")]
    ThresholdSigningFailed,

    #[error("could not serialize certificate to cbor")]
    CertificateSerializationFailed,

    #[error("could not leb encode timestamp")]
    TimestampLebEncodingFailed,

    #[error("could not parse canister ID")]
    CanisterIdParsingFailed,

    #[error("could not encode public key")]
    PublicKeyEncodingFailed,

    #[error("one of canister params or a custom tree must be provided")]
    CanisterParamsOrCustomTreeRequired,

    #[error("only one of canister params or a custom tree may be provided")]
    BothCanisterParamsAndCustomTreeProvided,

    #[error("failed to merge witnesses")]
    WitnessMergingFailed,
}

impl From<TreeHashError> for CertificationTestError {
    fn from(_: TreeHashError) -> Self {
        CertificationTestError::UnableToHashTree
    }
}

impl From<ClibThresholdSignError> for CertificationTestError {
    fn from(_: ClibThresholdSignError) -> Self {
        CertificationTestError::ThresholdSigningFailed
    }
}

impl From<serde_wasm_bindgen::Error> for CertificationTestError {
    fn from(_: serde_wasm_bindgen::Error) -> Self {
        CertificationTestError::CertificateSerializationFailed
    }
}

pub type CertificationTestResult<T = ()> = Result<T, CertificationTestError>;
