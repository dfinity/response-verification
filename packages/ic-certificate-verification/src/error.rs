use candid::Principal;
use ic_cbor::CborError;

/// Convenience type that represents the Result of performing certificate verification
pub type CertificateVerificationResult<T = ()> = Result<T, CertificateVerificationError>;

#[derive(thiserror::Error, Debug)]
pub enum CertificateVerificationError {
    /// Unexpected public key length
    #[error(
        "BLS DER-encoded public key must be {expected} bytes long, but is {actual} bytes long"
    )]
    DerKeyLengthMismatch {
        /// Expected size of the public key
        expected: usize,
        /// Actual size of the public key
        actual: usize,
    },

    /// Unexpected public key prefix
    #[error("BLS DER-encoded public key is invalid. Expected the following prefix: {expected:?}, but got {actual:?}")]
    DerPrefixMismatch {
        /// Expected public key prefix
        expected: Vec<u8>,
        /// Actual public key prefix
        actual: Vec<u8>,
    },

    /// The certificate's time was too far in the future
    #[error("Certificate time is too far in the future. Received {certificate_time:?}, expected {max_certificate_time:?} or earlier")]
    TimeTooFarInTheFuture {
        /// The actual certificate time
        certificate_time: u128,
        /// The maximum expected certificate time
        max_certificate_time: u128,
    },

    /// The certificate's time was too far in the past
    #[error("Certificate time is too far in the past. Received {certificate_time:?}, expected {min_certificate_time:?} or later")]
    TimeTooFarInThePast {
        /// The actual certificate time
        certificate_time: u128,
        /// The minimum expected certificate time
        min_certificate_time: u128,
    },

    /// Certificate is for a different subnet
    #[error(
        "Canister ID {canister_id} is not within the certificate's range: {canister_ranges:?}"
    )]
    PrincipalOutOfRange {
        /// The canister ID that was looked up in the certificate
        canister_id: Principal,
        /// The canister ID ranges that were found in the certificate
        canister_ranges: Vec<(Principal, Principal)>,
    },

    /// Certificate delegation is missing the required canister range
    #[error("Subnet canister ID ranges not found in certificate at path: {path:?}")]
    SubnetCanisterIdRangesNotFound {
        /// The path that was used to look up the canister ranges in the certificate
        path: Vec<Vec<u8>>,
    },

    /// Certificate delegation is missing the required public key
    #[error("Subnet public key not found in certificate at path: {path:?}")]
    SubnetPublicKeyNotFound {
        /// The path that was used to look up the public key in the certificate
        path: Vec<Vec<u8>>,
    },

    /// The certificate was expected to have a "time" path, but it was missing
    #[error(r#"Time not found in certificate at path: {path:?}"#)]
    MissingTimePathInTree {
        /// The path that was used to look up the time in the certificate
        path: Vec<Vec<u8>>,
    },

    /// Encountered an overflow error while decoding leb encoded timestamp
    #[error("Certificate time decoding failed due to an overflow: {timestamp:?}")]
    TimeDecodingFailed { timestamp: Vec<u8> },

    /// Failed to verify the certificate's signature
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Failed to decode CBOR
    #[error("CBOR decoding failed")]
    CborDecodingFailed(#[from] CborError),

    /// The certificate contained more than one delegation.
    #[error("The certificate contained more than one delegation")]
    CertificateHasTooManyDelegations,
}
