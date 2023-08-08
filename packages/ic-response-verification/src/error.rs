//! Various error types for response verification failure scenarios

#[cfg(all(target_arch = "wasm32", feature = "js"))]
use wasm_bindgen::prelude::*;

use crate::cel;

/// Convenience type that represents the Result of performing response verification
pub type ResponseVerificationResult<T = ()> = Result<T, ResponseVerificationError>;

/// The primary container for response verification errors
#[derive(thiserror::Error, Debug)]
pub enum ResponseVerificationError {
    /// The URL was malformed and could not be parsed correctly
    #[error(r#"Failed to parse url: "{0}""#)]
    MalformedUrl(String),

    /// The hash tree was malformed and could not be parsed correctly
    #[error(r#"Failed to parse hash tree: "{0}""#)]
    MalformedHashTree(String),

    /// The certificate was malformed and could not be parsed correctly
    #[error(r#"Failed to parse certificate: "{0}""#)]
    MalformedCertificate(String),

    /// The certificate was expected to have a "time" path, but it was missing
    #[error(r#"Certificate is missing the "time" path"#)]
    MissingTimePathInTree,

    /// Error converting UTF-8 string
    #[error(r#"IO error: "{0}""#)]
    IoError(#[from] std::io::Error),

    /// The certificate's time was too far in the future
    #[error("Certificate time is too far in the future. Received {certificate_time:?}, expected {max_certificate_time:?} or earlier")]
    CertificateTimeTooFarInTheFuture {
        /// The actual certificate time
        certificate_time: u128,
        /// The maximum expected certificate time
        max_certificate_time: u128,
    },

    /// The certificate's time was too far in the past
    #[error("Certificate time is too far in the past. Received {certificate_time:?}, expected {min_certificate_time:?} or later")]
    CertificateTimeTooFarInThePast {
        /// The actual certificate time
        certificate_time: u128,
        /// The minimum expected certificate time
        min_certificate_time: u128,
    },

    /// The CBOR was malformed and could not be parsed correctly
    #[error(r#"Invalid cbor: "{0}""#)]
    MalformedCbor(String),

    /// The Cbor parser expected a node of a certain type but found a different type
    #[error(r#"Expected node with name {node_name:?} to have type {expected_type:?}, found {found_type:?}"#)]
    UnexpectedCborNodeType {
        /// The name of the node with the incorrect type
        node_name: String,
        /// The expected type of the node
        expected_type: String,
        /// The actual type of the node
        found_type: String,
    },

    /// The hash tree pruned data was not the correct length
    #[error(r#"Invalid pruned data: "{0}""#)]
    IncorrectPrunedDataLength(#[from] std::array::TryFromSliceError),

    /// Encountered an overflow error while decoding leb encoded timestamp
    #[error("Overflow while decoding leb")]
    LebDecodingOverflow,

    /// Error converting UTF-8 string
    #[error(r#"Error converting UTF8 string bytes: "{0}""#)]
    Utf8ConversionError(#[from] std::string::FromUtf8Error),

    /// An unsupported verification version was requested
    #[error(r#"The requested verification version {requested_version:?} is not supported, the current supported range is {min_supported_version:?}-{max_supported_version:?}"#)]
    UnsupportedVerificationVersion {
        /// The minimum supported verification version
        min_supported_version: u8,
        /// The maximum supported verification version
        max_supported_version: u8,
        /// The actual requested verification version
        requested_version: u8,
    },

    /// Mismatch between the minimum requested version and the actual requested version
    #[error(r#"The requested verification version {requested_version:?} is lower than the minimum requested version {min_requested_verification_version:?}"#)]
    RequestedVerificationVersionMismatch {
        /// The minimum version that will be requested
        min_requested_verification_version: u8,
        /// The actual requested version
        requested_version: u8,
    },

    /// Error parsing CEL expression
    #[error("Cel parser error")]
    CelError(#[from] cel::CelParserError),

    /// Unexpected public key length
    #[error(
        r#"BLS DER-encoded public key must be {expected} bytes long, but is {actual} bytes long"#
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

    /// Failed to verify the certificate
    #[error("Certificate verification failed")]
    CertificateVerificationFailed,

    /// Certificate is for a different canister
    #[error("Certificate verification failed with principal out of range")]
    CertificatePrincipalOutOfRange,

    /// Certificate delegation is missing the required public key
    #[error("Certificate verification subnet public key not found")]
    CertificateSubnetPublicKeyNotFound,

    /// Certificate delegation is missing the required canister range
    #[error("Certificate verification subnet canister ranges not found")]
    CertificateSubnetCanisterRangesNotFound,

    /// Certificate delegation canister range was not correctly CBOR encoded
    #[error("Invalid cbor canister ranges")]
    MalformedCborCanisterRanges,

    /// Error decoding base64
    #[error("Base64 decoding error")]
    Base64DecodingError(#[from] base64::DecodeError),

    /// Error parsing int
    #[error("Error parsing int")]
    ParseIntError(#[from] std::num::ParseIntError),

    /// The tree has different root hash from the expected value in the certified variables
    #[error("Invalid tree root hash")]
    InvalidTree,

    /// The CEL expression path is invalid
    #[error("Invalid expression path")]
    InvalidExpressionPath,

    /// The response body was a mismatch from the expected values in the tree
    #[error("Invalid response body")]
    InvalidResponseBody,

    /// The response hashes were a mismatch from the expected values in the tree
    #[error("Invalid response hashes")]
    InvalidResponseHashes,

    /// The certificate was missing from the certification header
    #[error("Certificate not found")]
    MissingCertificate,

    /// The tree was missing from the certification header
    #[error("Tree not found")]
    MissingTree,

    /// The certificate expression path was missing from the certification header
    #[error("Certificate expression path not found")]
    MissingCertificateExpressionPath,

    /// The certificate expression was missing from the response headers
    #[error("Certificate expression not found")]
    MissingCertificateExpression,

    /// The certification values could not be found in the response headers
    #[error("Certification values not found")]
    MissingCertification,
}

/// JS Representation of the ResponseVerificationError code
#[cfg(all(target_arch = "wasm32", feature = "js"))]
#[wasm_bindgen(js_name = ResponseVerificationErrorCode)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ResponseVerificationJsErrorCode {
    /// The URL was malformed and could not be parsed correctly
    MalformedUrl,
    /// The hash tree was malformed and could not be parsed correctly
    MalformedHashTree,
    /// The certificate was malformed and could not be parsed correctly
    MalformedCertificate,
    /// The certificate was expected to have a "time" path, but it was missing
    MissingTimePathInTree,
    /// Error converting UTF-8 string
    IoError,
    /// The certificate's time was too far in the future
    CertificateTimeTooFarInTheFuture,
    /// The certificate's time was too far in the past
    CertificateTimeTooFarInThePast,
    /// The CBOR was malformed and could not be parsed correctly
    MalformedCbor,
    /// The Cbor parser expected a node of a certain type but found a different type
    UnexpectedCborNodeType,
    /// The hash tree pruned data was not the correct length
    IncorrectPrunedDataLength,
    /// Encountered an overflow error while decoding leb encoded timestamp
    LebDecodingOverflow,
    /// Error converting UTF-8 string
    Utf8ConversionError,
    /// An unsupported verification version was requested
    UnsupportedVerificationVersion,
    /// Mismatch between the minimum requested version and the actual requested version
    RequestedVerificationVersionMismatch,
    /// Error parsing CEL expression
    CelError,
    /// Unexpected public key length
    DerKeyLengthMismatch,
    /// Unexpected public key prefix
    DerPrefixMismatch,
    /// Failed to verify the certificate
    CertificateVerificationFailed,
    /// Certificate is for a different canister
    CertificatePrincipalOutOfRange,
    /// Certificate delegation is missing the required public key
    CertificateSubnetPublicKeyNotFound,
    /// Certificate delegation is missing the required canister range
    CertificateSubnetCanisterRangesNotFound,
    /// Certificate delegation canister range was not correctly CBOR encoded
    MalformedCborCanisterRanges,
    /// Error decoding base64
    Base64DecodingError,
    /// Error parsing int
    ParseIntError,
    /// The tree has different root hash from the expected value in the certified variables
    InvalidTree,
    /// The CEL expression path is invalid
    InvalidExpressionPath,
    /// The response body was a mismatch from the expected values in the tree
    InvalidResponseBody,
    /// The response hashes were a mismatch from the expected values in the tree
    InvalidResponseHashes,
    /// The certificate was missing from the certification header
    MissingCertificate,
    /// The tree was missing from the certification header
    MissingTree,
    /// The certificate expression path was missing from the certification header
    MissingCertificateExpressionPath,
    /// The certificate expression was missing from the response headers
    MissingCertificateExpression,
    /// The certification values could not be found in the response headers
    MissingCertification,
}

/// JS Representation of the ResponseVerificationError
#[cfg(all(target_arch = "wasm32", feature = "js"))]
#[wasm_bindgen(inspectable, js_name = ResponseVerificationError)]
#[derive(Debug, Eq, PartialEq)]
pub struct ResponseVerificationJsError {
    /// Error code as an enum
    #[wasm_bindgen(readonly)]
    pub code: ResponseVerificationJsErrorCode,

    /// Stringified error message
    #[wasm_bindgen(getter_with_clone, readonly)]
    pub message: String,
}

#[cfg(all(target_arch = "wasm32", feature = "js"))]
impl From<ResponseVerificationError> for ResponseVerificationJsError {
    fn from(error: ResponseVerificationError) -> ResponseVerificationJsError {
        let code = match error {
            ResponseVerificationError::MalformedUrl(_) => {
                ResponseVerificationJsErrorCode::MalformedUrl
            }
            ResponseVerificationError::MalformedHashTree(_) => {
                ResponseVerificationJsErrorCode::MalformedHashTree
            }
            ResponseVerificationError::MalformedCertificate(_) => {
                ResponseVerificationJsErrorCode::MalformedCertificate
            }
            ResponseVerificationError::MissingTimePathInTree => {
                ResponseVerificationJsErrorCode::MissingTimePathInTree
            }
            ResponseVerificationError::IoError(_) => ResponseVerificationJsErrorCode::IoError,
            ResponseVerificationError::CertificateTimeTooFarInTheFuture { .. } => {
                ResponseVerificationJsErrorCode::CertificateTimeTooFarInTheFuture
            }
            ResponseVerificationError::CertificateTimeTooFarInThePast { .. } => {
                ResponseVerificationJsErrorCode::CertificateTimeTooFarInThePast
            }
            ResponseVerificationError::MalformedCbor(_) => {
                ResponseVerificationJsErrorCode::MalformedCbor
            }
            ResponseVerificationError::UnexpectedCborNodeType { .. } => {
                ResponseVerificationJsErrorCode::UnexpectedCborNodeType
            }
            ResponseVerificationError::IncorrectPrunedDataLength(_) => {
                ResponseVerificationJsErrorCode::IncorrectPrunedDataLength
            }
            ResponseVerificationError::LebDecodingOverflow { .. } => {
                ResponseVerificationJsErrorCode::LebDecodingOverflow
            }
            ResponseVerificationError::Utf8ConversionError { .. } => {
                ResponseVerificationJsErrorCode::Utf8ConversionError
            }
            ResponseVerificationError::UnsupportedVerificationVersion { .. } => {
                ResponseVerificationJsErrorCode::UnsupportedVerificationVersion
            }
            ResponseVerificationError::RequestedVerificationVersionMismatch { .. } => {
                ResponseVerificationJsErrorCode::RequestedVerificationVersionMismatch
            }
            ResponseVerificationError::DerPrefixMismatch { .. } => {
                ResponseVerificationJsErrorCode::DerPrefixMismatch
            }
            ResponseVerificationError::DerKeyLengthMismatch { .. } => {
                ResponseVerificationJsErrorCode::DerKeyLengthMismatch
            }
            ResponseVerificationError::CertificateVerificationFailed { .. } => {
                ResponseVerificationJsErrorCode::CertificateVerificationFailed
            }
            ResponseVerificationError::CertificatePrincipalOutOfRange { .. } => {
                ResponseVerificationJsErrorCode::CertificatePrincipalOutOfRange
            }
            ResponseVerificationError::CertificateSubnetPublicKeyNotFound { .. } => {
                ResponseVerificationJsErrorCode::CertificateSubnetPublicKeyNotFound
            }
            ResponseVerificationError::CertificateSubnetCanisterRangesNotFound { .. } => {
                ResponseVerificationJsErrorCode::CertificateSubnetCanisterRangesNotFound
            }
            ResponseVerificationError::MalformedCborCanisterRanges { .. } => {
                ResponseVerificationJsErrorCode::MalformedCborCanisterRanges
            }
            ResponseVerificationError::CelError(_) => ResponseVerificationJsErrorCode::CelError,
            ResponseVerificationError::Base64DecodingError(_) => {
                ResponseVerificationJsErrorCode::Base64DecodingError
            }
            ResponseVerificationError::ParseIntError(_) => {
                ResponseVerificationJsErrorCode::ParseIntError
            }
            ResponseVerificationError::InvalidTree => ResponseVerificationJsErrorCode::InvalidTree,
            ResponseVerificationError::InvalidExpressionPath => {
                ResponseVerificationJsErrorCode::InvalidExpressionPath
            }
            ResponseVerificationError::InvalidResponseBody => {
                ResponseVerificationJsErrorCode::InvalidResponseBody
            }
            ResponseVerificationError::InvalidResponseHashes => {
                ResponseVerificationJsErrorCode::InvalidResponseHashes
            }
            ResponseVerificationError::MissingCertificate => {
                ResponseVerificationJsErrorCode::MissingCertificate
            }
            ResponseVerificationError::MissingTree => ResponseVerificationJsErrorCode::MissingTree,
            ResponseVerificationError::MissingCertificateExpressionPath => {
                ResponseVerificationJsErrorCode::MissingCertificateExpressionPath
            }
            ResponseVerificationError::MissingCertificateExpression => {
                ResponseVerificationJsErrorCode::MissingCertificateExpression
            }
            ResponseVerificationError::MissingCertification => {
                ResponseVerificationJsErrorCode::MissingCertification
            }
        };
        let message = error.to_string();

        ResponseVerificationJsError {
            code: code.into(),
            message,
        }
    }
}

#[cfg(all(target_arch = "wasm32", feature = "js", test))]
mod tests {
    use super::*;
    use crate::{cel::CelParserError, test_utils::test_utils::hex_decode};
    use base64::{engine::general_purpose, Engine as _};
    use std::array::TryFromSliceError;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn error_into_invalid_url() {
        let error = ResponseVerificationError::MalformedUrl("https://internetcomputer.org".into());

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MalformedUrl,
                message: r#"Failed to parse url: "https://internetcomputer.org""#.into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_hash_tree() {
        let error = ResponseVerificationError::MalformedHashTree(
            "Missing ByteString for Pruned node".into(),
        );

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MalformedHashTree,
                message: r#"Failed to parse hash tree: "Missing ByteString for Pruned node""#
                    .into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_certificate() {
        let error = ResponseVerificationError::MalformedCertificate(
            "Expected Tree when parsing Certificate Cbor".into(),
        );

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MalformedCertificate,
                message:
                    r#"Failed to parse certificate: "Expected Tree when parsing Certificate Cbor""#
                        .into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_missing_time_path_in_tree() {
        let error = ResponseVerificationError::MissingTimePathInTree;

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MissingTimePathInTree,
                message: r#"Certificate is missing the "time" path"#.into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_io_error() {
        let inner_error = std::fs::File::open("foo.txt").expect_err("Expected error");
        let error_msg = inner_error.to_string();

        let error = ResponseVerificationError::IoError(inner_error);

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::IoError,
                message: format!(r#"IO error: "{}""#, error_msg),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_certificate_time_too_far_in_the_future() {
        let error = ResponseVerificationError::CertificateTimeTooFarInTheFuture {
            certificate_time: 1000,
            max_certificate_time: 500,
        };

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::CertificateTimeTooFarInTheFuture,
                message: "Certificate time is too far in the future. Received 1000, expected 500 or earlier".into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_certificate_time_too_far_in_the_past() {
        let error = ResponseVerificationError::CertificateTimeTooFarInThePast {
            certificate_time: 500,
            min_certificate_time: 1000,
        };

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::CertificateTimeTooFarInThePast,
                message:
                    "Certificate time is too far in the past. Received 500, expected 1000 or later"
                        .into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_malformed_cbor() {
        let error = ResponseVerificationError::MalformedCbor("Unexpected EOF reached".into());

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MalformedCbor,
                message: r#"Invalid cbor: "Unexpected EOF reached""#.into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_unexpected_cbor_node_type() {
        let error = ResponseVerificationError::UnexpectedCborNodeType {
            node_name: "Foo".into(),
            found_type: "Bar".into(),
            expected_type: "Baz".into(),
        };

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::UnexpectedCborNodeType,
                message: r#"Expected node with name "Foo" to have type "Baz", found "Bar""#.into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_incorrect_pruned_data_length() {
        let incorrectly_sized_data: &[u8] = &[0u8];
        let conversion_attempt: Result<[u8; 10], TryFromSliceError> =
            TryFrom::try_from(incorrectly_sized_data);
        let inner_error = conversion_attempt.expect_err("Expected error");

        let error = ResponseVerificationError::IncorrectPrunedDataLength(inner_error);

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::IncorrectPrunedDataLength,
                message: format!(r#"Invalid pruned data: "{}""#, inner_error.to_string()),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_leb_decoding_overflow() {
        let error = ResponseVerificationError::LebDecodingOverflow;

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::LebDecodingOverflow,
                message: "Overflow while decoding leb".into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_utf8_conversion_error() {
        let invalid_utf_bytes = hex_decode("fca1a1a1a1a1");
        let inner_error = String::from_utf8(invalid_utf_bytes).expect_err("Expected error");

        let error = ResponseVerificationError::Utf8ConversionError(inner_error.clone());

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::Utf8ConversionError,
                message: format!(
                    r#"Error converting UTF8 string bytes: "{0}""#,
                    inner_error.to_string()
                ),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_unsupported_verification_version() {
        let error = ResponseVerificationError::UnsupportedVerificationVersion {
            min_supported_version: 1,
            max_supported_version: 2,
            requested_version: 42,
        };

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::UnsupportedVerificationVersion,
                message: r#"The requested verification version 42 is not supported, the current supported range is 1-2"#.into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_verification_version_mismatch() {
        let error = ResponseVerificationError::RequestedVerificationVersionMismatch {
            min_requested_verification_version: 2,
            requested_version: 1,
        };

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::RequestedVerificationVersionMismatch,
                message: r#"The requested verification version 1 is lower than the minimum requested version 2"#.into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_cel_error() {
        let inner_error = CelParserError::CelSyntaxException(
            "Garbage is not allowed in the CEL expression!".into(),
        );
        let error = ResponseVerificationError::from(inner_error);

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::CelError,
                message: r#"Cel parser error"#.into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_der_prefix_mismatch() {
        let error = ResponseVerificationError::DerPrefixMismatch {
            actual: vec![1, 2, 4],
            expected: vec![1, 2, 3],
        };

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::DerPrefixMismatch,
                message: "BLS DER-encoded public key is invalid. Expected the following prefix: [1, 2, 3], but got [1, 2, 4]".into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_der_key_length_mismatch() {
        let error = ResponseVerificationError::DerKeyLengthMismatch {
            actual: 10,
            expected: 11,
        };

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::DerKeyLengthMismatch,
                message: "BLS DER-encoded public key must be 11 bytes long, but is 10 bytes long"
                    .into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_certificate_verification_failed() {
        let error = ResponseVerificationError::CertificateVerificationFailed;

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::CertificateVerificationFailed,
                message: "Certificate verification failed".into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_certificate_principal_out_of_range() {
        let error = ResponseVerificationError::CertificatePrincipalOutOfRange;

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::CertificatePrincipalOutOfRange,
                message: "Certificate verification failed with principal out of range".into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_certificate_subnet_public_key_not_found() {
        let error = ResponseVerificationError::CertificateSubnetPublicKeyNotFound;

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::CertificateSubnetPublicKeyNotFound,
                message: "Certificate verification subnet public key not found".into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_certificate_subnet_canister_ranges_not_found() {
        let error = ResponseVerificationError::CertificateSubnetCanisterRangesNotFound;

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::CertificateSubnetCanisterRangesNotFound,
                message: "Certificate verification subnet canister ranges not found".into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_malformed_cbor_canister_ranges() {
        let error = ResponseVerificationError::MalformedCborCanisterRanges;

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MalformedCborCanisterRanges,
                message: "Invalid cbor canister ranges".into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_base64_decoding_error() {
        let invalid_base64 = hex_decode("fca1a1a1a1a1");
        let inner_error = general_purpose::STANDARD
            .decode(invalid_base64)
            .expect_err("Expected error");

        let error = ResponseVerificationError::Base64DecodingError(inner_error);

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::Base64DecodingError,
                message: format!(r#"Base64 decoding error"#),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_parse_int_error() {
        let invalid_int = "fortytwo";
        let inner_error = invalid_int.parse::<u8>().expect_err("Expected error");

        let error = ResponseVerificationError::ParseIntError(inner_error);

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::ParseIntError,
                message: format!(r#"Error parsing int"#),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_tree_error() {
        let error = ResponseVerificationError::InvalidTree;
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::InvalidTree,
                message: format!(r#"Invalid tree root hash"#),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_expression_path_error() {
        let error = ResponseVerificationError::InvalidExpressionPath;
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::InvalidExpressionPath,
                message: format!(r#"Invalid expression path"#),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_response_body_error() {
        let error = ResponseVerificationError::InvalidResponseBody;
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::InvalidResponseBody,
                message: format!(r#"Invalid response body"#),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_response_hashes_error() {
        let error = ResponseVerificationError::InvalidResponseHashes;
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::InvalidResponseHashes,
                message: format!(r#"Invalid response hashes"#),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_missing_certificate_error() {
        let error = ResponseVerificationError::MissingCertificate;
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MissingCertificate,
                message: format!(r#"Certificate not found"#),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_missing_tree_error() {
        let error = ResponseVerificationError::MissingTree;
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MissingTree,
                message: format!(r#"Tree not found"#),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_missing_certificate_expr_path_error() {
        let error = ResponseVerificationError::MissingCertificateExpressionPath;
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MissingCertificateExpressionPath,
                message: format!(r#"Certificate expression path not found"#),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_missing_certificate_expr_error() {
        let error = ResponseVerificationError::MissingCertificateExpression;
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MissingCertificateExpression,
                message: format!(r#"Certificate expression not found"#),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_missing_certification_error() {
        let error = ResponseVerificationError::MissingCertification;
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MissingCertification,
                message: format!(r#"Certification values not found"#),
            }
        )
    }
}
