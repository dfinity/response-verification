#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::cel;

pub type ResponseVerificationResult<T = ()> = Result<T, ResponseVerificationError>;

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

    #[error(r#"Certificate is missing the "time" path"#)]
    MissingTimePathInTree,

    #[error("Certificate time is too far in the future. Received {certificate_time:?}, expected {max_certificate_time:?} or earlier")]
    CertificateTimeTooFarInTheFuture {
        certificate_time: u128,
        max_certificate_time: u128,
    },

    #[error("Certificate time is too far in the past. Received {certificate_time:?}, expected {min_certificate_time:?} or later")]
    CertificateTimeTooFarInThePast {
        certificate_time: u128,
        min_certificate_time: u128,
    },

    /// The CBOR was malformed and could not be parsed correctly
    #[error(r#"Invalid cbor: "{0}""#)]
    MalformedCbor(String),

    #[error(r#"Expected node with name {node_name:?} to have type {expected_type:?}, found {found_type:?}"#)]
    UnexpectedCborNodeType {
        node_name: String,
        expected_type: String,
        found_type: String,
    },

    /// The hash tree pruned data was not the correct length
    #[error(r#"Invalid pruned data: "{0}""#)]
    IncorrectPrunedDataLength(#[from] std::array::TryFromSliceError),

    #[error("Overflow while decoding leb")]
    LebDecodingOverflow,

    #[error(r#"Error converting UTF8 string bytes: "{0}""#)]
    Utf8ConversionError(#[from] std::string::FromUtf8Error),

    #[error(r#"The requested verification version {requested_version:?} is not supported, the current supported range is {min_supported_version:?}-{max_supported_version:?}"#)]
    UnsupportedVerificationVersion {
        min_supported_version: u8,
        max_supported_version: u8,
        requested_version: u8,
    },

    #[error("Cel parser error")]
    CelError(#[from] cel::CelParserError),
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = ResponseVerificationErrorCode)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ResponseVerificationJsErrorCode {
    MalformedUrl,
    MalformedHashTree,
    MalformedCertificate,
    MissingTimePathInTree,
    CertificateTimeTooFarInTheFuture,
    CertificateTimeTooFarInThePast,
    MalformedCbor,
    UnexpectedCborNodeType,
    IncorrectPrunedDataLength,
    LebDecodingOverflow,
    Utf8ConversionError,
    UnsupportedVerificationVersion,
    CelError,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(inspectable, js_name = ResponseVerificationError)]
#[derive(Debug, Eq, PartialEq)]
pub struct ResponseVerificationJsError {
    #[wasm_bindgen(readonly)]
    pub code: ResponseVerificationJsErrorCode,

    #[wasm_bindgen(getter_with_clone, readonly)]
    pub message: String,
}

#[cfg(target_arch = "wasm32")]
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
            ResponseVerificationError::CelError(_) => ResponseVerificationJsErrorCode::CelError,
        };
        let message = error.to_string();

        ResponseVerificationJsError {
            code: code.into(),
            message,
        }
    }
}

#[cfg(all(target_arch = "wasm32", test))]
mod tests {
    use super::*;
    use crate::{cel::CelParserError, test_utils::test_utils::hex_decode};
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
}
