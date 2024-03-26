//! Various error types for response verification failure scenarios

use ic_cbor::CborError;
use ic_certificate_verification::CertificateVerificationError;
#[cfg(all(target_arch = "wasm32", feature = "js"))]
use wasm_bindgen::prelude::*;

use crate::cel;

/// Convenience type that represents the Result of performing response verification
pub type ResponseVerificationResult<T = ()> = Result<T, ResponseVerificationError>;

/// The primary container for response verification errors
#[derive(thiserror::Error, Debug)]
pub enum ResponseVerificationError {
    /// Error converting UTF-8 string
    #[error(r#"IO error: "{0}""#)]
    IoError(#[from] std::io::Error),

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

    /// The expression path provided by the "IC-Certificate" response header
    /// has an unexpected suffix and should end with "<$>" or "<*>"
    #[error(r#"The expression path provided by the "IC-Certificate" response header ({provided_expr_path:?}) has an unexpected prefix and should start with "http_expr"#)]
    UnexpectedExpressionPathPrefix {
        /// The invalid expression path
        provided_expr_path: Vec<String>,
    },

    /// The expression path provided by the "IC-Certificate" response header
    /// has an unexpected suffix and should end with "<$>" or "<*>"
    #[error(r#"The expression path provided by the "IC-Certificate" response header ({provided_expr_path:?}) has an unexpected suffix and should end with "<$>" or "<*>"#)]
    UnexpectedExpressionPathSuffix {
        /// The invalid expression path
        provided_expr_path: Vec<String>,
    },

    /// The exact expression path provided by the "IC-Certificate" response header
    /// was not found in the tree
    #[error(r#"The exact expression path provided by the "IC-Certificate" response header ({provided_expr_path:?}) was not found in the tree"#)]
    ExactExpressionPathNotFoundInTree {
        /// The missing expression path
        provided_expr_path: Vec<String>,
    },

    /// The exact expression path provided by the "IC-Certificate" response header
    /// is not valid for the request path
    #[error(r#"The exact expression path provided by the "IC-Certificate" response header ({provided_expr_path:?}) is not valid for the request path ({request_path:?})"#)]
    ExactExpressionPathMismatch {
        /// The expression path provided by the "IC-Certificate" response header
        provided_expr_path: Vec<String>,
        /// The request path
        request_path: String,
    },

    /// A wildcard expression path was provided by the "IC-Certificate" response header
    /// but a potential exact expression path is valid for the request path and might
    /// exist in the tree
    #[error(r#"A wildcard expression path was provided by the "IC-Certificate" response header ({provided_expr_path:?}), but a potential exact expression path ({potential_expr_path:?}) is valid for the request path ({request_path:?}) and might exist in the tree"#)]
    ExactExpressionPathMightExistInTree {
        /// The expression path provided by the "IC-Certificate" response header
        provided_expr_path: Vec<String>,
        /// The expected expression path
        potential_expr_path: Vec<String>,
        /// The request path
        request_path: String,
    },

    /// The wildcard expression path provided by the "IC-Certificate" response
    /// was not found in the tree
    #[error(r#"The wildcard expression path provided by the "IC-Certificate" response header ({provided_expr_path:?}) is valid for the request path ({request_path:?}), but was not found in the tree"#)]
    WildcardExpressionPathNotFoundInTree {
        /// The expression path provided by the "IC-Certificate" response header
        provided_expr_path: Vec<String>,
        /// The request path
        request_path: String,
    },

    /// The wildcard expression path provided by the "IC-Certificate" response
    /// header is not valid for the request path
    #[error(r#"The wildcard expression path provided by the "IC-Certificate" response header ({provided_expr_path:?}) is not valid for the request path ({request_path:?})"#)]
    WildcardExpressionPathMismatch {
        /// The expression path provided by the "IC-Certificate" response header
        provided_expr_path: Vec<String>,
        /// The request path
        request_path: String,
    },

    /// A more specific wildcard expression path than the one provided by the
    /// "IC-Certificate" response header that is valid for the request path might
    /// exist in the tree
    #[error(r#"A more specific wildcard expression path ({more_specific_expr_path:?}) than the one provided by the "IC-Certificate" response header ({provided_expr_path:?}) that is valid for the request path ({request_path:?}) might exist in the tree"#)]
    MoreSpecificWildcardExpressionMightExistInTree {
        /// The expression path provided by the "IC-Certificate" response header
        provided_expr_path: Vec<String>,
        /// The more specific expression path that might exist in the tree
        more_specific_expr_path: Vec<String>,
        /// The request path
        request_path: String,
    },

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

    /// Failed to decode CBOR
    #[error("CBOR decoding failed")]
    CborDecodingFailed(#[from] CborError),

    /// Failed to verify certificate
    #[error("Certificate verification failed")]
    CertificateVerificationFailed(#[from] CertificateVerificationError),

    /// HTTP Certification error
    #[error(r#"HTTP Certification error: "{0}""#)]
    HttpCertificationError(#[from] ic_http_certification::HttpCertificationError),
}

/// JS Representation of the ResponseVerificationError code
#[cfg(all(target_arch = "wasm32", feature = "js"))]
#[wasm_bindgen(js_name = ResponseVerificationErrorCode)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ResponseVerificationJsErrorCode {
    /// Error converting UTF-8 string
    IoError,
    /// An unsupported verification version was requested
    UnsupportedVerificationVersion,
    /// Mismatch between the minimum requested version and the actual requested version
    RequestedVerificationVersionMismatch,
    /// Error parsing CEL expression
    CelError,
    /// Error decoding base64
    Base64DecodingError,
    /// Error parsing int
    ParseIntError,
    /// The tree has different root hash from the expected value in the certified variables
    InvalidTree,
    /// The CEL expression path is invalid
    InvalidExpressionPath,
    /// The expression path provided by the "IC-Certificate" response header
    /// has an unexpected suffix and should end with "<$>" or "<*>"
    UnexpectedExpressionPathPrefix,
    /// The expression path provided by the "IC-Certificate" response header
    /// has an unexpected suffix and should end with "<$>" or "<*>"
    UnexpectedExpressionPathSuffix,
    /// The exact expression path provided by the "IC-Certificate" response header
    /// was not found in the tree
    ExactExpressionPathNotFoundInTree,
    /// The exact expression path provided by the "IC-Certificate" response header
    /// is not valid for the request path
    ExactExpressionPathMismatch,
    /// A wildcard expression path was provided by the "IC-Certificate" response header
    /// but a potential exact expression path is valid for the request path and might
    /// exist in the tree
    ExactExpressionPathMightExistInTree,
    /// The wildcard expression path provided by the "IC-Certificate" response
    /// was not found in the tree
    WildcardExpressionPathNotFoundInTree,
    /// The wildcard expression path provided by the "IC-Certificate" response
    /// header is not valid for the request path
    WildcardExpressionPathMismatch,
    /// A more specific wildcard expression path than the one provided by the
    /// "IC-Certificate" response header that is valid for the request path might
    /// exist in the tree
    MoreSpecificWildcardExpressionMightExistInTree,
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
    /// Failed to decode CBOR
    CborDecodingFailed,
    /// Failed to verify certificate
    CertificateVerificationFailed,
    /// HTTP Certification error
    HttpCertificationError,
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
            ResponseVerificationError::IoError(_) => ResponseVerificationJsErrorCode::IoError,
            ResponseVerificationError::UnsupportedVerificationVersion { .. } => {
                ResponseVerificationJsErrorCode::UnsupportedVerificationVersion
            }
            ResponseVerificationError::RequestedVerificationVersionMismatch { .. } => {
                ResponseVerificationJsErrorCode::RequestedVerificationVersionMismatch
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
            ResponseVerificationError::UnexpectedExpressionPathPrefix { .. } => {
                ResponseVerificationJsErrorCode::UnexpectedExpressionPathPrefix
            }
            ResponseVerificationError::UnexpectedExpressionPathSuffix { .. } => {
                ResponseVerificationJsErrorCode::UnexpectedExpressionPathSuffix
            }
            ResponseVerificationError::ExactExpressionPathNotFoundInTree { .. } => {
                ResponseVerificationJsErrorCode::ExactExpressionPathNotFoundInTree
            }
            ResponseVerificationError::ExactExpressionPathMismatch { .. } => {
                ResponseVerificationJsErrorCode::ExactExpressionPathMismatch
            }
            ResponseVerificationError::ExactExpressionPathMightExistInTree { .. } => {
                ResponseVerificationJsErrorCode::ExactExpressionPathMightExistInTree
            }
            ResponseVerificationError::WildcardExpressionPathNotFoundInTree { .. } => {
                ResponseVerificationJsErrorCode::WildcardExpressionPathNotFoundInTree
            }
            ResponseVerificationError::WildcardExpressionPathMismatch { .. } => {
                ResponseVerificationJsErrorCode::WildcardExpressionPathMismatch
            }
            ResponseVerificationError::MoreSpecificWildcardExpressionMightExistInTree {
                ..
            } => ResponseVerificationJsErrorCode::MoreSpecificWildcardExpressionMightExistInTree,
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
            ResponseVerificationError::CborDecodingFailed(_) => {
                ResponseVerificationJsErrorCode::CborDecodingFailed
            }
            ResponseVerificationError::CertificateVerificationFailed(_) => {
                ResponseVerificationJsErrorCode::CertificateVerificationFailed
            }
            ResponseVerificationError::HttpCertificationError(_) => {
                ResponseVerificationJsErrorCode::HttpCertificationError
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
    use crate::cel::CelParserError;
    use base64::{engine::general_purpose, Engine as _};
    use ic_http_certification::HttpCertificationError;
    use ic_response_verification_test_utils::hex_decode;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn error_into_http_certification_error() {
        let error = ResponseVerificationError::HttpCertificationError(
            HttpCertificationError::MalformedUrl("https://internetcomputer.org".into()),
        );
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::HttpCertificationError,
                message: r#"HTTP Certification error: "Failed to parse url: "https://internetcomputer.org"""#.into(),
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
    fn error_into_utf8_conversion_error() {
        let invalid_utf_bytes = hex_decode("fca1a1a1a1a1");
        let inner_error = String::from_utf8(invalid_utf_bytes).expect_err("Expected error");

        let error = ResponseVerificationError::HttpCertificationError(
            HttpCertificationError::Utf8ConversionError(inner_error.clone()),
        );

        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::HttpCertificationError,
                message: format!(
                    r#"HTTP Certification error: "Error converting UTF8 string bytes: "{0}"""#,
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
    fn error_into_unexpected_expression_path_prefix_error() {
        let error = ResponseVerificationError::UnexpectedExpressionPathPrefix {
            provided_expr_path: vec!["http_expr".into()],
        };
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::UnexpectedExpressionPathPrefix,
                message: format!(
                    r#"The expression path provided by the "IC-Certificate" response header (["http_expr"]) has an unexpected prefix and should start with "http_expr"#
                ),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_unexpected_expression_path_suffix_error() {
        let error = ResponseVerificationError::UnexpectedExpressionPathSuffix {
            provided_expr_path: vec!["http_expr".into()],
        };
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::UnexpectedExpressionPathSuffix,
                message: format!(
                    r#"The expression path provided by the "IC-Certificate" response header (["http_expr"]) has an unexpected suffix and should end with "<$>" or "<*>"#
                ),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_exact_expression_path_not_found_in_tree_error() {
        let error = ResponseVerificationError::ExactExpressionPathNotFoundInTree {
            provided_expr_path: vec!["http_expr".into()],
        };
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::ExactExpressionPathNotFoundInTree,
                message: format!(
                    r#"The exact expression path provided by the "IC-Certificate" response header (["http_expr"]) was not found in the tree"#
                ),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_exact_expression_path_mismatch_error() {
        let error = ResponseVerificationError::ExactExpressionPathMismatch {
            provided_expr_path: vec!["http_expr".into()],
            request_path: "/path".into(),
        };
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::ExactExpressionPathMismatch,
                message: format!(
                    r#"The exact expression path provided by the "IC-Certificate" response header (["http_expr"]) is not valid for the request path ("/path")"#
                ),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_exact_expression_path_might_exist_in_tree_error() {
        let error = ResponseVerificationError::ExactExpressionPathMightExistInTree {
            provided_expr_path: vec!["http_expr".into()],
            potential_expr_path: vec!["http_expr".into()],
            request_path: "/path".into(),
        };
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::ExactExpressionPathMightExistInTree,
                message: format!(
                    r#"A wildcard expression path was provided by the "IC-Certificate" response header (["http_expr"]), but a potential exact expression path (["http_expr"]) is valid for the request path ("/path") and might exist in the tree"#
                ),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_wildcard_expression_path_not_found_in_tree_error() {
        let error = ResponseVerificationError::WildcardExpressionPathNotFoundInTree {
            provided_expr_path: vec!["http_expr".into()],
            request_path: "/path".into(),
        };
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::WildcardExpressionPathNotFoundInTree,
                message: format!(
                    r#"The wildcard expression path provided by the "IC-Certificate" response header (["http_expr"]) is valid for the request path ("/path"), but was not found in the tree"#
                ),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_wildcard_expression_path_mismatch_error() {
        let error = ResponseVerificationError::WildcardExpressionPathMismatch {
            provided_expr_path: vec!["http_expr".into()],
            request_path: "/path".into(),
        };
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::WildcardExpressionPathMismatch,
                message: format!(
                    r#"The wildcard expression path provided by the "IC-Certificate" response header (["http_expr"]) is not valid for the request path ("/path")"#
                ),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_more_specific_wildcard_expression_might_exist_in_tree_error() {
        let error = ResponseVerificationError::MoreSpecificWildcardExpressionMightExistInTree {
            provided_expr_path: vec!["http_expr".into()],
            more_specific_expr_path: vec!["http_expr".into()],
            request_path: "/path".into(),
        };
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code:
                    ResponseVerificationJsErrorCode::MoreSpecificWildcardExpressionMightExistInTree,
                message: format!(
                    r#"A more specific wildcard expression path (["http_expr"]) than the one provided by the "IC-Certificate" response header (["http_expr"]) that is valid for the request path ("/path") might exist in the tree"#
                ),
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

    #[wasm_bindgen_test]
    fn error_into_cbor_decoding_failed_error() {
        let error = ResponseVerificationError::CborDecodingFailed(CborError::MalformedCbor(
            "HashTree CBOR is malformed".into(),
        ));
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::CborDecodingFailed,
                message: format!(r#"CBOR decoding failed"#),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_certificate_verification_failed_error() {
        let error = ResponseVerificationError::CertificateVerificationFailed(
            CertificateVerificationError::MissingTimePathInTree {
                path: vec![b"time".to_vec()],
            },
        );
        let result = ResponseVerificationJsError::from(error);

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::CertificateVerificationFailed,
                message: format!(r#"Certificate verification failed"#),
            }
        )
    }
}
