#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

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

    /// The CBOR was malformed and could not be parsed correctly
    #[error(r#"Invalid cbor: "{0}""#)]
    MalformedCbor(String),

    /// The hash tree pruned data was not the correct length
    #[error(r#"Invalid pruned data: "{0}""#)]
    IncorrectPrunedDataLength(#[from] std::array::TryFromSliceError),
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = ResponseVerificationErrorCode)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ResponseVerificationJsErrorCode {
    MalformedUrl,
    MalformedHashTree,
    MalformedCertificate,
    MalformedCbor,
    IncorrectPrunedDataLength,
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
            ResponseVerificationError::MalformedCbor(_) => {
                ResponseVerificationJsErrorCode::MalformedCbor
            }
            ResponseVerificationError::IncorrectPrunedDataLength(_) => {
                ResponseVerificationJsErrorCode::IncorrectPrunedDataLength
            }
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
    use std::array::TryFromSliceError;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn error_into_invalid_url() {
        let error = ResponseVerificationError::MalformedUrl("https://internetcomputer.org".into());

        let result: ResponseVerificationJsError = error.into();

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

        let result: ResponseVerificationJsError = error.into();

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

        let result: ResponseVerificationJsError = error.into();

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
    fn error_into_invalid_cbor() {
        let error = ResponseVerificationError::MalformedCbor("Unexpected EOF reached".into());

        let result: ResponseVerificationJsError = error.into();

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::MalformedCbor,
                message: r#"Invalid cbor: "Unexpected EOF reached""#.into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_pruned_data() {
        let incorrectly_sized_data: &[u8] = &[0u8];
        let conversion_attempt: Result<[u8; 10], TryFromSliceError> =
            TryFrom::try_from(incorrectly_sized_data);
        let inner_error = conversion_attempt.expect_err("Expected error");

        let error = ResponseVerificationError::IncorrectPrunedDataLength(inner_error);

        let result: ResponseVerificationJsError = error.into();

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::IncorrectPrunedDataLength,
                message: format!(r#"Invalid pruned data: "{}""#, inner_error.to_string()).into(),
            }
        )
    }
}
