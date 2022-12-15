#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[derive(thiserror::Error, Debug)]
pub enum ResponseVerificationError {
    /// The provided URL was invalid
    #[error(r#"Invalid url: "{0}""#)]
    InvalidUrl(String),

    /// The parsed hash tree was invalid
    #[error(r#"Invalid hash tree: "{0}""#)]
    InvalidHashTree(String),

    /// The parsed certificate was invalid
    #[error(r#"Invalid certificate: "{0}""#)]
    InvalidCertificate(String),

    /// The cbor was invalid
    #[error(r#"Invalid cbor: "{0}""#)]
    InvalidCbor(String),

    /// The hash tree pruned data was not valid
    #[error(r#"Invalid pruned data: "{0}""#)]
    InvalidPrunedData(#[from] std::array::TryFromSliceError),
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = ResponseVerificationErrorCode)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ResponseVerificationJsErrorCode {
    InvalidUrl,
    InvalidHashTree,
    InvalidCertificate,
    InvalidCbor,
    InvalidPrunedData,
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
impl Into<ResponseVerificationJsError> for ResponseVerificationError {
    fn into(self) -> ResponseVerificationJsError {
        let code = match self {
            ResponseVerificationError::InvalidUrl(_) => ResponseVerificationJsErrorCode::InvalidUrl,
            ResponseVerificationError::InvalidHashTree(_) => {
                ResponseVerificationJsErrorCode::InvalidHashTree
            }
            ResponseVerificationError::InvalidCertificate(_) => {
                ResponseVerificationJsErrorCode::InvalidCertificate
            }
            ResponseVerificationError::InvalidCbor(_) => {
                ResponseVerificationJsErrorCode::InvalidCbor
            }
            ResponseVerificationError::InvalidPrunedData(_) => {
                ResponseVerificationJsErrorCode::InvalidPrunedData
            }
        };
        let message = self.to_string();

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
        let error = ResponseVerificationError::InvalidUrl("https://internetcomputer.org".into());

        let result: ResponseVerificationJsError = error.into();

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::InvalidUrl,
                message: r#"Invalid url: "https://internetcomputer.org""#.into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_hash_tree() {
        let error =
            ResponseVerificationError::InvalidHashTree("Missing ByteString for Pruned node".into());

        let result: ResponseVerificationJsError = error.into();

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::InvalidHashTree,
                message: r#"Invalid hash tree: "Missing ByteString for Pruned node""#.into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_certificate() {
        let error = ResponseVerificationError::InvalidCertificate(
            "Expected Tree when parsing Certificate Cbor".into(),
        );

        let result: ResponseVerificationJsError = error.into();

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::InvalidCertificate,
                message: r#"Invalid certificate: "Expected Tree when parsing Certificate Cbor""#
                    .into(),
            }
        )
    }

    #[wasm_bindgen_test]
    fn error_into_invalid_cbor() {
        let error = ResponseVerificationError::InvalidCbor("Unexpected EOF reached".into());

        let result: ResponseVerificationJsError = error.into();

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::InvalidCbor,
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

        let error = ResponseVerificationError::InvalidPrunedData(inner_error);

        let result: ResponseVerificationJsError = error.into();

        assert_eq!(
            result,
            ResponseVerificationJsError {
                code: ResponseVerificationJsErrorCode::InvalidPrunedData,
                message: format!(r#"Invalid pruned data: "{}""#, inner_error.to_string()).into(),
            }
        )
    }
}
