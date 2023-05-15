use crate::{types::VerifiedResponse, ResponseVerificationError};

#[cfg(all(target_arch = "wasm32", feature = "js"))]
use wasm_bindgen::prelude::*;

#[cfg(all(target_arch = "wasm32", feature = "js"))]
use crate::{ResponseVerificationJsError};

#[cfg(all(target_arch = "wasm32", feature = "js"))]
#[wasm_bindgen(typescript_custom_section)]
const VERIFICATION_RESULT: &'static str = r#"
type VerificationResult = {
  passed: true;
  response?: VerifiedResponse;
  verificationVersion: number;
} | {
  passed: false;
  verificationVersion: number;
  reason: ResponseVerificationError;
}
"#;

/// Result of verifying the provided request/response pair's certification.
#[derive(Debug)]
pub enum VerificationResult {
    /// Verification passed
    Passed {
        /// Response object including the status code, body and headers that were included in the
        /// certification and passed verification. If verification failed then this object will be
        /// empty.
        response: Option<VerifiedResponse>,
        /// The version of verification that was used to verify the response
        verification_version: u16,
    },
    /// Verification failed
    Failed {
        /// The version of verification that was used to verify the response
        verification_version: u16,
        /// The reason why the verification of the response has failed
        reason: ResponseVerificationError,
    },
}

#[cfg(all(target_arch = "wasm32", feature = "js"))]
impl From<VerificationResult> for JsValue {
    fn from(verification_result: VerificationResult) -> Self {
        use js_sys::{Array, Boolean, Number, Object};

        let result = match verification_result {
            VerificationResult::Failed {
                verification_version,
                reason,
            } => {
                let passed = Boolean::from(false);
                let passed_entry = Array::of2(&JsValue::from("passed"), &passed.into());

                let verification_version = Number::from(verification_version);
                let verification_version_entry =
                    Array::of2(&JsValue::from("verificationVersion"), &verification_version);


                let reason = JsValue::from(ResponseVerificationJsError::from(reason));
                let reason_entry = Array::of2(&JsValue::from("reason"), &reason.into());

                Object::from_entries(&Array::of3(
                    &passed_entry,
                    &verification_version_entry,
                    &reason_entry,
                ))
                .unwrap()
            }
            VerificationResult::Passed {
                verification_version,
                response,
            } => {
                let passed = Boolean::from(true);
                let passed_entry = Array::of2(&JsValue::from("passed"), &passed.into());

                let verification_version = Number::from(verification_version);
                let verification_version_entry =
                    Array::of2(&JsValue::from("verificationVersion"), &verification_version);

                let response = JsValue::from(response);
                let response_entry = Array::of2(&JsValue::from("response"), &response.into());

                Object::from_entries(&Array::of3(
                    &passed_entry,
                    &response_entry,
                    &verification_version_entry,
                ))
                .unwrap()
            }
        };

        JsValue::from(result)
    }
}

#[cfg(all(target_arch = "wasm32", feature = "js", test))]
mod tests {
    use crate::ResponseVerificationError;
    use crate::types::{VerificationResult, VerifiedResponse};
    use js_sys::JSON;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn serialize_verification_result_with_no_response() {
        let expected = r#"{"passed":true,"verificationVersion":1}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(VerificationResult::Passed {
                response: None,
                verification_version: 1,
            }))
            .unwrap(),
            expected
        );
    }

    #[wasm_bindgen_test]
    fn serialize_verification_result_with_response() {
        let expected = r#"{"passed":true,"response":{"statusCode":200,"body":{"0":0,"1":1,"2":2},"headers":[]},"verificationVersion":2}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(VerificationResult::Passed {
                response: Some(VerifiedResponse {
                    status_code: Some(200),
                    body: vec![0, 1, 2],
                    headers: vec![],
                }),
                verification_version: 2,
            }))
            .unwrap(),
            expected
        );
    }

    #[wasm_bindgen_test]
    fn serialize_failed_verification_result() {
        let expected = r#"{"passed":false,"verificationVersion":2,"reason":{"code":27,"message":"Invalid response hashes"}}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(VerificationResult::Failed {
                verification_version: 2,
                reason: ResponseVerificationError::InvalidResponseHashes
            }))
            .unwrap(),
            expected
        );
    }
}
