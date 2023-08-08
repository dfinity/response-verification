use crate::types::VerifiedResponse;

#[cfg(all(target_arch = "wasm32", feature = "js"))]
use wasm_bindgen::prelude::*;

#[cfg(all(target_arch = "wasm32", feature = "js"))]
#[wasm_bindgen(typescript_custom_section)]
const VERIFICATION_RESULT: &'static str = r#"
type VerificationInfo = {
  response?: VerifiedResponse;
  verificationVersion: number;
}
"#;

/// Result of verifying the provided request/response pair's certification.
#[derive(Debug)]
pub struct VerificationInfo {
    /// Response object including the status code, body and headers that were included in the
    /// certification and passed verification. If verification failed then this object will be
    /// empty.
    pub response: Option<VerifiedResponse>,
    /// The version of verification that was used to verify the response
    pub verification_version: u16,
}

#[cfg(all(target_arch = "wasm32", feature = "js"))]
impl From<VerificationInfo> for JsValue {
    fn from(verification_result: VerificationInfo) -> Self {
        use js_sys::{Array, Number, Object};

        let verification_version = Number::from(verification_result.verification_version);
        let verification_version_entry =
            Array::of2(&JsValue::from("verificationVersion"), &verification_version);

        let response = JsValue::from(verification_result.response);
        let response_entry = Array::of2(&JsValue::from("response"), &response.into());

        let result =
            Object::from_entries(&Array::of2(&response_entry, &verification_version_entry))
                .unwrap();

        JsValue::from(result)
    }
}

#[cfg(all(target_arch = "wasm32", feature = "js", test))]
mod tests {
    use super::*;
    use js_sys::JSON;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn serialize_verification_result_with_no_response() {
        let expected = r#"{"verificationVersion":1}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(VerificationInfo {
                response: None,
                verification_version: 1,
            }))
            .unwrap(),
            expected
        );
    }

    #[wasm_bindgen_test]
    fn serialize_verification_result_with_response() {
        let expected = r#"{"response":{"statusCode":200,"body":{"0":0,"1":1,"2":2},"headers":[]},"verificationVersion":2}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(VerificationInfo {
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
}
