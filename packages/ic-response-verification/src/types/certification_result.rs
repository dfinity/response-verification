use crate::types::CertifiedResponse;

#[cfg(all(target_arch = "wasm32", feature = "js"))]
use wasm_bindgen::prelude::*;

#[cfg(all(target_arch = "wasm32", feature = "js"))]
#[wasm_bindgen(typescript_custom_section)]
const CERTIFICATION_RESULT_TYPE: &'static str = r#"
interface CertificationResult {
  passed: boolean;
  response: CertifiedResponse;
  verificationVersion: number;
}
"#;

/// Result of verifying the provided request/response pair's certification.
#[derive(Debug, Eq, PartialEq)]
pub struct CertificationResult {
    /// True if verification was successful, false otherwise.
    pub passed: bool,
    /// Response object including the status code, body and headers that were included in the
    /// certification and passed verification. If verification failed then this object will be
    /// empty.
    pub response: Option<CertifiedResponse>,
    /// The version of verification that was used to verify the response
    pub verification_version: u16,
}

#[cfg(all(target_arch = "wasm32", feature = "js"))]
impl From<CertificationResult> for JsValue {
    fn from(certification_result: CertificationResult) -> Self {
        use js_sys::{Array, Boolean, Number, Object};

        let passed = Boolean::from(certification_result.passed);
        let response = JsValue::from(certification_result.response);

        let passed_entry = Array::of2(&JsValue::from("passed"), &passed.into());
        let response_entry = Array::of2(&JsValue::from("response"), &response.into());

        let verification_version = Number::from(certification_result.verification_version);
        let verification_version_entry =
            Array::of2(&JsValue::from("verificationVersion"), &verification_version);

        let result = Object::from_entries(&Array::of3(
            &passed_entry,
            &response_entry,
            &verification_version_entry,
        ))
        .unwrap();

        JsValue::from(result)
    }
}

#[cfg(all(target_arch = "wasm32", feature = "js", test))]
mod tests {
    use crate::types::{CertificationResult, CertifiedResponse};
    use js_sys::JSON;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn serialize_certification_result_with_no_response() {
        let expected = r#"{"passed":true,"verificationVersion":1}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(CertificationResult {
                passed: true,
                response: None,
                verification_version: 1,
            }))
            .unwrap(),
            expected
        );
    }

    #[wasm_bindgen_test]
    fn serialize_certification_result_with_response() {
        let expected = r#"{"passed":true,"response":{"statusCode":200,"body":{"0":0,"1":1,"2":2},"headers":[]},"verificationVersion":2}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(CertificationResult {
                passed: true,
                response: Some(CertifiedResponse {
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
