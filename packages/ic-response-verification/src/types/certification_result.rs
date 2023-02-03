use crate::types::Response;

#[cfg(all(target_arch = "wasm32", feature = "js"))]
use wasm_bindgen::prelude::*;

#[cfg(all(target_arch = "wasm32", feature = "js"))]
#[wasm_bindgen(typescript_custom_section)]
const CERTIFICATION_RESULT_TYPE: &'static str = r#"
interface CertificationResult {
  passed: boolean;
  response: Response;
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
    pub response: Option<Response>,
}

#[cfg(all(target_arch = "wasm32", feature = "js"))]
impl From<CertificationResult> for JsValue {
    fn from(certification_result: CertificationResult) -> Self {
        use js_sys::{Array, Boolean, Object};

        let passed = Boolean::from(certification_result.passed);
        let response = JsValue::from(certification_result.response);

        let passed_entry = Array::of2(&JsValue::from("passed"), &passed.into());
        let response_entry = Array::of2(&JsValue::from("response"), &response.into());

        let result = Object::from_entries(&Array::of2(&passed_entry, &response_entry)).unwrap();

        JsValue::from(result)
    }
}

#[cfg(all(target_arch = "wasm32", feature = "js", test))]
mod tests {
    use crate::types::{CertificationResult, Response};
    use js_sys::JSON;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn serialize_certification_result_with_no_response() {
        let expected = r#"{"passed":true}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(CertificationResult {
                passed: true,
                response: None
            }))
            .unwrap(),
            expected
        );
    }

    #[wasm_bindgen_test]
    fn serialize_certification_result_with_response() {
        let expected = r#"{"passed":true,"response":{"statusCode":200,"body":{"0":0,"1":1,"2":2},"headers":[]}}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(CertificationResult {
                passed: true,
                response: Some(Response {
                    status_code: 200,
                    body: vec![0, 1, 2],
                    headers: vec![],
                })
            }))
            .unwrap(),
            expected
        );
    }
}
