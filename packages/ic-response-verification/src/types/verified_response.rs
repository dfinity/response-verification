#[cfg(all(target_arch = "wasm32", feature = "js"))]
use wasm_bindgen::prelude::*;

#[cfg(all(target_arch = "wasm32", feature = "js"))]
#[wasm_bindgen(typescript_custom_section)]
const VERIFIED_RESPONSE: &'static str = r#"
interface VerifiedResponse {
    statusCode?: number;
    headers: [string, string][];
    body: Uint8Array;
}
"#;

/// Represents a certified Response from the [Internet Computer](https://internetcomputer.org).
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedResponse {
    /// The HTTP status code of the response, i.e. 200.
    pub status_code: Option<u16>,
    /// The HTTP headers of the request, i.e. \[\["Ic-Certificate", "certificate=:2dn3o2R0cmVlgw=:, tree=:2dn3gwGDA:"\]\]
    pub headers: Vec<(String, String)>,
    /// The body of the request as a candid decoded blob, i.e.  \[60, 33, 100, 111, 99\]
    pub body: Vec<u8>,
}

#[cfg(all(target_arch = "wasm32", feature = "js"))]
impl From<VerifiedResponse> for JsValue {
    fn from(response: VerifiedResponse) -> Self {
        use js_sys::{Array, Number, Object, Uint8Array};

        let body = Uint8Array::from(response.body.as_slice());

        let headers = Array::new();
        for (k, v) in response.headers.iter() {
            let value = JsValue::from(v);
            headers.push(&Array::of2(&k.into(), &value.into()));
        }

        let body_entry = Array::of2(&JsValue::from("body"), &body);
        let headers_entry = Array::of2(&JsValue::from("headers"), &headers);

        let js_response = match response.status_code {
            Some(status_code) => {
                let status_code = Number::from(status_code);
                let status_code_entry = Array::of2(&JsValue::from("statusCode"), &status_code);

                Object::from_entries(&Array::of3(&status_code_entry, &body_entry, &headers_entry))
                    .unwrap()
            }
            _ => Object::from_entries(&Array::of2(&body_entry, &headers_entry)).unwrap(),
        };

        JsValue::from(js_response)
    }
}

#[cfg(all(target_arch = "wasm32", feature = "js", test))]
mod tests {
    use super::*;
    use js_sys::JSON;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn serialize_response_with_headers() {
        let expected =
            r#"{"statusCode":200,"body":{"0":0,"1":1,"2":2},"headers":[["header1","header1val"]]}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(VerifiedResponse {
                status_code: Some(200),
                body: vec![0, 1, 2],
                headers: vec![("header1".into(), "header1val".into())],
            }))
            .unwrap(),
            expected
        );
    }

    #[wasm_bindgen_test]
    fn serialize_response_with_empty_headers() {
        let expected = r#"{"statusCode":200,"body":{"0":0,"1":1,"2":2},"headers":[]}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(VerifiedResponse {
                status_code: Some(200),
                body: vec![0, 1, 2],
                headers: vec![],
            }))
            .unwrap(),
            expected
        );
    }

    #[wasm_bindgen_test]
    fn serialize_response_without_status_code() {
        let expected = r#"{"body":{"0":0,"1":1,"2":2},"headers":[["header1","header1val"]]}"#;

        assert_eq!(
            JSON::stringify(&JsValue::from(VerifiedResponse {
                status_code: None,
                body: vec![0, 1, 2],
                headers: vec![("header1".into(), "header1val".into())],
            }))
            .unwrap(),
            expected
        );
    }
}
