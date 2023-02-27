#[cfg(all(target_arch = "wasm32", feature = "js"))]
use wasm_bindgen::{prelude::*, JsCast};

#[cfg(all(target_arch = "wasm32", feature = "js"))]
#[wasm_bindgen(typescript_custom_section)]
const RESPONSE: &'static str = r#"
interface Response {
    statusCode: number;
    headers: [string, string][];
    body: Uint8Array;
}
"#;

/// Represents a Response from the [Internet Computer](https://internetcomputer.org).
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    /// The HTTP status code of the response, i.e. 200.
    pub status_code: u16,
    /// The HTTP headers of the request, i.e. \[\["Ic-Certificate", "certificate=:2dn3o2R0cmVlgw=:, tree=:2dn3gwGDA:"\]\]
    pub headers: Vec<(String, String)>,
    /// The body of the request as a candid decoded blob, i.e.  \[60, 33, 100, 111, 99\]
    pub body: Vec<u8>,
}

#[cfg(all(target_arch = "wasm32", feature = "js"))]
impl From<JsValue> for Response {
    fn from(resp: JsValue) -> Self {
        use js_sys::{Array, JsString, Number, Object, Uint8Array};

        let status_code_str = JsString::from("statusCode");
        let headers_str = JsString::from("headers");
        let body_str = JsString::from("body");

        let mut status_code: u16 = 0;
        let mut headers = Vec::new();
        let mut body = Vec::new();

        let resp = Object::unchecked_from_js(resp);
        for entry in Object::entries(&resp).iter() {
            let entry = Array::unchecked_from_js(entry);
            let k = JsString::unchecked_from_js(entry.get(0));

            if k == status_code_str {
                status_code = Number::unchecked_from_js(entry.get(1)).as_f64().unwrap() as u16;
            }

            if k == headers_str {
                let headers_v = Array::unchecked_from_js(entry.get(1));
                let headers_v = headers_v.iter();
                headers = Vec::with_capacity(headers_v.len());
                for header in headers_v {
                    let header = Array::unchecked_from_js(header);
                    let header_name = header.get(0).as_string().unwrap();
                    let header_val = header.get(1).as_string().unwrap();
                    headers.push((header_name, header_val))
                }
            }

            if k == body_str {
                body = Uint8Array::unchecked_from_js(entry.get(1)).to_vec();
            }
        }

        Self {
            status_code,
            headers,
            body,
        }
    }
}

#[cfg(all(target_arch = "wasm32", feature = "js", test))]
mod tests {
    use super::*;
    use js_sys::JSON;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn request_from() {
        let v = JSON::parse(
            r#"{
                "statusCode": 200,
                "body": [0, 1, 2, 3, 4, 5, 6],
                "headers": [
                    ["header1", "header1val"],
                    ["header2", "header2val"]
                ]
            }"#,
        )
        .expect("failed to parse JSON");
        let r = Response::from(v);

        assert_eq!(
            r,
            Response {
                status_code: 200,
                body: vec![0, 1, 2, 3, 4, 5, 6],
                headers: vec![
                    ("header1".into(), "header1val".into()),
                    ("header2".into(), "header2val".into()),
                ],
            }
        );
    }
}
