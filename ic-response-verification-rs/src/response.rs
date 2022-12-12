#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{prelude::*, JsCast};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(typescript_custom_section)]
const RESPONSE: &'static str = r#"
interface Response {
    body: Uint8Array;
    headers: [string, string][];
}
"#;

/// Represents a Response from the IC
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

#[cfg(target_arch = "wasm32")]
impl From<JsValue> for Response {
    fn from(req: JsValue) -> Self {
        use js_sys::{Array, JsString, Object, Uint8Array};

        let headers_str = JsString::from("headers");
        let body_str = JsString::from("body");

        let mut headers = Vec::new();
        let mut body = Vec::new();

        let req = Object::unchecked_from_js(req);
        for entry in Object::entries(&req).iter() {
            let entry = Array::unchecked_from_js(entry);
            let k = JsString::unchecked_from_js(entry.get(0));

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

        Self { headers, body }
    }
}

#[cfg(all(target_arch = "wasm32", test))]
mod tests {
    use super::*;
    use js_sys::JSON;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn request_from() {
        let v = JSON::parse(
            r#"{
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
                body: vec![0, 1, 2, 3, 4, 5, 6],
                headers: vec![
                    ("header1".into(), "header1val".into()),
                    ("header2".into(), "header2val".into()),
                ],
            }
        );
    }
}
