#[cfg(target_arch = "wasm32")]
use wasm_bindgen::{JsCast, prelude::*};


#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(typescript_custom_section)]
const RESPONSE: &'static str = r#"
interface Response {
    headers: [string, string][];
}
"#;

/// Represents a Response from the IC
#[derive(Debug, PartialEq, Eq)]
pub struct Response {
    pub headers: Vec<(String, String)>,
}

#[cfg(target_arch = "wasm32")]
impl From<JsValue> for Response {
    fn from(req: JsValue) -> Self {
        use js_sys::{Array, Object, JsString};

        let headers_str = JsString::from("headers");

        let req = Object::unchecked_from_js(req);
        let mut headers = Vec::new();
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
        }
        Self{
            headers
        }
    }
}

#[cfg(all(target_arch = "wasm32", test))]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;
    use super::*;
    use js_sys::JSON;

    #[wasm_bindgen_test]
    fn request_from() {
        let v = JSON::parse(r#"{
    "headers": [
        ["header1", "header1val"],
        ["header2", "header2val"]
    ]
}"#).expect("failed to parse JSON");
        let r = Response::from(v);

        assert_eq!(r, Response{
            headers: vec![
                ("header1".into(), "header1val".into()),
                ("header2".into(), "header2val".into()),
            ],
        });
    }
}