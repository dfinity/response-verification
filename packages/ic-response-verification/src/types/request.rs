use crate::error::{ResponseVerificationError, ResponseVerificationResult};
use http::Uri;

#[cfg(all(target_arch = "wasm32", feature = "js"))]
use wasm_bindgen::{prelude::*, JsCast};

#[cfg(all(target_arch = "wasm32", feature = "js"))]
#[wasm_bindgen(typescript_custom_section)]
const REQUEST: &'static str = r#"
interface Request {
    method: String;
    url: String;
    headers: [string, string][];
}
"#;

/// Represents a Request from the [Internet Computer](https://dfinity.org).
#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    /// The HTTP method of the request, i.e. "GET".
    pub method: String,
    /// The URL of the request, i.e. "/".
    pub url: String,
    /// The HTTP headers of the request, i.e. \[\["Host", "rdmx6-jaaaa-aaaaa-aaadq-cai.ic0.app"\]\]
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub(crate) fn get_uri(&self) -> ResponseVerificationResult<Uri> {
        self.url
            .parse::<Uri>()
            .map_err(|_| ResponseVerificationError::MalformedUrl(self.url.clone()))
    }
}

#[cfg(all(target_arch = "wasm32", feature = "js"))]
impl From<JsValue> for Request {
    fn from(req: JsValue) -> Self {
        use js_sys::{Array, JsString, Object};

        let method_str = JsString::from("method");
        let url_str = JsString::from("url");
        let headers_str = JsString::from("headers");

        let mut method = String::from("");
        let mut url = String::from("");
        let mut headers = Vec::new();

        let req = Object::unchecked_from_js(req);
        for entry in Object::entries(&req).iter() {
            let entry = Array::unchecked_from_js(entry);
            let k = JsString::unchecked_from_js(entry.get(0));

            if k == method_str {
                method = JsString::unchecked_from_js(entry.get(1))
                    .as_string()
                    .unwrap();
            }

            if k == url_str {
                url = JsString::unchecked_from_js(entry.get(1))
                    .as_string()
                    .unwrap();
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
        }

        Self {
            method,
            url,
            headers,
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
    "method": "GET",
    "url": "http://url.com",
    "headers": [
        ["header1", "header1val"],
        ["header2", "header2val"]
    ]
}"#,
        )
        .expect("failed to parse JSON");
        let r = Request::from(v);

        assert_eq!(
            r,
            Request {
                method: "GET".into(),
                url: "http://url.com".into(),
                headers: vec![
                    ("header1".into(), "header1val".into()),
                    ("header2".into(), "header2val".into()),
                ],
            }
        );
    }
}
