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
    body: Uint8Array;
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
    /// The body of the request as an array of bytes, i.e. \[60, 33, 100, 111, 99\]
    pub body: Vec<u8>,
}

impl Request {
    pub(crate) fn get_uri(&self) -> ResponseVerificationResult<Uri> {
        let uri = self
            .url
            .parse::<Uri>()
            .map_err(|_| ResponseVerificationError::MalformedUrl(self.url.clone()))?;

        // When decoding a URL the path and query string need to be handled differently, this allows for
        // clients to send encoded URL paths that would match the same decoded URL path but the query string can
        // still remain encoded.
        let authority = uri
            .authority()
            .map_or(String::new(), |authority| authority.to_string());
        let scheme_with_delimiter = uri
            .scheme_str()
            .map_or(String::new(), |s| format!("{}://", s));
        let decoded_path = urlencoding::decode(uri.path())?;
        let query_string = uri
            .query()
            .map(|query| format!("?{}", query))
            .unwrap_or_default();

        let decoded_url = format!(
            "{}{}{}{}",
            scheme_with_delimiter, authority, decoded_path, query_string
        );

        decoded_url
            .parse::<Uri>()
            .map_err(|_| ResponseVerificationError::MalformedUrl(self.url.clone()))
    }
}

#[cfg(all(target_arch = "wasm32", feature = "js"))]
impl From<JsValue> for Request {
    fn from(req: JsValue) -> Self {
        use js_sys::{Array, JsString, Object, Uint8Array};

        let method_str = JsString::from("method");
        let url_str = JsString::from("url");
        let headers_str = JsString::from("headers");
        let body_str = JsString::from("body");

        let mut method = String::from("");
        let mut url = String::from("");
        let mut headers = Vec::new();
        let mut body = Vec::new();

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

            if k == body_str {
                body = Uint8Array::unchecked_from_js(entry.get(1)).to_vec();
            }
        }

        Self {
            method,
            url,
            headers,
            body,
        }
    }
}

#[cfg(all(not(target_arch = "wasm32"), test))]
mod tests {
    use super::*;

    #[test]
    fn request_get_uri() {
        let req = Request {
            method: "GET".to_string(),
            url: "https://canister.com/sample-asset.txt".to_string(),
            headers: vec![],
            body: vec![],
        };

        let uri = req.get_uri().unwrap();

        assert_eq!(uri.path(), "/sample-asset.txt");
    }

    #[test]
    fn request_get_encoded_uri() {
        let test_requests = [
            (
                Request {
                    method: "GET".to_string(),
                    url: "https://canister.com/%73ample-asset.txt".to_string(),
                    headers: vec![],
                    body: vec![],
                },
                "/sample-asset.txt",
                "",
            ),
            (
                Request {
                    method: "GET".to_string(),
                    url: "https://canister.com/path/123?foo=test%20component&bar=1".to_string(),
                    headers: vec![],
                    body: vec![],
                },
                "/path/123",
                "foo=test%20component&bar=1",
            ),
        ];

        for (req, expected_path, expected_query) in test_requests.iter() {
            let uri = req.get_uri().unwrap();

            assert_eq!(uri.path(), *expected_path);
            assert_eq!(uri.query().unwrap_or_default(), *expected_query);
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
                ],
                "body": [0, 1, 2, 3, 4, 5, 6]
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
                body: vec![0, 1, 2, 3, 4, 5, 6],
            }
        );
    }
}
