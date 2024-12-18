use ic_http_certification::{HttpRequest, Method};
use std::str::FromStr;
use wasm_bindgen::{prelude::*, JsCast};

#[wasm_bindgen(typescript_custom_section)]
const REQUEST: &'static str = r#"
interface Request {
    url: string;
    method: string;
    body: Uint8Array | number[];
    headers: [string, string][];
    certificate_version: [] | [number],
}
"#;

pub fn request_from_js(req: JsValue) -> HttpRequest<'static> {
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

    HttpRequest::builder()
        .with_method(Method::from_str(&method).unwrap())
        .with_url(url)
        .with_headers(headers)
        .with_body(body)
        .build()
}

#[cfg(test)]
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
        let r = request_from_js(v);

        assert_eq!(
            r,
            HttpRequest::get("http://url.com")
                .with_headers(vec![
                    ("header1".into(), "header1val".into()),
                    ("header2".into(), "header2val".into()),
                ])
                .with_body(vec![0, 1, 2, 3, 4, 5, 6])
                .build()
        );
    }
}
