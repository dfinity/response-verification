use ic_http_certification::HttpResponse;
use wasm_bindgen::{prelude::*, JsCast};

#[wasm_bindgen(typescript_custom_section)]
const RESPONSE: &'static str = r#"
interface Response {
    status_code: number;
    headers: [string, string][];
    body: Uint8Array | number[];
}
"#;

pub fn response_from_js(resp: JsValue) -> HttpResponse<'static> {
    use js_sys::{Array, JsString, Number, Object, Uint8Array};

    let status_code_str = JsString::from("status_code");
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

    HttpResponse::builder()
        .with_status_code(status_code.try_into().unwrap())
        .with_headers(headers)
        .with_body(body)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_http_certification::StatusCode;
    use js_sys::JSON;
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn request_from() {
        let v = JSON::parse(
            r#"{
                "status_code": 200,
                "body": [0, 1, 2, 3, 4, 5, 6],
                "headers": [
                    ["header1", "header1val"],
                    ["header2", "header2val"]
                ]
            }"#,
        )
        .expect("failed to parse JSON");
        let r = response_from_js(v);

        assert_eq!(
            r,
            HttpResponse::builder()
                .with_status_code(StatusCode::OK)
                .with_body(vec![0, 1, 2, 3, 4, 5, 6])
                .with_headers(vec![
                    ("header1".into(), "header1val".into()),
                    ("header2".into(), "header2val".into())
                ])
                .build()
        );
    }
}
