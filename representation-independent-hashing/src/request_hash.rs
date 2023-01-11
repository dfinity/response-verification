use crate::representation_independent_hash::{representation_independent_hash, Value};
use cel_parser::RequestCertification;
use http::{HeaderMap, HeaderValue, Request};

pub fn request_hash(
    request: &Request<&[u8]>,
    request_certification: &RequestCertification,
) -> [u8; 32] {
    let mut filtered_headers = get_filtered_headers(request.headers(), request_certification);

    filtered_headers.push((
        ":ic-cert-method".into(),
        Value::String(request.method().to_string()),
    ));

    let filtered_query = request
        .uri()
        .query()
        .and_then(|query| Some(get_filtered_query(query, request_certification)));
    if let Some(query_hash) = filtered_query {
        filtered_headers.push((":ic-cert-query".into(), Value::String(query_hash)))
    }

    representation_independent_hash(&filtered_headers)
}

fn get_filtered_headers(
    headers: &HeaderMap<HeaderValue>,
    request_certification: &RequestCertification,
) -> Vec<(String, Value)> {
    headers
        .iter()
        .filter_map(|(header_name, header_value)| {
            let is_header_included =
                request_certification
                    .certified_request_headers
                    .iter()
                    .any(|header_to_include| {
                        header_to_include.eq_ignore_ascii_case(&header_name.to_string())
                    });

            if !is_header_included {
                return None;
            }

            Some((
                header_name.to_string(),
                Value::String(String::from(header_value.to_str().unwrap())),
            ))
        })
        .collect()
}

fn get_filtered_query(query: &str, request_certification: &RequestCertification) -> String {
    let filtered_query_string = query
        .split("&")
        .filter(|query_fragment| {
            let mut split_fragment: Vec<&str> = query_fragment.split("=").take(1).collect();
            let query_param_name = split_fragment.pop();

            query_param_name
                .and_then(|query_param_name| {
                    let is_param_included = request_certification
                        .certified_query_parameters
                        .iter()
                        .any(|query_param_to_include| {
                            query_param_to_include.eq_ignore_ascii_case(&query_param_name)
                        });

                    Some(is_param_included)
                })
                .unwrap_or(false)
        })
        .collect::<Vec<&str>>()
        .join("&");

    filtered_query_string
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_hash_without_query() {
        let request_certification = RequestCertification {
            certified_request_headers: vec!["host".into()],
            certified_query_parameters: vec![],
        };
        let request = create_request("https://ic0.app");
        let expected_hash =
            hex::decode("acf45639fb32005e186bb68d4aefb5caf39c986ed32f620c278ef6eb0196e237")
                .unwrap();

        let result = request_hash(&request, &request_certification);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn request_hash_with_query() {
        let request_certification = RequestCertification {
            certified_request_headers: vec!["host".into()],
            certified_query_parameters: vec!["q".into(), "name".into()],
        };
        let request =
            create_request("https://ic0.app?q=hello+world&name=foo&name=bar&color=purple");
        let expected_hash =
            hex::decode("213b9e222b01decd26d0db070808ca8d437d863ac5b8172f8149c40735e13f47")
                .unwrap();

        let result = request_hash(&request, &request_certification);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn request_hash_query_order_matters() {
        let request_certification = RequestCertification {
            certified_request_headers: vec!["host".into()],
            certified_query_parameters: vec!["q".into(), "name".into()],
        };
        let request =
            create_request("https://ic0.app?q=hello+world&name=foo&name=bar&color=purple");
        let reordered_request =
            create_request("https://ic0.app?q=hello+world&name=bar&name=foo&color=purple");

        let result = request_hash(&request, &request_certification);
        let reordered_result = request_hash(&reordered_request, &request_certification);

        assert_ne!(result, reordered_result);
    }

    #[test]
    fn request_hash_query_with_fragment_does_not_change() {
        let request_certification = RequestCertification {
            certified_request_headers: vec!["host".into()],
            certified_query_parameters: vec!["q".into(), "name".into()],
        };
        let request =
            create_request("https://ic0.app?q=hello+world&name=foo&name=bar&color=purple");
        let request_with_fragment = create_request(
            "https://ic0.app?q=hello+world&name=foo&name=bar&color=purple#index.html",
        );

        let result = request_hash(&request, &request_certification);
        let result_with_fragment = request_hash(&request_with_fragment, &request_certification);

        assert_eq!(result, result_with_fragment);
    }

    fn create_request(uri: &str) -> Request<&'static [u8]> {
        Request::builder()
            .uri(uri)
            .method("POST")
            .header("accept-language", "en")
            .header("accept-language", "en-US")
            .header("host", "https://ic0.app")
            .body(&[] as &[u8])
            .unwrap()
    }
}
