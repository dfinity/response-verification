use super::Hash;
use crate::{cel::DefaultRequestCertification, HttpCertificationResult, HttpRequest};
use ic_representation_independent_hash::{hash, representation_independent_hash, Value};

/// Calculates the
/// [Representation Independent Hash](https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map)
/// of an [HttpRequest] according to a CEL expression defined by [DefaultRequestCertification].
pub fn request_hash<'a>(
    request: &'a HttpRequest,
    request_certification: &'a DefaultRequestCertification,
) -> HttpCertificationResult<Hash> {
    let mut filtered_headers = get_filtered_headers(&request.headers, request_certification);

    filtered_headers.push((
        ":ic-cert-method".into(),
        Value::String(request.method.to_string()),
    ));

    let filtered_query = request
        .get_query()?
        .map(|query| get_filtered_query(&query, request_certification));
    if let Some(query_hash) = filtered_query {
        filtered_headers.push((":ic-cert-query".into(), Value::String(query_hash)))
    }

    let concatenated_hashes = [
        representation_independent_hash(&filtered_headers),
        hash(&request.body),
    ]
    .concat();

    Ok(hash(concatenated_hashes.as_slice()))
}

fn get_filtered_headers(
    headers: &[(String, String)],
    request_certification: &DefaultRequestCertification,
) -> Vec<(String, Value)> {
    headers
        .iter()
        .filter_map(|(header_name, header_value)| {
            let is_header_included =
                request_certification
                    .headers
                    .iter()
                    .any(|header_to_include| {
                        header_to_include.eq_ignore_ascii_case(&header_name.to_string())
                    });

            if !is_header_included {
                return None;
            }

            Some((
                header_name.to_string().to_ascii_lowercase(),
                Value::String(String::from(header_value)),
            ))
        })
        .collect()
}

fn get_filtered_query(query: &str, request_certification: &DefaultRequestCertification) -> String {
    let filtered_query_string = query
        .split('&')
        .filter(|query_fragment| {
            let mut split_fragment: Vec<&str> = query_fragment.split('=').take(1).collect();
            let query_param_name = split_fragment.pop();

            query_param_name
                .map(|query_param_name| {
                    request_certification
                        .query_parameters
                        .iter()
                        .any(|query_param_to_include| {
                            query_param_to_include.eq_ignore_ascii_case(query_param_name)
                        })
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
        let request_certification = DefaultRequestCertification::new(vec!["host"], vec![]);
        let request = create_request("https://ic0.app");
        let expected_hash =
            hex::decode("10796453466efb3e333891136b8a5931269f77e40ead9d437fcee94a02fa833c")
                .unwrap();

        let result = request_hash(&request, &request_certification).unwrap();

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn request_hash_with_query() {
        let request_certification =
            DefaultRequestCertification::new(vec!["host"], vec!["q", "name"]);
        let request =
            create_request("https://ic0.app?q=hello+world&name=foo&name=bar&color=purple");
        let expected_hash =
            hex::decode("3ade1c9054f05bc8bcebd3fd7b884078a6e67c63e5ac4a639fa46a47f5a955c9")
                .unwrap();

        let result = request_hash(&request, &request_certification).unwrap();

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn request_hash_query_order_matters() {
        let request_certification =
            DefaultRequestCertification::new(vec!["host"], vec!["q", "name"]);
        let request =
            create_request("https://ic0.app?q=hello+world&name=foo&name=bar&color=purple");
        let reordered_request =
            create_request("https://ic0.app?q=hello+world&name=bar&name=foo&color=purple");

        let result = request_hash(&request, &request_certification).unwrap();
        let reordered_result = request_hash(&reordered_request, &request_certification).unwrap();

        assert_ne!(result, reordered_result);
    }

    #[test]
    fn request_hash_query_with_fragment_does_not_change() {
        let request_certification =
            DefaultRequestCertification::new(vec!["host"], vec!["q", "name"]);
        let request =
            create_request("https://ic0.app?q=hello+world&name=foo&name=bar&color=purple");
        let request_with_fragment = create_request(
            "https://ic0.app?q=hello+world&name=foo&name=bar&color=purple#index.html",
        );

        let result = request_hash(&request, &request_certification).unwrap();
        let result_with_fragment =
            request_hash(&request_with_fragment, &request_certification).unwrap();

        assert_eq!(result, result_with_fragment);
    }

    fn create_request(uri: &str) -> HttpRequest {
        HttpRequest {
            url: uri.into(),
            method: "POST".into(),
            headers: vec![
                ("Accept-Language".into(), "en".into()),
                ("Accept-Language".into(), "en-US".into()),
                ("Host".into(), "https://ic0.app".into()),
            ],
            body: vec![0, 1, 2, 3, 4, 5, 6],
        }
    }
}
