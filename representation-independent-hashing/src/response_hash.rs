use crate::hash::hash;
use crate::representation_independent_hash::representation_independent_hash;
use cel_parser::ResponseCertification;
use http::header::HeaderName;
use http::Response;
use std::collections::HashMap;

pub fn response_hash(
    response: &Response<&[u8]>,
    response_certification: &ResponseCertification,
) -> [u8; 32] {
    let headers_filter: Box<dyn Fn(_) -> _> = match response_certification {
        ResponseCertification::CertifiedHeaders(headers_to_include) => {
            Box::new(move |header_name: &HeaderName| {
                headers_to_include.iter().any(|header_to_include| {
                    header_to_include.eq_ignore_ascii_case(&header_name.to_string())
                })
            })
        }
        ResponseCertification::HeaderExclusions(headers_to_exclude) => {
            Box::new(move |header_name: &HeaderName| {
                !headers_to_exclude.iter().any(|header_to_exclude| {
                    header_to_exclude.eq_ignore_ascii_case(&header_name.to_string())
                })
            })
        }
    };

    let mut filtered_headers: HashMap<_, _> = response
        .headers()
        .iter()
        .filter_map(|(header_name, header_value)| {
            if (header_name
                .to_string()
                .eq_ignore_ascii_case("IC-Certificate")
                || !headers_filter(header_name))
                && !header_name
                    .to_string()
                    .eq_ignore_ascii_case("IC-Certificate-Expression")
            {
                return None::<(String, String)>;
            }

            Some((
                header_name.to_string(),
                String::from(header_value.to_str().unwrap()),
            ))
        })
        .collect();
    filtered_headers.insert(":ic-cert-status".into(), response.status().to_string());

    let concatenated_hashes = [
        representation_independent_hash(&filtered_headers),
        hash(response.body()),
    ]
    .concat();

    hash(concatenated_hashes.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO_WORLD_BODY: &[u8] = &[72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
    const CERTIFICATE: &str = "certificate=:SGVsbG8gQ2VydGlmaWNhdGUh:,tree=:SGVsbG8gVHJlZSE=:";
    const CEL_EXPRESSION: &str = r#"
        default_certification (
          ValidationArgs {
            certification: Certification {
              no_request_certification: Empty {},
              response_certification: ResponseCertification {
                response_header_exclusions: ResponseHeaderList {
                  headers: ["Accept-Encoding", "Cache-Control", "X-Cache-Status"]
                }
              }
            }
          }
        )
    "#;

    fn remove_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }

    fn create_response() -> Response<&'static [u8]> {
        let cel_expression = remove_whitespace(CEL_EXPRESSION);

        Response::builder()
            .header("IC-Certificate", CERTIFICATE)
            .header("IC-Certificate-Expression", &cel_expression)
            .header("Accept-Encoding", "gzip")
            .header("Cache-Control", "no-cache")
            .header("Content-Security-Policy", "default-src 'self'")
            .body(HELLO_WORLD_BODY)
            .unwrap()
    }

    #[test]
    fn response_hash_with_certified_headers() {
        let response_certification = ResponseCertification::CertifiedHeaders(vec![
            "Accept-Encoding".into(),
            "Cache-Control".into(),
        ]);
        let response = create_response();
        let expected_hash = [
            35, 79, 46, 153, 224, 77, 202, 213, 223, 71, 188, 45, 251, 234, 113, 245, 86, 79, 27,
            172, 81, 216, 25, 126, 39, 155, 113, 155, 201, 200, 168, 190,
        ];

        let result = response_hash(&response, &response_certification);

        assert_eq!(result, expected_hash);
    }

    #[test]
    fn response_hash_with_certified_headers_without_excluded_headers() {
        let cel_expression = remove_whitespace(CEL_EXPRESSION);
        let response_certification =
            ResponseCertification::CertifiedHeaders(vec!["Accept-Encoding".into()]);
        let response = create_response();
        let response_without_excluded_headers: Response<&[u8]> = Response::builder()
            .header("IC-Certificate-Expression", &cel_expression)
            .header("Accept-Encoding", "gzip")
            .body(HELLO_WORLD_BODY)
            .unwrap();

        let result = response_hash(&response, &response_certification);
        let result_without_excluded_headers =
            response_hash(&response_without_excluded_headers, &response_certification);

        assert_eq!(result, result_without_excluded_headers);
    }

    #[test]
    fn response_hash_with_header_exclusions() {
        let response_certification =
            ResponseCertification::HeaderExclusions(vec!["Content-Security-Policy".into()]);
        let response = create_response();
        let expected_hash = [
            35, 79, 46, 153, 224, 77, 202, 213, 223, 71, 188, 45, 251, 234, 113, 245, 86, 79, 27,
            172, 81, 216, 25, 126, 39, 155, 113, 155, 201, 200, 168, 190,
        ];

        let result = response_hash(&response, &response_certification);

        assert_eq!(result, expected_hash);
    }

    #[test]
    fn response_hash_with_with_header_exclusions_without_excluded_headers() {
        let cel_expression = remove_whitespace(CEL_EXPRESSION);
        let response_certification = ResponseCertification::HeaderExclusions(vec![
            "Accept-Encoding".into(),
            "Cache-Control".into(),
        ]);
        let response = create_response();
        let response_without_excluded_headers: Response<&[u8]> = Response::builder()
            .header("IC-Certificate-Expression", &cel_expression)
            .header("Content-Security-Policy", "default-src 'self'")
            .body(HELLO_WORLD_BODY)
            .unwrap();

        let result = response_hash(&response, &response_certification);
        let result_without_excluded_headers =
            response_hash(&response_without_excluded_headers, &response_certification);

        assert_eq!(result, result_without_excluded_headers);
    }
}
