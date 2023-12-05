#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use ic_http_certification::{
        request_hash, response_hash, CelExpression, DefaultCelBuilder,
        DefaultResponseCertification, HttpRequest, HttpResponse,
    };
    use ic_response_verification::types::{VerificationInfo, VerifiedResponse};
    use ic_response_verification::verify_request_response_pair;
    use ic_response_verification_test_utils::{
        create_v2_fixture, get_current_timestamp, V2Fixture,
    };

    const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;
    const MIN_REQUESTED_VERIFICATION_VERSION: u8 = 2;

    #[test]
    fn no_certification_passes_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let expr_path = ["", "<$>"];
        let cel_expr = DefaultCelBuilder::skip_certification();

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };
        let mut response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("IC-CertificateExpression".into(), cel_expr.to_string()),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
        };

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(&cel_expr.to_string(), &expr_path, &current_time, None, None);

        response
            .headers
            .push(("IC-Certificate".into(), certificate_header));

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
            MIN_REQUESTED_VERIFICATION_VERSION,
        )
        .unwrap();

        assert!(matches!(
            result,
            VerificationInfo {
                verification_version,
                response,
            } if verification_version == 2 && response.is_none()
        ));
    }

    #[test]
    fn no_request_certification_passes_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let expr_path = ["", "<$>"];

        let certification = DefaultCelBuilder::response_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                &["Cache-Control"],
            ))
            .build();
        let cel_expr = certification.to_string();
        let CelExpression::DefaultCertification(Some(certification)) = certification else {
            panic!("Expected asset certification to have response certification")
        };
        let response_certification = certification.response_certification;

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };
        let mut response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("IC-CertificateExpression".into(), cel_expr.clone()),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
        };

        let response_hash = response_hash(&response, &response_certification);

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(
            &cel_expr,
            &expr_path,
            &current_time,
            None,
            Some(&response_hash),
        );

        response
            .headers
            .push(("IC-Certificate".into(), certificate_header));

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
            MIN_REQUESTED_VERIFICATION_VERSION,
        )
        .unwrap();

        let expected_response = VerifiedResponse {
            status_code: Some(200),
            body: body.as_bytes().to_vec(),
            headers: vec![("cache-control".into(), "max-age=604800".into())],
        };

        assert!(matches!(
            result,
            VerificationInfo {
                verification_version,
                response,
            } if verification_version == 2 && response == Some(expected_response)
        ));
    }

    #[test]
    fn full_certification_passes_verification() {
        let path = "/?q=greeting";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let expr_path = ["", "<$>"];

        let certification = DefaultCelBuilder::full_certification()
            .with_request_headers(&["Cache-Control"])
            .with_request_query_parameters(&["q"])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                &["Cache-Control"],
            ))
            .build();
        let cel_expr = certification.to_string();
        let CelExpression::DefaultCertification(Some(certification)) = certification else {
            panic!("Expected asset certification to have response certification")
        };
        let request_certification = certification.request_certification.unwrap();
        let response_certification = certification.response_certification;

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: vec![],
        };
        let mut response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("IC-CertificateExpression".into(), cel_expr.clone()),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
        };

        let request_hash = request_hash(&request, &request_certification).unwrap();
        let response_hash = response_hash(&response, &response_certification);

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(
            &cel_expr,
            &expr_path,
            &current_time,
            Some(&request_hash),
            Some(&response_hash),
        );

        response
            .headers
            .push(("IC-Certificate".into(), certificate_header));

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
            MIN_REQUESTED_VERIFICATION_VERSION,
        )
        .unwrap();

        let expected_response = VerifiedResponse {
            status_code: Some(200),
            body: body.as_bytes().to_vec(),
            headers: vec![("cache-control".into(), "max-age=604800".into())],
        };

        assert!(matches!(
            result,
            VerificationInfo {
                verification_version,
                response,
            } if verification_version == 2 && response == Some(expected_response)
        ));
    }

    #[test]
    fn response_certification_with_header_exclusions_passes_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let expr_path = ["", "<$>"];

        let certification = DefaultCelBuilder::response_certification()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                &["Content-Language", "Content-Encoding"],
            ))
            .build();
        let cel_expr = certification.to_string();
        let CelExpression::DefaultCertification(Some(certification)) = certification else {
            panic!("Expected asset certification to have response certification")
        };
        let response_certification = certification.response_certification;

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };
        let mut response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("IC-CertificateExpression".into(), cel_expr.clone()),
                ("Cache-Control".into(), "max-age=604800".into()),
                ("Content-Encoding".into(), "gzip".into()),
                ("Content-Language".into(), "en-US".into()),
                ("Server".into(), "Apache/2.4.1 (Unix)".into()),
            ],
        };

        let response_hash = response_hash(&response, &response_certification);

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(
            &cel_expr,
            &expr_path,
            &current_time,
            None,
            Some(&response_hash),
        );

        response
            .headers
            .push(("IC-Certificate".into(), certificate_header));

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
            MIN_REQUESTED_VERIFICATION_VERSION,
        )
        .unwrap();

        let expected_response = VerifiedResponse {
            status_code: Some(200),
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("cache-control".into(), "max-age=604800".into()),
                ("server".into(), "Apache/2.4.1 (Unix)".into()),
            ],
        };

        assert!(matches!(
            result,
            VerificationInfo {
                verification_version,
                response,
            } if verification_version == 2 && response == Some(expected_response)
        ));
    }
}
