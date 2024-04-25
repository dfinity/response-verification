mod tests {
    use ic_http_certification::{
        DefaultCelBuilder, DefaultResponseCertification, HttpCertification, HttpCertificationPath,
        HttpCertificationTreeEntry, HttpRequest, HttpResponse,
    };
    use ic_response_verification::{
        types::{VerificationInfo, VerifiedResponse},
        verify_request_response_pair,
    };
    use ic_response_verification_test_utils::{
        create_v2_fixture, get_current_timestamp, V2Fixture,
    };

    const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;
    const MIN_REQUESTED_VERIFICATION_VERSION: u8 = 2;

    #[test]
    fn no_certification_passes_verification() {
        let req_path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let certification_path = HttpCertificationPath::exact("/");
        let cel_expr = DefaultCelBuilder::skip_certification();

        let request = HttpRequest {
            url: req_path.into(),
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
            upgrade: None,
        };

        let certification = HttpCertification::skip();
        let certification_tree_entry =
            HttpCertificationTreeEntry::new(&certification_path, certification);

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(req_path, &certification_tree_entry, &current_time);

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
        let req_path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let certification_path = HttpCertificationPath::exact("/");

        let cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["Cache-Control"],
            ))
            .build();

        let request = HttpRequest {
            url: req_path.into(),
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
            upgrade: None,
        };

        let certification = HttpCertification::response_only(&cel_expr, &response, None).unwrap();
        let certification_tree_entry =
            HttpCertificationTreeEntry::new(&certification_path, certification);

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(req_path, &certification_tree_entry, &current_time);

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
        let req_path = "/?q=greeting";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let certification_path = HttpCertificationPath::exact("/");

        let cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["Cache-Control"])
            .with_request_query_parameters(vec!["q"])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["Cache-Control"],
            ))
            .build();

        let request = HttpRequest {
            url: req_path.into(),
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
                ("IC-CertificateExpression".into(), cel_expr.to_string()),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
            upgrade: None,
        };

        let certification = HttpCertification::full(&cel_expr, &request, &response, None).unwrap();
        let certification_tree_entry =
            HttpCertificationTreeEntry::new(&certification_path, certification);

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(req_path, &certification_tree_entry, &current_time);

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
        let req_path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let expr_path = HttpCertificationPath::exact("/");

        let cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec!["Content-Language", "Content-Encoding"],
            ))
            .build();

        let request = HttpRequest {
            url: req_path.into(),
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
                ("Content-Encoding".into(), "gzip".into()),
                ("Content-Language".into(), "en-US".into()),
                ("Server".into(), "Apache/2.4.1 (Unix)".into()),
            ],
            upgrade: None,
        };

        let certification = HttpCertification::response_only(&cel_expr, &response, None).unwrap();
        let certification_tree_entry = HttpCertificationTreeEntry::new(&expr_path, certification);

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(req_path, &certification_tree_entry, &current_time);

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
