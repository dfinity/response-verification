mod tests {
    use assert_matches::assert_matches;
    use ic_http_certification::{
        DefaultCelBuilder, DefaultResponseCertification, HttpCertification, HttpCertificationPath,
        HttpCertificationTreeEntry, HttpRequest, HttpResponse, CERTIFICATE_EXPRESSION_HEADER_NAME,
        CERTIFICATE_HEADER_NAME,
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

        let request = HttpRequest::get(req_path).build();
        let mut response = HttpResponse::ok(
            body.as_bytes(),
            vec![
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.into(),
                    cel_expr.to_string(),
                ),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
        )
        .build();

        let certification = HttpCertification::skip();
        let certification_tree_entry =
            HttpCertificationTreeEntry::new(&certification_path, certification);

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(req_path, &certification_tree_entry, &current_time);

        response.add_header((CERTIFICATE_HEADER_NAME.to_string(), certificate_header));

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

        assert_matches!(
            result,
            VerificationInfo {
                verification_version,
                response,
            } if verification_version == 2 && response.is_none()
        );
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

        let request = HttpRequest::get(req_path).build();
        let mut response = HttpResponse::ok(
            body.as_bytes(),
            vec![
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.into(),
                    cel_expr.to_string(),
                ),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
        )
        .build();

        let certification = HttpCertification::response_only(&cel_expr, &response, None).unwrap();
        let certification_tree_entry =
            HttpCertificationTreeEntry::new(&certification_path, certification);

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(req_path, &certification_tree_entry, &current_time);

        response.add_header((
            CERTIFICATE_HEADER_NAME.to_string(),
            certificate_header.clone(),
        ));

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
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.to_lowercase(),
                    cel_expr.to_string(),
                ),
                ("cache-control".into(), "max-age=604800".into()),
                (CERTIFICATE_HEADER_NAME.into(), certificate_header),
            ],
        };

        assert_matches!(
            result,
            VerificationInfo {
                verification_version,
                response,
            } if verification_version == 2 && response == Some(expected_response)
        );
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

        let request = HttpRequest::get(req_path)
            .with_headers(vec![
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ])
            .build();
        let mut response = HttpResponse::ok(
            body.as_bytes(),
            vec![
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.into(),
                    cel_expr.to_string(),
                ),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
        )
        .build();

        let certification = HttpCertification::full(&cel_expr, &request, &response, None).unwrap();
        let certification_tree_entry =
            HttpCertificationTreeEntry::new(&certification_path, certification);

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(req_path, &certification_tree_entry, &current_time);

        response.add_header((
            CERTIFICATE_HEADER_NAME.to_string(),
            certificate_header.clone(),
        ));

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
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.to_lowercase(),
                    cel_expr.to_string(),
                ),
                ("cache-control".into(), "max-age=604800".into()),
                (CERTIFICATE_HEADER_NAME.into(), certificate_header),
            ],
        };

        assert_matches!(
            result,
            VerificationInfo {
                verification_version,
                response,
            } if verification_version == 2 && response == Some(expected_response)
        );
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

        let request = HttpRequest::get(req_path).build();
        let mut response = HttpResponse::ok(
            body.as_bytes(),
            vec![
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.into(),
                    cel_expr.to_string(),
                ),
                ("Cache-Control".into(), "max-age=604800".into()),
                ("Content-Encoding".into(), "gzip".into()),
                ("Content-Language".into(), "en-US".into()),
                ("Server".into(), "Apache/2.4.1 (Unix)".into()),
            ],
        )
        .build();

        let certification = HttpCertification::response_only(&cel_expr, &response, None).unwrap();
        let certification_tree_entry = HttpCertificationTreeEntry::new(&expr_path, certification);

        let V2Fixture {
            root_key,
            certificate_header,
            canister_id,
        } = create_v2_fixture(req_path, &certification_tree_entry, &current_time);

        response.add_header((
            CERTIFICATE_HEADER_NAME.to_string(),
            certificate_header.clone(),
        ));

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
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.to_lowercase(),
                    cel_expr.to_string(),
                ),
                ("cache-control".into(), "max-age=604800".into()),
                ("server".into(), "Apache/2.4.1 (Unix)".into()),
                (CERTIFICATE_HEADER_NAME.into(), certificate_header),
            ],
        };

        assert_matches!(
            result,
            VerificationInfo {
                verification_version,
                response,
            } if verification_version == 2 && response == Some(expected_response)
        );
    }
}
