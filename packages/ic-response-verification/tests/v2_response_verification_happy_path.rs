#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use ic_certified_map::Hash;
    use ic_response_verification::cel::cel_to_certification;
    use ic_response_verification::hash::{request_hash, response_hash};
    use ic_response_verification::types::{CertifiedResponse, Request, Response};
    use ic_response_verification::verify_request_response_pair;
    use ic_response_verification_test_utils::{
        create_canister_id, create_expr_tree_path, create_versioned_certificate_header,
        get_current_timestamp, hash, remove_whitespace, serialize_to_cbor, CanisterData,
        CertificateBuilder, CertificateData, ExprTree,
    };
    use ic_types::CanisterId;

    const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;
    const MIN_REQUESTED_VERIFICATION_VERSION: u8 = 2;

    #[test]
    fn no_certification_passes_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");
        let expr_path = ["", "<$>"];
        let cel_expr = remove_whitespace(
            r#"
            default_certification (
                ValidationArgs {
                    no_certification: Empty { }
                }
            )
        "#,
        );

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };
        let mut response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("IC-CertificateExpression".into(), cel_expr.clone()),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
        };

        let (root_key, certificate_header) = create_happy_path_fixture(
            &cel_expr,
            &expr_path,
            &canister_id,
            &current_time,
            None,
            None,
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

        assert!(result.passed);
        assert_eq!(result.response, None);
    }

    #[test]
    fn no_request_certification_passes_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");
        let expr_path = ["", "<$>"];
        let cel_expr = remove_whitespace(
            r#"
            default_certification (
                ValidationArgs {
                    certification: Certification {
                        no_request_certification: Empty {},
                        response_certification: ResponseCertification {
                            certified_response_headers: ResponseHeaderList {
                                headers: ["Cache-Control"]
                            }
                        }
                    }
                }
            )
        "#,
        );
        let certification = cel_to_certification(&cel_expr).unwrap().unwrap();
        let response_certification = certification.response_certification;

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };
        let mut response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("IC-CertificateExpression".into(), cel_expr.clone()),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
        };

        let response_hash = response_hash(&response, &response_certification);

        let (root_key, certificate_header) = create_happy_path_fixture(
            &cel_expr,
            &expr_path,
            &canister_id,
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

        let expected_response = CertifiedResponse {
            status_code: Some(200),
            body: body.as_bytes().to_vec(),
            headers: vec![("cache-control".into(), "max-age=604800".into())],
        };

        assert!(result.passed);
        assert_eq!(result.response, Some(expected_response));
    }

    #[test]
    fn full_certification_passes_verification() {
        let path = "/?q=greeting";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");
        let expr_path = ["", "<$>"];
        let cel_expr = remove_whitespace(
            r#"
            default_certification (
                ValidationArgs {
                    certification: Certification {
                        request_certification: RequestCertification {
                            certified_request_headers: ["Cache-Control"],
                            certified_query_parameters: ["q"]
                        },
                        response_certification: ResponseCertification {
                            certified_response_headers: ResponseHeaderList {
                                headers: ["Cache-Control"]
                            }
                        }
                    }
                }
            )
        "#,
        );
        let certification = cel_to_certification(&cel_expr).unwrap().unwrap();
        let request_certification = certification.request_certification.unwrap();
        let response_certification = certification.response_certification;

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
        };
        let mut response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("IC-CertificateExpression".into(), cel_expr.clone()),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
        };

        let request_hash = request_hash(&request, &request_certification).unwrap();
        let response_hash = response_hash(&response, &response_certification);

        let (root_key, certificate_header) = create_happy_path_fixture(
            &cel_expr,
            &expr_path,
            &canister_id,
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

        let expected_response = CertifiedResponse {
            status_code: Some(200),
            body: body.as_bytes().to_vec(),
            headers: vec![("cache-control".into(), "max-age=604800".into())],
        };

        assert!(result.passed);
        assert_eq!(result.response, Some(expected_response));
    }

    #[test]
    fn response_certification_with_header_exclusions_passes_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");
        let expr_path = ["", "<$>"];
        let cel_expr = remove_whitespace(
            r#"
            default_certification (
                ValidationArgs {
                    certification: Certification {
                        no_request_certification: Empty {},
                        response_certification: ResponseCertification {
                            response_header_exclusions: ResponseHeaderList {
                                headers: ["Content-Language", "Content-Encoding"]
                            }
                        }
                    }
                }
            )
        "#,
        );
        let certification = cel_to_certification(&cel_expr).unwrap().unwrap();
        let response_certification = certification.response_certification;

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };
        let mut response = Response {
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

        let (root_key, certificate_header) = create_happy_path_fixture(
            &cel_expr,
            &expr_path,
            &canister_id,
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

        let expected_response = CertifiedResponse {
            status_code: Some(200),
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("cache-control".into(), "max-age=604800".into()),
                ("server".into(), "Apache/2.4.1 (Unix)".into()),
            ],
        };

        assert!(result.passed);
        assert_eq!(result.response, Some(expected_response));
    }

    fn create_happy_path_fixture(
        cel_expr: &str,
        expr_path: &[&str],
        canister_id: &CanisterId,
        current_time: &u128,
        req_hash: Option<&Hash>,
        res_hash: Option<&Hash>,
    ) -> (Vec<u8>, String) {
        let cel_expr_hash = hash(cel_expr);

        let expr_tree_path = create_expr_tree_path(expr_path, &cel_expr_hash, req_hash, res_hash);

        let mut expr_tree = ExprTree::new();
        expr_tree.insert(&expr_tree_path);
        println!("expr_tree: {:?}", expr_tree);
        let certified_data = expr_tree.get_certified_data();
        let tree_cbor = expr_tree.serialize_to_cbor(&expr_tree_path);

        let (_, root_key, certificate_cbor) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id: *canister_id,
                certified_data,
            }))
            .with_time(*current_time)
            .build();

        let mut full_expr_path = vec!["http_expr"];
        full_expr_path.extend(expr_path);

        let certificate_header = create_versioned_certificate_header(
            &certificate_cbor,
            &tree_cbor,
            &serialize_to_cbor(&full_expr_path),
            2,
        );

        (root_key, certificate_header)
    }
}
