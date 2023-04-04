#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use ic_response_verification::{
        cel::cel_to_certification,
        hash::{request_hash, response_hash},
        types::{Request, Response},
        verify_request_response_pair,
    };
    use ic_response_verification_test_utils::{
        create_canister_id, create_v2_certificate_fixture, create_v2_fixture, create_v2_header,
        create_v2_tree_fixture, get_current_timestamp, hash_from_hex, remove_whitespace,
        V2CertificateFixture, V2Fixture, V2TreeFixture,
    };

    const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;
    const MIN_REQUESTED_VERIFICATION_VERSION: u8 = 2;

    #[test]
    fn request_hash_mismatch_fails_verification() {
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

        let request_hash =
            hash_from_hex("8afafcbf4e8ba0e372a5c17bcb8d668f6acdfab65ab3739a708ca632ded39098");
        let response_hash = response_hash(&response, &response_certification);

        let V2Fixture {
            root_key,
            certificate_header,
        } = create_v2_fixture(
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

        assert!(!result.passed);
        assert_eq!(result.response, None);
    }

    #[test]
    pub fn response_hash_mismatch_fails_verification() {
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
        let response_hash =
            hash_from_hex("25dfc31fa622ded0d67b3ea322ab85dbc6c7455729c3618fcb3c26c23e1cc17c");

        let V2Fixture {
            root_key,
            certificate_header,
        } = create_v2_fixture(
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

        assert!(!result.passed);
        assert_eq!(result.response, None);
    }

    #[test]
    fn cel_expr_hash_fails_verification() {
        let path = "/?q=greeting";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");
        let expr_path = ["", "<$>"];
        let wrong_cel_expr = remove_whitespace(
            r#"
            default_certification (
                ValidationArgs {
                    no_certification: Empty { }
                }
            )
        "#,
        );
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
                ("IC-CertificateExpression".into(), wrong_cel_expr.clone()),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
        };

        let request_hash = request_hash(&request, &request_certification).unwrap();
        let response_hash = response_hash(&response, &response_certification);

        let V2TreeFixture {
            tree_cbor,
            certified_data,
        } = create_v2_tree_fixture(
            &cel_expr,
            &expr_path,
            Some(&request_hash),
            Some(&response_hash),
        );
        let V2CertificateFixture {
            root_key,
            certificate_cbor,
        } = create_v2_certificate_fixture(&canister_id, &certified_data, &current_time);
        let certificate_header = create_v2_header(&expr_path, &certificate_cbor, &tree_cbor);

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

        assert!(!result.passed);
        assert_eq!(result.response, None);
    }
}
