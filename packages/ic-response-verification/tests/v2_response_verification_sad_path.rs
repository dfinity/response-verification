#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use crate::fixtures::{
        self, expired_certificate, full_certification_cel, future_certificate,
        invalid_root_key_certificate, skip_certification_cel, wrong_canister_certificate,
        MAX_CERT_TIME_OFFSET_NS, MIN_REQUESTED_VERIFICATION_VERSION,
    };
    use ic_response_verification::{
        cel::cel_to_certification,
        hash::{request_hash, response_hash},
        types::{Request, Response},
        verify_request_response_pair, ResponseVerificationError,
    };
    use ic_response_verification_test_utils::{
        create_expr_tree_path, create_v2_certificate_fixture, create_v2_fixture, create_v2_header,
        create_v2_tree_fixture, get_current_timestamp, hash, hash_from_hex, ExprTree,
        V2CertificateFixture, V2Fixture, V2TreeFixture,
    };
    use rstest::*;

    #[rstest]
    fn request_hash_mismatch_fails_verification(#[from(full_certification_cel)] cel_expr: String) {
        let path = "/?q=greeting";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let expr_path = ["", "<$>"];
        let certification = cel_to_certification(&cel_expr).unwrap().unwrap();
        let response_certification = certification.response_certification;

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: vec![],
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
            fixtures::MAX_CERT_TIME_OFFSET_NS,
            &root_key,
            fixtures::MIN_REQUESTED_VERIFICATION_VERSION,
        );

        assert!(matches!(
            result,
            Err(ResponseVerificationError::InvalidResponseHashes)
        ));
    }

    #[rstest]
    pub fn response_hash_mismatch_fails_verification(
        #[from(full_certification_cel)] cel_expr: String,
    ) {
        let path = "/?q=greeting";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let expr_path = ["", "<$>"];
        let certification = cel_to_certification(&cel_expr).unwrap().unwrap();
        let request_certification = certification.request_certification.unwrap();

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: vec![],
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
        );

        assert!(matches!(
            result,
            Err(ResponseVerificationError::InvalidResponseHashes)
        ));
    }

    #[rstest]
    fn cel_expr_hash_fails_verification(
        #[from(skip_certification_cel)] wrong_cel_expr: String,
        #[from(full_certification_cel)] cel_expr: String,
    ) {
        let path = "/?q=greeting";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let expr_path = ["", "<$>"];
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
            body: vec![],
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
            canister_id,
        } = create_v2_certificate_fixture(&certified_data, &current_time);
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
        );

        assert!(matches!(
            result,
            Err(ResponseVerificationError::InvalidExpressionPath)
        ));
    }

    #[rstest]
    #[case::does_not_exist_in_tree(&["assets", "css", "<*>"])]
    #[case::more_specific_path_exists_in_tree(&["assets", "<*>"])]
    #[case::does_not_match_request_url(&["assets", "js", "dashboard.js", "<$>"])]
    fn invalid_expr_path_fails_verification(
        #[from(skip_certification_cel)] cel_expr: String,
        #[case] expr_path: &[&str],
    ) {
        let current_time = get_current_timestamp();

        let request = Request {
            url: "/assets/js/app.js".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: vec![],
        };
        let mut response = Response {
            status_code: 200,
            body: b"Hello World!".to_vec(),
            headers: vec![("IC-CertificateExpression".to_string(), cel_expr.clone())],
        };

        let cel_expr_hash = hash(cel_expr);
        let mut expr_tree = ExprTree::new();

        expr_tree.insert(&create_expr_tree_path(
            &["assets", "<*>"],
            &cel_expr_hash,
            None,
            None,
        ));
        expr_tree.insert(&create_expr_tree_path(
            &["assets", "js", "<*>"],
            &cel_expr_hash,
            None,
            None,
        ));
        expr_tree.insert(&create_expr_tree_path(
            &["assets", "js", "dashboard.js", "<$>"],
            &cel_expr_hash,
            None,
            None,
        ));

        let V2CertificateFixture {
            root_key,
            certificate_cbor,
            canister_id,
        } = create_v2_certificate_fixture(&expr_tree.get_certified_data(), &current_time);
        let certificate_header = create_v2_header(
            &expr_path,
            &certificate_cbor,
            &expr_tree.serialize_to_cbor(),
        );

        response
            .headers
            .push(("IC-Certificate".to_string(), certificate_header));

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
            MIN_REQUESTED_VERIFICATION_VERSION,
        );

        assert!(matches!(
            result,
            Err(ResponseVerificationError::InvalidExpressionPath)
        ));
    }

    #[rstest]
    #[case::invalid_root_key_certificate(
        invalid_root_key_certificate(),
        ResponseVerificationError::CertificateVerificationFailed
    )]
    #[case::expired_certificate(
        expired_certificate(),
        ResponseVerificationError::CertificateTimeTooFarInThePast  { certificate_time: 0, min_certificate_time: 0 }
    )]
    #[case::future_certificate(
        future_certificate(),
        ResponseVerificationError::CertificateTimeTooFarInTheFuture  { certificate_time: 0, max_certificate_time: 0 }
    )]
    #[case::wrong_canister_certificate(
        wrong_canister_certificate(),
        ResponseVerificationError::CertificatePrincipalOutOfRange
    )]
    fn invalid_certificate_fails_verification(
        #[case] fixture: (V2Fixture, u128, String),
        #[case] expected_failure: ResponseVerificationError,
    ) {
        let (
            V2Fixture {
                root_key,
                certificate_header,
                canister_id,
            },
            current_time,
            cel_expr,
        ) = fixture;

        let path = "/";
        let body = "Hello World!";

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };
        let mut response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("IC-CertificateExpression".into(), cel_expr.clone()),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
        };

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
        );

        assert!(
            matches!(result, Err(ref failure) if match (failure, expected_failure) {
                (ResponseVerificationError::CertificateVerificationFailed, ResponseVerificationError::CertificateVerificationFailed) => true,
                (ResponseVerificationError::CertificatePrincipalOutOfRange, ResponseVerificationError::CertificatePrincipalOutOfRange) => true,
                (ResponseVerificationError::CertificateTimeTooFarInThePast { .. }, ResponseVerificationError::CertificateTimeTooFarInThePast { .. }) => true,
                (ResponseVerificationError::CertificateTimeTooFarInTheFuture { .. }, ResponseVerificationError::CertificateTimeTooFarInTheFuture { .. }) => true,
                _ => false
            })
        )
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod fixtures {
    use ic_response_verification_test_utils::{
        create_v2_fixture, get_current_timestamp, get_timestamp, remove_whitespace, V2Fixture,
    };
    use ic_types::CanisterId;
    use rstest::*;
    use std::{
        ops::{Add, Sub},
        time::{Duration, SystemTime},
    };

    pub const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;
    pub const MIN_REQUESTED_VERIFICATION_VERSION: u8 = 2;

    #[fixture]
    pub fn full_certification_cel() -> String {
        remove_whitespace(
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
        )
    }

    #[fixture]
    pub fn skip_certification_cel() -> String {
        remove_whitespace(
            r#"
                default_certification (
                    ValidationArgs {
                        no_certification: Empty { }
                    }
                )
            "#,
        )
    }

    pub fn invalid_root_key_certificate() -> (V2Fixture, u128, String) {
        let cel_expr = skip_certification_cel();
        let expr_path = ["", "<$>"];
        let current_time = get_current_timestamp();

        let root_key = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

        let v2_fixture = create_v2_fixture(&cel_expr, &expr_path, &current_time, None, None);

        (
            V2Fixture {
                certificate_header: v2_fixture.certificate_header,
                canister_id: v2_fixture.canister_id,
                root_key: root_key.to_vec(),
            },
            current_time,
            cel_expr,
        )
    }

    pub fn expired_certificate() -> (V2Fixture, u128, String) {
        let cel_expr = skip_certification_cel();
        let expr_path = ["", "<$>"];
        let current_time = get_current_timestamp();

        let max_cert_time_offset_s: u64 = (MAX_CERT_TIME_OFFSET_NS / 1_000_000_000)
            .try_into()
            .unwrap();
        let past_time =
            get_timestamp(SystemTime::now().sub(Duration::new(max_cert_time_offset_s + 1, 0)));

        let v2_fixture = create_v2_fixture(&cel_expr, &expr_path, &past_time, None, None);

        (v2_fixture, current_time, cel_expr)
    }

    pub fn future_certificate() -> (V2Fixture, u128, String) {
        let cel_expr = skip_certification_cel();
        let expr_path = ["", "<$>"];
        let current_time = get_current_timestamp();

        let max_cert_time_offset_s: u64 = (MAX_CERT_TIME_OFFSET_NS / 1_000_000_000)
            .try_into()
            .unwrap();
        let future_time =
            get_timestamp(SystemTime::now().add(Duration::new(max_cert_time_offset_s + 1, 0)));

        let v2_fixture = create_v2_fixture(&cel_expr, &expr_path, &future_time, None, None);

        (v2_fixture, current_time, cel_expr)
    }

    pub fn wrong_canister_certificate() -> (V2Fixture, u128, String) {
        let cel_expr = skip_certification_cel();
        let expr_path = ["", "<$>"];
        let other_canister_id = CanisterId::from_u64(15);
        let current_time = get_current_timestamp();

        let v2_fixture = create_v2_fixture(&cel_expr, &expr_path, &current_time, None, None);

        (
            V2Fixture {
                root_key: v2_fixture.root_key,
                certificate_header: v2_fixture.certificate_header,
                canister_id: other_canister_id,
            },
            current_time,
            cel_expr,
        )
    }
}
