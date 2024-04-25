mod tests {
    use crate::fixtures::{
        self, expired_certificate, full_certification_cel, future_certificate,
        invalid_root_key_certificate, skip_certification_cel, wrong_canister_certificate,
        MAX_CERT_TIME_OFFSET_NS, MIN_REQUESTED_VERIFICATION_VERSION,
    };
    use candid::Principal;
    use ic_certificate_verification::CertificateVerificationError;
    use ic_http_certification::{
        CelExpression, DefaultFullCelExpression, HttpCertification, HttpCertificationPath,
        HttpCertificationTreeEntry, HttpRequest, HttpResponse,
    };
    use ic_response_verification::{verify_request_response_pair, ResponseVerificationError};
    use ic_response_verification_test_utils::{
        create_v2_certificate_fixture, create_v2_fixture, create_v2_header, create_v2_tree_fixture,
        get_current_timestamp, V2CertificateFixture, V2Fixture, V2TreeFixture,
    };
    use rstest::*;

    #[rstest]
    fn request_hash_mismatch_fails_verification(
        #[from(full_certification_cel)] cel_expr: DefaultFullCelExpression<'static>,
    ) {
        let req_path = "/?q=greeting";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let certification_path = HttpCertificationPath::exact("/");

        let request = HttpRequest {
            url: req_path.into(),
            method: "GET".into(),
            headers: vec![
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: vec![],
        };
        let wrong_request = HttpRequest {
            url: req_path.into(),
            method: "GET".into(),
            headers: vec![
                ("Cache-Control".into(), "public".into()),
                ("Cache-Control".into(), "immutable".into()),
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
            wrong_request,
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
        #[from(full_certification_cel)] cel_expr: DefaultFullCelExpression<'static>,
    ) {
        let req_path = "/?q=greeting";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let certification_path = HttpCertificationPath::exact("/");

        let request = HttpRequest {
            url: req_path.into(),
            method: "GET".into(),
            headers: vec![
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: vec![],
        };
        let response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("IC-CertificateExpression".into(), cel_expr.to_string()),
                ("Cache-Control".into(), "max-age=604800".into()),
            ],
            upgrade: None,
        };
        let mut wrong_response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("IC-CertificateExpression".into(), cel_expr.to_string()),
                ("Cache-Control".into(), "public".into()),
                ("Cache-Control".into(), "immutable".into()),
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

        wrong_response
            .headers
            .push(("IC-Certificate".into(), certificate_header));

        let result = verify_request_response_pair(
            request,
            wrong_response,
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
        #[from(skip_certification_cel)] wrong_cel_expr: CelExpression<'static>,
        #[from(full_certification_cel)] cel_expr: DefaultFullCelExpression<'static>,
    ) {
        let req_path = "/?q=greeting";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let certification_path = HttpCertificationPath::exact("");

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

        let V2TreeFixture {
            tree_cbor,
            certified_data,
        } = create_v2_tree_fixture(req_path, &certification_tree_entry);
        let V2CertificateFixture {
            root_key,
            certificate_cbor,
            canister_id,
        } = create_v2_certificate_fixture(&certified_data, &current_time);
        let certificate_header =
            create_v2_header(&certification_tree_entry, &certificate_cbor, &tree_cbor);

        response
            .headers
            .push(("IC-Certificate".into(), certificate_header));
        let _ = std::mem::replace(
            &mut response.headers[0],
            (
                "IC-CertificateExpression".into(),
                wrong_cel_expr.to_string(),
            ),
        );

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
            Err(ResponseVerificationError::ExactExpressionPathMismatch { .. })
        ));
    }

    #[rstest]
    #[case::invalid_root_key_certificate(
        invalid_root_key_certificate(),
        ResponseVerificationError::CertificateVerificationFailed(
            CertificateVerificationError::SignatureVerificationFailed
        )
    )]
    #[case::expired_certificate(
        expired_certificate(),
        ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::TimeTooFarInThePast  { certificate_time: 0, min_certificate_time: 0 })
    )]
    #[case::future_certificate(
        future_certificate(),
        ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::TimeTooFarInTheFuture  { certificate_time: 0, max_certificate_time: 0 } )
    )]
    #[case::wrong_canister_certificate(
        wrong_canister_certificate(),
        ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::PrincipalOutOfRange { canister_id: Principal::anonymous(), canister_ranges: vec![] } )
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
            upgrade: None,
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
            matches!(result, Err(ref failure) if matches!((failure, expected_failure),
                (ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::SignatureVerificationFailed), ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::SignatureVerificationFailed)) |
                (ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::PrincipalOutOfRange { .. }), ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::PrincipalOutOfRange { .. })) |
                (ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::TimeTooFarInThePast { .. }), ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::TimeTooFarInThePast { .. })) |
                (ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::TimeTooFarInTheFuture { .. }), ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::TimeTooFarInTheFuture { .. }))
            ))
        );
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod fixtures {
    use ic_http_certification::{
        CelExpression, DefaultCelBuilder, DefaultFullCelExpression, DefaultResponseCertification,
        HttpCertification, HttpCertificationPath, HttpCertificationTreeEntry,
    };
    use ic_response_verification_test_utils::{
        create_v2_fixture, get_current_timestamp, get_timestamp, V2Fixture,
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
    pub fn full_certification_cel() -> DefaultFullCelExpression<'static> {
        DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["Cache-Control"])
            .with_request_query_parameters(vec!["q"])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["Cache-Control"],
            ))
            .build()
    }

    #[fixture]
    pub fn skip_certification_cel() -> CelExpression<'static> {
        DefaultCelBuilder::skip_certification()
    }

    pub fn invalid_root_key_certificate() -> (V2Fixture, u128, String) {
        let cel_expr = skip_certification_cel().to_string();
        let req_path = "/";
        let certification_path = HttpCertificationPath::exact("/");
        let current_time = get_current_timestamp();
        let certification = HttpCertification::skip();
        let certification_tree_entry =
            HttpCertificationTreeEntry::new(&certification_path, certification);

        let root_key = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";

        let v2_fixture = create_v2_fixture(req_path, &certification_tree_entry, &current_time);

        (
            V2Fixture {
                root_key: root_key.to_vec(),
                ..v2_fixture
            },
            current_time,
            cel_expr,
        )
    }

    pub fn expired_certificate() -> (V2Fixture, u128, String) {
        let cel_expr = skip_certification_cel().to_string();
        let req_path = "/";
        let certification_path = HttpCertificationPath::exact("/");
        let current_time = get_current_timestamp();
        let certification = HttpCertification::skip();
        let certification_tree_entry =
            HttpCertificationTreeEntry::new(&certification_path, certification);

        let max_cert_time_offset_s: u64 = (MAX_CERT_TIME_OFFSET_NS / 1_000_000_000)
            .try_into()
            .unwrap();
        let past_time =
            get_timestamp(SystemTime::now().sub(Duration::new(max_cert_time_offset_s + 1, 0)));

        let v2_fixture = create_v2_fixture(req_path, &certification_tree_entry, &past_time);

        (v2_fixture, current_time, cel_expr)
    }

    pub fn future_certificate() -> (V2Fixture, u128, String) {
        let cel_expr = skip_certification_cel().to_string();
        let req_path = "/";
        let certification_path = HttpCertificationPath::exact("/");
        let current_time = get_current_timestamp();
        let certification = HttpCertification::skip();
        let certification_tree_entry =
            HttpCertificationTreeEntry::new(&certification_path, certification);

        let max_cert_time_offset_s: u64 = (MAX_CERT_TIME_OFFSET_NS / 1_000_000_000)
            .try_into()
            .unwrap();
        let future_time =
            get_timestamp(SystemTime::now().add(Duration::new(max_cert_time_offset_s + 1, 0)));

        let v2_fixture = create_v2_fixture(req_path, &certification_tree_entry, &future_time);

        (v2_fixture, current_time, cel_expr)
    }

    pub fn wrong_canister_certificate() -> (V2Fixture, u128, String) {
        let cel_expr = skip_certification_cel().to_string();
        let req_path = "/";
        let certification_path = HttpCertificationPath::exact("/");
        let other_canister_id = CanisterId::from_u64(15);
        let current_time = get_current_timestamp();
        let certification = HttpCertification::skip();
        let certification_tree_entry =
            HttpCertificationTreeEntry::new(&certification_path, certification);

        let v2_fixture = create_v2_fixture(req_path, &certification_tree_entry, &current_time);

        (
            V2Fixture {
                canister_id: other_canister_id,
                ..v2_fixture
            },
            current_time,
            cel_expr,
        )
    }
}
