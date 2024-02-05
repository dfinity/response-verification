mod tests {
    use ic_certificate_verification::CertificateVerificationError;
    use ic_certification_testing::{CertificateBuilder, CertificateData};
    use ic_http_certification::{HttpRequest, HttpResponse};
    use ic_response_verification::types::{VerificationInfo, VerifiedResponse};
    use ic_response_verification::verify_request_response_pair;
    use ic_response_verification::ResponseVerificationError;
    use ic_response_verification_test_utils::{
        create_canister_id, create_certificate_header, create_certified_data,
        get_current_timestamp, get_timestamp, AssetTree,
    };
    use std::ops::{Add, Sub};
    use std::time::{Duration, SystemTime};

    const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;
    const MIN_REQUESTED_VERIFICATION_VERSION: u8 = 1;

    #[test]
    fn standard_certification_passes_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");

        let mut asset_tree = AssetTree::new();
        asset_tree.insert(path, body);
        let certified_data = asset_tree.get_certified_data();
        let tree_cbor = asset_tree.serialize_to_cbor(Some(path));

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .with_time(current_time)
            .build()
            .unwrap();

        let certificate_header = create_certificate_header(&cbor_encoded_certificate, &tree_cbor);

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
            upgrade: None,
        };
        let expected_response = VerifiedResponse {
            status_code: None,
            body: response.body.clone(),
            headers: vec![],
        };

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
            } if verification_version == 1 && response == Some(expected_response)
        ));
    }

    #[test]
    fn standard_certification_with_encoded_url_passes_verification() {
        let path = "/sample-asset.txt";
        let encoded_path = "/%73ample-asset.txt";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");

        let mut asset_tree = AssetTree::new();
        asset_tree.insert(path, body);
        let certified_data = asset_tree.get_certified_data();
        let tree_cbor = asset_tree.serialize_to_cbor(Some(path));

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .with_time(current_time)
            .build()
            .unwrap();

        let certificate_header = create_certificate_header(&cbor_encoded_certificate, &tree_cbor);

        let request = HttpRequest {
            url: encoded_path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
            upgrade: None,
        };
        let expected_response = VerifiedResponse {
            status_code: None,
            body: response.body.clone(),
            headers: vec![],
        };

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
            } if verification_version == 1 && response == Some(expected_response)
        ));
    }

    #[test]
    fn index_html_fallback_certification_passes_verification() {
        let path = "/index.html";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");

        let mut asset_tree = AssetTree::new();
        asset_tree.insert(path, body);
        let certified_data = asset_tree.get_certified_data();
        let tree_cbor = asset_tree.serialize_to_cbor(Some(path));

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .with_time(current_time)
            .build()
            .unwrap();

        let certificate_header = create_certificate_header(&cbor_encoded_certificate, &tree_cbor);

        let request = HttpRequest {
            url: "/".into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
            upgrade: None,
        };
        let expected_response = VerifiedResponse {
            status_code: None,
            body: response.body.clone(),
            headers: vec![],
        };

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
            } if verification_version == 1 && response == Some(expected_response)
        ));
    }

    #[test]
    fn certification_with_mismatched_body_fails_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");

        let mut asset_tree = AssetTree::new();
        asset_tree.insert(path, body);
        let certified_data = asset_tree.get_certified_data();
        let tree_cbor = asset_tree.serialize_to_cbor(Some(path));

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .with_time(current_time)
            .build()
            .unwrap();

        let certificate_header = create_certificate_header(&cbor_encoded_certificate, &tree_cbor);

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: b"Hello IC!".to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
            upgrade: None,
        };

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
            Err(ResponseVerificationError::InvalidResponseBody)
        ));
    }

    #[test]
    fn certification_with_mismatched_root_key_fails_verification() {
        let root_key: &[u8] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x08\x1a\x0b\xaa\xae";
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");

        let mut asset_tree = AssetTree::new();
        asset_tree.insert(path, body);
        let certified_data = asset_tree.get_certified_data();
        let tree_cbor = asset_tree.serialize_to_cbor(Some(path));

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key: _,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .with_time(current_time)
            .build()
            .unwrap();

        let certificate_header = create_certificate_header(&cbor_encoded_certificate, &tree_cbor);

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
            upgrade: None,
        };

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            root_key,
            MIN_REQUESTED_VERIFICATION_VERSION,
        );

        assert!(matches!(
            result,
            Err(ResponseVerificationError::CertificateVerificationFailed(
                CertificateVerificationError::SignatureVerificationFailed
            ))
        ));
    }

    #[test]
    fn certification_with_timestamp_too_far_in_the_future_fails_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let certificate_time = get_timestamp(
            SystemTime::now().add(Duration::new(300, MAX_CERT_TIME_OFFSET_NS as u32)),
        );
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");

        let mut asset_tree = AssetTree::new();
        asset_tree.insert(path, body);
        let certified_data = asset_tree.get_certified_data();
        let tree_cbor = asset_tree.serialize_to_cbor(Some(path));

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .with_time(certificate_time)
            .build()
            .unwrap();

        let certificate_header = create_certificate_header(&cbor_encoded_certificate, &tree_cbor);

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
            upgrade: None,
        };

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
            Err(ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::TimeTooFarInTheFuture {
                certificate_time,
                max_certificate_time
            })) if certificate_time == certificate_time &&
            max_certificate_time == current_time + MAX_CERT_TIME_OFFSET_NS
        ));
    }

    #[test]
    fn certification_with_timestamp_too_far_in_the_past_fails_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let certificate_time = get_timestamp(
            SystemTime::now().sub(Duration::new(300, MAX_CERT_TIME_OFFSET_NS as u32)),
        );
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");

        let mut asset_tree = AssetTree::new();
        asset_tree.insert(path, body);
        let certified_data = asset_tree.get_certified_data();
        let tree_cbor = asset_tree.serialize_to_cbor(Some(path));

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .with_time(certificate_time)
            .build()
            .unwrap();

        let certificate_header = create_certificate_header(&cbor_encoded_certificate, &tree_cbor);

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
            upgrade: None,
        };

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
            Err(ResponseVerificationError::CertificateVerificationFailed(CertificateVerificationError::TimeTooFarInThePast {
                certificate_time,
                min_certificate_time
            })) if certificate_time == certificate_time &&
            min_certificate_time == current_time - MAX_CERT_TIME_OFFSET_NS
        ));
    }

    #[test]
    fn certification_for_another_canister_fails_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");
        let other_canister_id = create_canister_id("qoctq-giaaa-aaaaa-aaaea-cai");

        let mut asset_tree = AssetTree::new();
        asset_tree.insert(path, body);
        let certified_data = asset_tree.get_certified_data();
        let tree_cbor = asset_tree.serialize_to_cbor(Some(path));

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(&other_canister_id.to_string(), &certified_data)
            .unwrap()
            .with_time(current_time)
            .build()
            .unwrap();

        let certificate_header = create_certificate_header(&cbor_encoded_certificate, &tree_cbor);

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
            upgrade: None,
        };

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
            Err(ResponseVerificationError::InvalidTree)
        ));
    }

    #[test]
    fn certification_with_invalid_witness_fails_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");
        let certified_data = create_certified_data(
            "8160c07b45d617dba08a20eaa71ace28b5962965034b7539e42ebdb80da729a9",
        );

        let mut asset_tree = AssetTree::new();
        asset_tree.insert(path, body);
        let tree_cbor = asset_tree.serialize_to_cbor(Some(path));

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .with_time(current_time)
            .build()
            .unwrap();

        let certificate_header = create_certificate_header(&cbor_encoded_certificate, &tree_cbor);

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
            upgrade: None,
        };

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
            Err(ResponseVerificationError::InvalidTree)
        ));
    }

    #[test]
    fn certification_with_missing_asset_fails_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");

        let mut asset_tree = AssetTree::new();
        asset_tree.insert("/other-path", body);
        let certified_data = asset_tree.get_certified_data();
        let tree_cbor = asset_tree.serialize_to_cbor(Some(path));

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .with_time(current_time)
            .build()
            .unwrap();

        let certificate_header = create_certificate_header(&cbor_encoded_certificate, &tree_cbor);

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
            upgrade: None,
        };

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
            Err(ResponseVerificationError::InvalidResponseBody)
        ));
    }

    #[test]
    fn certification_with_mismatched_version_fails_verification() {
        let path = "/";
        let body = "Hello World!";
        let current_time = get_current_timestamp();
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");

        let mut asset_tree = AssetTree::new();
        asset_tree.insert(path, body);
        let certified_data = asset_tree.get_certified_data();
        let tree_cbor = asset_tree.serialize_to_cbor(Some(path));

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .with_time(current_time)
            .build()
            .unwrap();

        let certificate_header = create_certificate_header(&cbor_encoded_certificate, &tree_cbor);

        let request = HttpRequest {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
            upgrade: None,
        };

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
            2,
        );

        assert!(matches!(
            result,
            Err(
                ResponseVerificationError::RequestedVerificationVersionMismatch {
                    min_requested_verification_version: 2,
                    requested_version: 1
                }
            )
        ));
    }
}
