#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use ic_response_verification::types::{CertifiedResponse, Request, Response};
    use ic_response_verification::verify_request_response_pair;
    use ic_response_verification::ResponseVerificationError;
    use ic_response_verification_test_utils::{
        create_canister_id, create_certificate_header, create_certified_data,
        get_current_timestamp, get_timestamp, AssetTree, CanisterData, CertificateBuilder,
        CertificateData,
    };
    use std::ops::{Add, Sub};
    use std::time::{Duration, SystemTime};

    const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;

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

        let (_, root_key, certificate_cbor) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id,
                certified_data,
            }))
            .with_time(current_time)
            .build();

        let certificate_header = create_certificate_header(&certificate_cbor, &tree_cbor);

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };

        let response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
        };
        let expected_response = CertifiedResponse {
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
        )
        .unwrap();

        assert!(result.passed);
        assert_eq!(result.response, Some(expected_response));
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

        let (_, root_key, certificate_cbor) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id,
                certified_data,
            }))
            .with_time(current_time)
            .build();

        let certificate_header = create_certificate_header(&certificate_cbor, &tree_cbor);

        let request = Request {
            url: "/".into(),
            method: "GET".into(),
            headers: vec![],
        };

        let response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
        };
        let expected_response = CertifiedResponse {
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
        )
        .unwrap();

        assert!(result.passed);
        assert_eq!(result.response, Some(expected_response));
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

        let (_, root_key, certificate_cbor) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id,
                certified_data,
            }))
            .with_time(current_time)
            .build();

        let certificate_header = create_certificate_header(&certificate_cbor, &tree_cbor);

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };

        let response = Response {
            status_code: 200,
            body: b"Hello IC!".to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
        };

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
        )
        .unwrap();

        assert!(!result.passed);
        assert!(result.response.is_none());
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

        let (_, _, certificate_cbor) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id,
                certified_data,
            }))
            .with_time(current_time)
            .build();

        let certificate_header = create_certificate_header(&certificate_cbor, &tree_cbor);

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };

        let response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
        };

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            root_key,
        );

        assert!(matches!(
            result,
            Err(ResponseVerificationError::CertificateVerificationFailed)
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

        let (_, root_key, certificate_cbor) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id,
                certified_data,
            }))
            .with_time(certificate_time)
            .build();

        let certificate_header = create_certificate_header(&certificate_cbor, &tree_cbor);

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };

        let response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
        };

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
        );

        assert!(matches!(
            result,
            Err(ResponseVerificationError::CertificateTimeTooFarInTheFuture {
                certificate_time,
                max_certificate_time
            }) if certificate_time == certificate_time &&
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

        let (_, root_key, certificate_cbor) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id,
                certified_data,
            }))
            .with_time(certificate_time)
            .build();

        let certificate_header = create_certificate_header(&certificate_cbor, &tree_cbor);

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };

        let response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
        };

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
        );

        assert!(matches!(
            result,
            Err(ResponseVerificationError::CertificateTimeTooFarInThePast {
                certificate_time,
                min_certificate_time
            }) if certificate_time == certificate_time &&
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

        let (_, root_key, certificate_cbor) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id: other_canister_id,
                certified_data,
            }))
            .with_time(current_time)
            .build();

        let certificate_header = create_certificate_header(&certificate_cbor, &tree_cbor);

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };

        let response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
        };

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
        )
        .unwrap();

        assert!(!result.passed);
        assert!(result.response.is_none());
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

        let (_, root_key, certificate_cbor) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id,
                certified_data,
            }))
            .with_time(current_time)
            .build();

        let certificate_header = create_certificate_header(&certificate_cbor, &tree_cbor);

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };

        let response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
        };

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
        )
        .unwrap();

        assert!(!result.passed);
        assert!(result.response.is_none());
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

        let (_, root_key, certificate_cbor) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id,
                certified_data,
            }))
            .with_time(current_time)
            .build();

        let certificate_header = create_certificate_header(&certificate_cbor, &tree_cbor);

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };

        let response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![("IC-Certificate".into(), certificate_header)],
        };

        let result = verify_request_response_pair(
            request,
            response,
            canister_id.as_ref(),
            current_time,
            MAX_CERT_TIME_OFFSET_NS,
            &root_key,
        )
        .unwrap();

        assert!(!result.passed);
        assert!(result.response.is_none());
    }
}
