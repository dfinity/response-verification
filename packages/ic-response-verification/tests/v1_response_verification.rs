#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use ic_response_verification::types::{Request, Response};
    use ic_response_verification::verify_request_response_pair;
    use ic_response_verification_test_utils::{
        create_canister_id, create_certificate_header, get_current_timestamp, AssetTree,
        CanisterData, CertificateBuilder, CertificateData,
    };

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
        let expected_response = Response {
            status_code: response.status_code,
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
        let expected_response = Response {
            status_code: response.status_code,
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
}
