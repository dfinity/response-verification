#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use ic_response_verification::types::{Request, Response};
    use ic_response_verification::verify_request_response_pair;
    use ic_response_verification_test_utils::{
        create_canister_id, create_expr_tree_path, create_versioned_certificate_header,
        get_current_timestamp, hash, remove_whitespace, serialize_to_cbor, CanisterData,
        CertificateBuilder, CertificateData, ExprTree,
    };

    const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;

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
        let cel_expr_hash = hash(cel_expr.clone());

        let expr_tree_path = create_expr_tree_path(&expr_path, &cel_expr_hash, None, None);

        let mut expr_tree = ExprTree::new();
        expr_tree.insert(&expr_tree_path, body);
        let certified_data = expr_tree.get_certified_data();
        let tree_cbor = expr_tree.serialize_to_cbor(&expr_tree_path);

        let (_, root_key, certificate_cbor) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id,
                certified_data,
            }))
            .with_time(current_time)
            .build();

        let mut full_expr_path = vec!["http_expr"];
        full_expr_path.extend(expr_path);

        let certificate_header = create_versioned_certificate_header(
            &certificate_cbor,
            &tree_cbor,
            &serialize_to_cbor(&full_expr_path),
            2,
        );

        let request = Request {
            url: path.into(),
            method: "GET".into(),
            headers: vec![],
        };

        let response = Response {
            status_code: 200,
            body: body.as_bytes().to_vec(),
            headers: vec![
                ("IC-Certificate".into(), certificate_header),
                ("IC-CertificateExpression".into(), cel_expr),
            ],
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
        assert_eq!(result.response, None);
    }
}
