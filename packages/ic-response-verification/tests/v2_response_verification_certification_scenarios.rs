#[cfg(not(target_arch = "wasm32"))]
mod tests {
    use super::fixtures::{
        certificate_tree, index_html_response, MAX_CERT_TIME_OFFSET_NS,
        MIN_REQUESTED_VERIFICATION_VERSION,
    };
    use crate::fixtures::{
        content_encoding_deflate_response, content_encoding_gzip_response,
        content_encoding_identity_response, etag_caching_match_request,
        etag_caching_match_response, etag_caching_mismatch_request, etag_caching_mismatch_response,
        etag_certificate_tree, index_js_response, not_found_response, redirect_response,
    };
    use ic_http_certification::{HttpRequest, HttpResponse};
    use ic_response_verification::{
        types::{VerificationInfo, VerifiedResponse},
        verify_request_response_pair, ResponseVerificationError,
    };
    use ic_response_verification_test_utils::{
        create_v2_certificate_fixture, create_v2_header, get_current_timestamp, ExprTree,
        V2CertificateFixture,
    };
    use rstest::*;

    #[rstest]
    // assert that the index html fallback response is accepted for paths outside the js folder
    #[case::index_html_path(&"/", &["<*>"], index_html_response())]
    #[case::not_found_path(&"/not-found", &["<*>"], index_html_response())]
    #[case::not_found_trailing_slash_path(&"/not-found/", &["<*>"], index_html_response())]
    #[case::nested_not_found_path(&"/not/found", &["<*>"], index_html_response())]
    #[case::nested_not_found_trailing_slash_path(&"/not/found/", &["<*>"], index_html_response())]
    // assert that the asset not found response is accepted for paths inside the js folder
    #[case::index_js_path(&"/js/index.js", &["js", "index.js", "<$>"], index_js_response())]
    #[case::index_js_encoded_path(&"/j%73/index.js", &["js", "index.js", "<$>"], index_js_response())]
    #[case::js_not_found_path(&"/js/not-found", &["js", "<*>"], not_found_response())]
    #[case::js_not_found_trailing_slash_path(&"/js/not-found/", &["js", "<*>"], not_found_response())]
    #[case::js_nested_not_found_path(&"/js/not/found", &["js", "<*>"], not_found_response())]
    #[case::js_nested_not_found_trailing_slash_path(&"/js/not/found/", &["js", "<*>"], not_found_response())]
    // assert that the redirect response is accepted for the correct path
    #[case::old_path(&"/old-path", &["old-path", "<$>"], redirect_response())]
    // assert that any encoded response is accepted for the correct path
    #[case::identity_encoding(&"/multi-encoded-path", &["multi-encoded-path", "<$>"], content_encoding_identity_response())]
    #[case::gzip_encoding(&"/multi-encoded-path", &["multi-encoded-path", "<$>"], content_encoding_gzip_response())]
    #[case::deflate_encoding(&"/multi-encoded-path", &["multi-encoded-path", "<$>"], content_encoding_deflate_response())]
    fn certification_scenarios_pass_verification(
        #[from(certificate_tree)] expr_tree: ExprTree,
        #[case] req_path: &str,
        #[case] expr_path: &[&str],
        #[case] mut expected_response: HttpResponse,
    ) {
        let request = HttpRequest {
            url: req_path.into(),
            method: "GET".into(),
            headers: vec![
                ("Accept".into(), "text/html".into()),
                ("Accept-Encoding".into(), "gzip, deflate, br".into()),
            ],
            body: vec![],
        };

        let current_time = get_current_timestamp();

        let V2CertificateFixture {
            root_key,
            canister_id,
            certificate_cbor,
        } = create_v2_certificate_fixture(&expr_tree.get_certified_data(), &current_time);
        let certificate_header = create_v2_header(
            &expr_path,
            &certificate_cbor,
            &expr_tree.serialize_to_cbor(),
        );

        let expected_certified_response = VerifiedResponse {
            body: expected_response.body.clone(),
            headers: expected_response
                .headers
                .iter()
                .map(|(key, value)| (key.to_lowercase(), String::from(value)))
                .filter(|(key, _)| key != "ic-certificateexpression")
                .collect::<Vec<_>>()
                .clone(),
            status_code: Some(expected_response.status_code.clone()),
        };

        expected_response
            .headers
            .push(("IC-Certificate".to_string(), certificate_header));

        let result = verify_request_response_pair(
            request,
            expected_response,
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
            } if verification_version == 2 && response == Some(expected_certified_response)
        ));
    }

    #[rstest]
    // assert that the asset not found response is not accepted for assets outside the js folder
    #[case::not_found_for_index_html_path(&"/", &["js",  "<*>"], not_found_response())]
    #[case::not_found_for_not_found_path(&"/not-found", &["js",  "<*>"], not_found_response())]
    #[case::not_found_for_not_found_trailing_slash_path(&"/not-found/", &["js",  "<*>"], not_found_response())]
    #[case::not_found_for_nested_not_found_path(&"/not/found", &["js",  "<*>"], not_found_response())]
    #[case::not_found_for_nested_not_found_trailing_slash_path(&"/not/found/", &["js",  "<*>"], not_found_response())]
    #[case::not_found_for_old_path(&"/old-path", &["js",  "<*>"], not_found_response())]
    // assert that the index html fallback response is not accepted for assets inside the js folder
    #[case::index_html_for_js_path(&"/js/index.js", &["<*>"], index_html_response())]
    #[case::index_html_for_js_not_found_path(&"/js/not-found", &["<*>"], index_html_response())]
    #[case::index_html_for_js_not_found_trailing_slash_path(&"/js/not-found/", &["<*>"], index_html_response())]
    #[case::index_html_for_js_nested_not_found_path(&"/js/not/found", &["<*>"], index_html_response())]
    #[case::index_html_for_js_nested_not_found_trailing_slash_path(&"/js/not/found/", &["<*>"], index_html_response())]
    #[case::index_html_for_old_path(&"/old-path", &["<*>"], index_html_response())]
    // assert that the redirect response is not accepted for incorrect paths
    #[case::redirect_for_old_trailing_slash_path(&"/old-path/", &["old-path", "<$>"], redirect_response())]
    #[case::redirect_for_index_html_path(&"/", &["old-path", "<$>"], redirect_response())]
    #[case::redirect_for_not_found_path(&"/not-found", &["old-path", "<$>"], redirect_response())]
    #[case::redirect_for_nested_not_found_path(&"/not/found", &["old-path", "<$>"], redirect_response())]
    #[case::redirect_for_js_path(&"/js/index.js", &["<*>"], index_html_response())]
    #[case::redirect_for_js_not_found_path(&"/js/not-found", &["<*>"], index_html_response())]
    #[case::redirect_for_js_nested_not_found_path(&"/js/not/found", &["<*>"], index_html_response())]
    // assert that encoded responses are accepted for the incorrect paths
    #[case::identity_encoding_for_encoded_trailing_slash_path(&"/multi-encoded-path/", &["multi-encoded-path", "<$>"], content_encoding_identity_response())]
    #[case::gzip_encoding_for_encoded_trailing_slash_path(&"/multi-encoded-path/", &["multi-encoded-path", "<$>"], content_encoding_gzip_response())]
    #[case::deflate_encoding_for_encoded_trailing_slash_path(&"/multi-encoded-path/", &["multi-encoded-path", "<$>"], content_encoding_deflate_response())]
    #[case::identity_encoding_for_index_html_path(&"/", &["multi-encoded-path", "<$>"], content_encoding_identity_response())]
    #[case::gzip_encoding_for_not_found_path(&"/not-found", &["multi-encoded-path", "<$>"], content_encoding_gzip_response())]
    #[case::gzip_encoding_for_nested_not_found_path(&"/not/found", &["multi-encoded-path", "<$>"], content_encoding_gzip_response())]
    #[case::deflate_encoding_for_js_path(&"/js/index.js", &["multi-encoded-path", "<$>"], content_encoding_deflate_response())]
    #[case::deflate_encoding_for_js_not_found_path(&"/js/not-found", &["multi-encoded-path", "<$>"], content_encoding_deflate_response())]
    #[case::deflate_encoding_for_nested_js_not_found_path(&"/js/not/found", &["multi-encoded-path", "<$>"], content_encoding_deflate_response())]
    fn certification_scenarios_fail_verification(
        #[from(certificate_tree)] expr_tree: ExprTree,
        #[case] req_path: &str,
        #[case] expr_path: &[&str],
        #[case] mut expected_response: HttpResponse,
    ) {
        let request = HttpRequest {
            url: req_path.into(),
            method: "GET".into(),
            headers: vec![
                ("Accept".into(), "text/html".into()),
                ("Accept-Encoding".into(), "gzip, deflate, br".into()),
            ],
            body: vec![],
        };

        let current_time = get_current_timestamp();

        let V2CertificateFixture {
            root_key,
            canister_id,
            certificate_cbor,
        } = create_v2_certificate_fixture(&expr_tree.get_certified_data(), &current_time);
        let certificate_header = create_v2_header(
            &expr_path,
            &certificate_cbor,
            &expr_tree.serialize_to_cbor(),
        );

        expected_response
            .headers
            .push(("IC-Certificate".to_string(), certificate_header));

        let result = verify_request_response_pair(
            request,
            expected_response,
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
    #[case::etag_match(etag_caching_match_request(), etag_caching_match_response())]
    #[case::etag_match_mismatch_response(
        etag_caching_match_request(),
        etag_caching_mismatch_response()
    )]
    #[case::etag_match_mismatch_response(
        etag_caching_mismatch_request(),
        etag_caching_mismatch_response()
    )]
    fn etag_scenarios_pass_verification(
        #[from(etag_certificate_tree)] expr_tree: ExprTree,
        #[case] request: HttpRequest,
        #[case] mut expected_response: HttpResponse,
    ) {
        let expr_path = ["app", "<$>"];
        let current_time = get_current_timestamp();

        let V2CertificateFixture {
            root_key,
            canister_id,
            certificate_cbor,
        } = create_v2_certificate_fixture(&expr_tree.get_certified_data(), &current_time);
        let certificate_header = create_v2_header(
            &expr_path,
            &certificate_cbor,
            &expr_tree.serialize_to_cbor(),
        );

        let expected_certified_response = VerifiedResponse {
            body: expected_response.body.clone(),
            headers: expected_response
                .headers
                .iter()
                .map(|(key, value)| (key.to_lowercase(), String::from(value)))
                .filter(|(key, _)| key != "ic-certificateexpression")
                .collect::<Vec<_>>()
                .clone(),
            status_code: Some(expected_response.status_code.clone()),
        };

        expected_response
            .headers
            .push(("IC-Certificate".to_string(), certificate_header));

        let result = verify_request_response_pair(
            request,
            expected_response,
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
            } if verification_version == 2 && response == Some(expected_certified_response)
        ));
    }

    #[rstest]
    fn etag_scenarios_fail_verification(
        #[from(etag_certificate_tree)] expr_tree: ExprTree,
        #[from(etag_caching_mismatch_request)] request: HttpRequest,
        #[from(etag_caching_match_response)] mut expected_response: HttpResponse,
    ) {
        let expr_path = ["app", "<$>"];
        let current_time = get_current_timestamp();

        let V2CertificateFixture {
            root_key,
            canister_id,
            certificate_cbor,
        } = create_v2_certificate_fixture(&expr_tree.get_certified_data(), &current_time);
        let certificate_header = create_v2_header(
            &expr_path,
            &certificate_cbor,
            &expr_tree.serialize_to_cbor(),
        );

        expected_response
            .headers
            .push(("IC-Certificate".to_string(), certificate_header));

        let result = verify_request_response_pair(
            request,
            expected_response,
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
}

#[cfg(not(target_arch = "wasm32"))]
mod fixtures {
    use ic_http_certification::{
        request_hash, response_hash, DefaultCelBuilder, DefaultFullCelExpression,
        DefaultResponseCertification, DefaultResponseOnlyCelExpression, HttpRequest, HttpResponse,
    };
    use ic_response_verification_test_utils::{
        create_expr_tree_path, deflate_encode, gzip_encode, hash, ExprTree,
    };
    use rstest::*;

    pub const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;
    pub const MIN_REQUESTED_VERIFICATION_VERSION: u8 = 2;

    #[fixture]
    pub fn html_body() -> Vec<u8> {
        br#"<!DOCTYPE html><html lang="en"><head><title>Hello World</title></head><body><h1>Hello World</h1></body></html>"#.to_vec()
    }

    #[fixture]
    pub fn index_html_response() -> HttpResponse {
        let cel = asset_cel();

        HttpResponse {
            status_code: 200,
            body: gzip_encode(&html_body()),
            headers: vec![
                ("Content-Type".into(), "text/html".into()),
                ("Content-Encoding".into(), "gzip".into()),
                ("IC-CertificateExpression".into(), cel.to_string()),
            ],
        }
    }

    #[fixture]
    pub fn index_js_response() -> HttpResponse {
        let cel = asset_cel();
        let body = br#"window.onload=function(){console.log("Hello World")};"#;

        HttpResponse {
            status_code: 200,
            body: gzip_encode(body),
            headers: vec![
                ("Content-Type".into(), "text/javascript".into()),
                ("Content-Encoding".into(), "gzip".into()),
                ("IC-CertificateExpression".into(), cel.to_string()),
            ],
        }
    }

    #[fixture]
    pub fn not_found_response() -> HttpResponse {
        let cel = asset_cel();
        let body = br#"Not Found"#;

        HttpResponse {
            status_code: 404,
            body: body.to_vec(),
            headers: vec![
                ("Content-Type".into(), "text/plain".into()),
                ("Content-Encoding".into(), "identity".into()),
                ("IC-CertificateExpression".into(), cel.to_string()),
            ],
        }
    }

    #[fixture]
    pub fn redirect_response() -> HttpResponse {
        let cel = redirect_cel();
        let body = br#"Moved Permanently"#;

        HttpResponse {
            status_code: 301,
            body: body.to_vec(),
            headers: vec![
                ("Location".into(), "/new-path".into()),
                ("IC-CertificateExpression".into(), cel.to_string()),
            ],
        }
    }

    #[fixture]
    pub fn content_encoding_identity_response() -> HttpResponse {
        let cel = asset_cel();

        HttpResponse {
            status_code: 200,
            body: html_body(),
            headers: vec![
                ("Content-Type".into(), "text/html".into()),
                ("Content-Encoding".into(), "identity".into()),
                ("IC-CertificateExpression".into(), cel.to_string()),
            ],
        }
    }

    #[fixture]
    pub fn content_encoding_gzip_response() -> HttpResponse {
        let cel = asset_cel();

        HttpResponse {
            status_code: 200,
            body: gzip_encode(&html_body()),
            headers: vec![
                ("Content-Type".into(), "text/html".into()),
                ("Content-Encoding".into(), "gzip".into()),
                ("IC-CertificateExpression".into(), cel.to_string()),
            ],
        }
    }

    #[fixture]
    pub fn content_encoding_deflate_response() -> HttpResponse {
        let cel = asset_cel();

        HttpResponse {
            status_code: 200,
            body: deflate_encode(&html_body()),
            headers: vec![
                ("Content-Type".into(), "text/html".into()),
                ("Content-Encoding".into(), "deflate".into()),
                ("IC-CertificateExpression".into(), cel.to_string()),
            ],
        }
    }

    #[fixture]
    pub fn etag_caching_match_request() -> HttpRequest {
        let etag = hex::encode(hash(html_body().as_slice()));

        HttpRequest {
            url: "/app".into(),
            method: "GET".into(),
            headers: vec![
                ("Accept".into(), "text/html".into()),
                ("Accept-Encoding".into(), "gzip, deflate, br".into()),
                ("If-None-Match".into(), etag),
            ],
            body: vec![],
        }
    }

    #[fixture]
    pub fn etag_caching_match_response() -> HttpResponse {
        let cel = etag_caching_match_cel();
        let body = br#"Not Modified"#;

        HttpResponse {
            status_code: 304,
            body: body.to_vec(),
            headers: vec![
                ("Content-Type".into(), "text/html".into()),
                ("Content-Encoding".into(), "deflate".into()),
                ("IC-CertificateExpression".into(), cel.to_string()),
            ],
        }
    }

    #[fixture]
    pub fn etag_caching_mismatch_request() -> HttpRequest {
        HttpRequest {
            url: "/app".into(),
            method: "GET".into(),
            headers: vec![
                ("Accept".into(), "text/html".into()),
                ("Accept-Encoding".into(), "gzip, deflate, br".into()),
                (
                    "If-None-Match".into(),
                    "5fd924625f6ab16a19cc9807c7c506ae1813490e4ba675f843d5a10e0baacdb8".into(),
                ),
            ],
            body: vec![],
        }
    }

    #[fixture]
    pub fn etag_caching_mismatch_response() -> HttpResponse {
        let cel = etag_caching_mismatch_cel();
        let etag = hex::encode(hash(html_body().as_slice()));

        HttpResponse {
            status_code: 200,
            body: deflate_encode(&html_body()),
            headers: vec![
                ("Content-Type".into(), "text/html".into()),
                ("Content-Encoding".into(), "deflate".into()),
                ("ETag".into(), etag),
                ("IC-CertificateExpression".into(), cel.to_string()),
            ],
        }
    }

    #[fixture]
    pub fn asset_cel() -> DefaultResponseOnlyCelExpression<'static> {
        DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                &["Content-Type", "Content-Encoding"],
            ))
            .build()
    }

    #[fixture]
    pub fn redirect_cel() -> DefaultResponseOnlyCelExpression<'static> {
        DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                &["Location"],
            ))
            .build()
    }

    #[fixture]
    pub fn etag_caching_match_cel() -> DefaultFullCelExpression<'static> {
        DefaultCelBuilder::full_certification()
            .with_request_headers(&["If-None-Match"])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                &["Content-Type", "Content-Encoding", "ETag"],
            ))
            .build()
    }

    #[fixture]
    pub fn etag_caching_mismatch_cel() -> DefaultResponseOnlyCelExpression<'static> {
        DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                &["Content-Type", "Content-Encoding", "ETag"],
            ))
            .build()
    }

    #[fixture]
    pub fn certificate_tree() -> ExprTree {
        let asset_certification = asset_cel();
        let asset_cel = asset_certification.to_string();
        let asset_cel_hash = hash(asset_cel.as_bytes());

        let index_html_response_hash =
            response_hash(&index_html_response(), &asset_certification.response, None);
        let index_js_response_hash =
            response_hash(&index_js_response(), &asset_certification.response, None);
        let not_found_response_hash =
            response_hash(&not_found_response(), &asset_certification.response, None);

        let redirect_certification = redirect_cel();
        let redirect_cel = redirect_certification.to_string();
        let redirect_cel_hash = hash(redirect_cel.as_bytes());

        let redirect_response_hash =
            response_hash(&redirect_response(), &redirect_certification.response, None);

        let content_encoding_identity_response_hash = response_hash(
            &content_encoding_identity_response(),
            &asset_certification.response,
            None,
        );
        let content_encoding_gzip_response_hash = response_hash(
            &content_encoding_gzip_response(),
            &asset_certification.response,
            None,
        );
        let content_encoding_deflate_response_hash = response_hash(
            &content_encoding_deflate_response(),
            &asset_certification.response,
            None,
        );

        let mut expr_tree = ExprTree::new();
        expr_tree.insert(&create_expr_tree_path(
            &["<*>"],
            &asset_cel_hash,
            None,
            Some(&index_html_response_hash),
        ));
        expr_tree.insert(&create_expr_tree_path(
            &["js", "index.js", "<$>"],
            &asset_cel_hash,
            None,
            Some(&index_js_response_hash),
        ));
        expr_tree.insert(&create_expr_tree_path(
            &["js", "<*>"],
            &asset_cel_hash,
            None,
            Some(&not_found_response_hash),
        ));
        expr_tree.insert(&create_expr_tree_path(
            &["old-path", "<$>"],
            &redirect_cel_hash,
            None,
            Some(&redirect_response_hash),
        ));
        expr_tree.insert(&create_expr_tree_path(
            &["multi-encoded-path", "<$>"],
            &asset_cel_hash,
            None,
            Some(&content_encoding_identity_response_hash),
        ));
        expr_tree.insert(&create_expr_tree_path(
            &["multi-encoded-path", "<$>"],
            &asset_cel_hash,
            None,
            Some(&content_encoding_gzip_response_hash),
        ));
        expr_tree.insert(&create_expr_tree_path(
            &["multi-encoded-path", "<$>"],
            &asset_cel_hash,
            None,
            Some(&content_encoding_deflate_response_hash),
        ));

        expr_tree
    }

    #[fixture]
    pub fn etag_certificate_tree() -> ExprTree {
        let etag_caching_match_certification = etag_caching_match_cel();
        let etag_caching_match_cel = etag_caching_match_certification.to_string();
        let etag_caching_match_cel_hash = hash(etag_caching_match_cel.as_bytes());

        let etag_caching_match_response_hash = response_hash(
            &etag_caching_match_response(),
            &etag_caching_match_certification.response,
            None,
        );
        let etag_caching_match_request_hash = request_hash(
            &etag_caching_match_request(),
            &etag_caching_match_certification.request,
        )
        .unwrap();

        let etag_caching_mismatch_certification = etag_caching_mismatch_cel();
        let etag_caching_mismatch_cel = etag_caching_mismatch_certification.to_string();
        let etag_caching_mismatch_cel_hash = hash(etag_caching_mismatch_cel.as_bytes());

        let etag_caching_mismatch_response_hash = response_hash(
            &etag_caching_mismatch_response(),
            &etag_caching_mismatch_certification.response,
            None,
        );

        let mut expr_tree = ExprTree::new();
        expr_tree.insert(&create_expr_tree_path(
            &["app", "", "<$>"],
            &etag_caching_mismatch_cel_hash,
            None,
            Some(&etag_caching_mismatch_response_hash),
        ));
        expr_tree.insert(&create_expr_tree_path(
            &["app", "<$>"],
            &etag_caching_mismatch_cel_hash,
            None,
            Some(&etag_caching_mismatch_response_hash),
        ));
        expr_tree.insert(&create_expr_tree_path(
            &["app", "", "<$>"],
            &etag_caching_match_cel_hash,
            Some(&etag_caching_match_request_hash),
            Some(&etag_caching_match_response_hash),
        ));
        expr_tree.insert(&create_expr_tree_path(
            &["app", "<$>"],
            &etag_caching_match_cel_hash,
            Some(&etag_caching_match_request_hash),
            Some(&etag_caching_match_response_hash),
        ));

        expr_tree
    }
}
