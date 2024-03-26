mod tests {
    use super::fixtures::{
        certificate_tree, index_html_response, MAX_CERT_TIME_OFFSET_NS,
        MIN_REQUESTED_VERIFICATION_VERSION,
    };
    use crate::fixtures::{
        content_encoding_deflate_certification, content_encoding_deflate_response,
        content_encoding_gzip_certification, content_encoding_gzip_response,
        content_encoding_identity_certification, content_encoding_identity_response,
        etag_caching_match_certification, etag_caching_match_request, etag_caching_match_response,
        etag_caching_mismatch_certification, etag_caching_mismatch_request,
        etag_caching_mismatch_response, etag_certificate_tree, index_html_certification,
        index_js_certification, index_js_response, not_found_certification, not_found_response,
        redirect_certification, redirect_response,
    };
    use ic_http_certification::{
        HttpCertificationPath, HttpCertificationTree, HttpCertificationTreeEntry, HttpRequest,
        HttpResponse,
    };
    use ic_response_verification::{
        types::{VerificationInfo, VerifiedResponse},
        verify_request_response_pair, ResponseVerificationError,
    };
    use ic_response_verification_test_utils::{
        cbor_encode, create_v2_certificate_fixture, create_v2_header, get_current_timestamp,
        V2CertificateFixture,
    };
    use rstest::*;

    #[rstest]
    // assert that the index html fallback response is accepted for paths outside the js folder
    #[case::index_html_path(&"/", index_html_response(), index_html_certification())]
    #[case::not_found_path(&"/not-found", index_html_response(), index_html_certification())]
    #[case::not_found_trailing_slash_path(&"/not-found/", index_html_response(), index_html_certification())]
    #[case::nested_not_found_path(&"/not/found", index_html_response(), index_html_certification())]
    #[case::nested_not_found_trailing_slash_path(&"/not/found/", index_html_response(), index_html_certification())]
    // assert that the asset not found response is accepted for paths inside the js folder
    #[case::index_js_path(&"/js/index.js", index_js_response(), index_js_certification())]
    #[case::index_js_encoded_path(&"/j%73/index.js", index_js_response(), index_js_certification())]
    #[case::js_not_found_path(&"/js/not-found", not_found_response(), not_found_certification())]
    #[case::js_not_found_trailing_slash_path(&"/js/not-found/", not_found_response(), not_found_certification())]
    #[case::js_nested_not_found_path(&"/js/not/found", not_found_response(), not_found_certification())]
    #[case::js_nested_not_found_trailing_slash_path(&"/js/not/found/", not_found_response(), not_found_certification())]
    // assert that the redirect response is accepted for the correct path
    #[case::old_path(&"/old-path", redirect_response(), redirect_certification())]
    // assert that any encoded response is accepted for the correct path
    #[case::identity_encoding(&"/multi-encoded-path", content_encoding_identity_response(), content_encoding_identity_certification())]
    #[case::gzip_encoding(&"/multi-encoded-path", content_encoding_gzip_response(), content_encoding_gzip_certification())]
    #[case::deflate_encoding(&"/multi-encoded-path", content_encoding_deflate_response(), content_encoding_deflate_certification())]
    fn certification_scenarios_pass_verification(
        #[from(certificate_tree)] certification_tree: HttpCertificationTree,
        #[case] req_path: &str,
        #[case] mut expected_response: HttpResponse,
        #[case] certification_tree_entry: HttpCertificationTreeEntry<'static>,
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
        } = create_v2_certificate_fixture(&certification_tree.root_hash(), &current_time);
        let certificate_header = create_v2_header(
            &certification_tree_entry,
            &certificate_cbor,
            &cbor_encode(
                &certification_tree
                    .witness(&certification_tree_entry, req_path)
                    .unwrap(),
            ),
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
            status_code: Some(expected_response.status_code),
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
    // assert that the index html fallback response is not accepted for assets inside the js folder
    #[case::index_html_for_js_not_found_path(&"/js/not-found", index_html_response(), index_html_certification())]
    #[case::index_html_for_js_not_found_trailing_slash_path(&"/js/not-found/", index_html_response(), index_html_certification())]
    #[case::index_html_for_js_nested_not_found_path(&"/js/not/found", index_html_response(), index_html_certification())]
    #[case::index_html_for_js_nested_not_found_trailing_slash_path(&"/js/not/found/", index_html_response(), index_html_certification())]

    fn more_specific_wildcard_might_exist_fails_verification(
        #[from(certificate_tree)] certification_tree: HttpCertificationTree,
        #[case] req_path: &str,
        #[case] mut expected_response: HttpResponse,
        #[case] certification_tree_entry: HttpCertificationTreeEntry<'static>,
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
        } = create_v2_certificate_fixture(&certification_tree.root_hash(), &current_time);
        let certificate_header = create_v2_header(
            &certification_tree_entry,
            &certificate_cbor,
            &cbor_encode(
                &certification_tree
                    .witness(&certification_tree_entry, req_path)
                    .unwrap(),
            ),
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
            Err(ResponseVerificationError::MoreSpecificWildcardExpressionMightExistInTree { .. })
        ));
    }

    #[rstest]
    // assert that the asset not found response is not accepted for assets outside the js folder
    #[case::not_found_for_old_path(&"/old-path", not_found_response(), not_found_certification())]
    // assert that the index html fallback response is not accepted for assets inside the js folder
    #[case::index_html_for_old_path(&"/old-path", index_html_response(), index_html_certification())]
    // assert that the index html fallback response is not accepted for assets inside the js folder
    #[case::index_html_for_js_path(&"/js/index.js", index_html_response(), index_html_certification())]
    fn certification_scenarios_fail_verification(
        #[from(certificate_tree)] certification_tree: HttpCertificationTree,
        #[case] req_path: &str,
        #[case] mut expected_response: HttpResponse,
        #[case] certification_tree_entry: HttpCertificationTreeEntry<'static>,
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
        } = create_v2_certificate_fixture(&certification_tree.root_hash(), &current_time);
        let certificate_header = create_v2_header(
            &certification_tree_entry,
            &certificate_cbor,
            &cbor_encode(
                &certification_tree
                    .witness(&certification_tree_entry, req_path)
                    .unwrap(),
            ),
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
            Err(ResponseVerificationError::ExactExpressionPathMightExistInTree { .. })
        ));
    }

    #[rstest]
    // assert that the redirect response is not accepted for incorrect paths
    #[case::redirect_for_not_found_path(&"/not-found", redirect_response(), redirect_certification())]
    #[case::redirect_for_js_path(&"/js/index.js", index_html_response(), redirect_certification())]
    #[case::redirect_for_js_not_found_path(&"/js/not-found", index_html_response(), redirect_certification())]
    #[case::redirect_for_js_nested_not_found_path(&"/js/not/found", index_html_response(), redirect_certification())]
    #[case::redirect_for_nested_not_found_path(&"/not/found", redirect_response(), redirect_certification())]
    #[case::redirect_for_index_html_path(&"/", redirect_response(), redirect_certification())]
    #[case::redirect_for_old_trailing_slash_path(&"/old-path/", redirect_response(), redirect_certification())]
    // assert that encoded responses are not accepted for the incorrect paths
    #[case::identity_encoding_for_encoded_trailing_slash_path(&"/multi-encoded-path/", content_encoding_identity_response(), content_encoding_identity_certification())]
    #[case::gzip_encoding_for_encoded_trailing_slash_path(&"/multi-encoded-path/", content_encoding_gzip_response(), content_encoding_gzip_certification())]
    #[case::deflate_encoding_for_encoded_trailing_slash_path(&"/multi-encoded-path/", content_encoding_deflate_response(), content_encoding_deflate_certification())]
    #[case::identity_encoding_for_index_html_path(&"/", content_encoding_identity_response(), content_encoding_identity_certification())]
    #[case::gzip_encoding_for_not_found_path(&"/not-found", content_encoding_gzip_response(), content_encoding_gzip_certification())]
    #[case::gzip_encoding_for_nested_not_found_path(&"/not/found", content_encoding_gzip_response(), content_encoding_gzip_certification())]
    #[case::deflate_encoding_for_js_path(&"/js/index.js", content_encoding_deflate_response(), content_encoding_deflate_certification())]
    #[case::deflate_encoding_for_js_not_found_path(&"/js/not-found", content_encoding_deflate_response(), content_encoding_deflate_certification())]
    #[case::deflate_encoding_for_nested_js_not_found_path(&"/js/not/found", content_encoding_deflate_response(), content_encoding_deflate_certification())]
    fn exact_expr_path_mismatch_fails_verification(
        #[from(certificate_tree)] certification_tree: HttpCertificationTree,
        #[case] req_path: &str,
        #[case] mut expected_response: HttpResponse,
        #[case] certification_tree_entry: HttpCertificationTreeEntry<'static>,
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
        } = create_v2_certificate_fixture(&certification_tree.root_hash(), &current_time);
        let certificate_header = create_v2_header(
            &certification_tree_entry,
            &certificate_cbor,
            &cbor_encode(
                &certification_tree
                    .witness(&certification_tree_entry, req_path)
                    .unwrap(),
            ),
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
            Err(ResponseVerificationError::ExactExpressionPathMismatch { .. })
        ));
    }

    #[rstest]
    // assert that the asset not found response is not accepted for assets outside the js folder
    #[case::not_found_for_index_html_path(&"/", not_found_response(), not_found_certification())]
    #[case::not_found_for_nested_not_found_trailing_slash_path(&"/not/found/", not_found_response(), not_found_certification())]
    #[case::not_found_for_nested_not_found_path(&"/not/found", not_found_response(), not_found_certification())]
    #[case::not_found_for_not_found_path(&"/not-found", not_found_response(), not_found_certification())]
    #[case::not_found_for_not_found_trailing_slash_path(&"/not-found/", not_found_response(), not_found_certification())]
    fn wildcard_expr_path_mismatch_fails_verification(
        #[from(certificate_tree)] certification_tree: HttpCertificationTree,
        #[case] req_path: &str,
        #[case] mut expected_response: HttpResponse,
        #[case] certification_tree_entry: HttpCertificationTreeEntry<'static>,
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
        } = create_v2_certificate_fixture(&certification_tree.root_hash(), &current_time);
        let certificate_header = create_v2_header(
            &certification_tree_entry,
            &certificate_cbor,
            &cbor_encode(
                &certification_tree
                    .witness(&certification_tree_entry, req_path)
                    .unwrap(),
            ),
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
            Err(ResponseVerificationError::WildcardExpressionPathMismatch { .. })
        ));
    }

    #[rstest]
    #[case::etag_match(
        etag_caching_match_request(),
        etag_caching_match_response(),
        etag_caching_match_certification(HttpCertificationPath::exact("/app"))
    )]
    #[case::etag_match_mismatch_response(
        etag_caching_match_request(),
        etag_caching_mismatch_response(),
        etag_caching_mismatch_certification(HttpCertificationPath::exact("/app"))
    )]
    #[case::etag_match_mismatch_response(
        etag_caching_mismatch_request(),
        etag_caching_mismatch_response(),
        etag_caching_mismatch_certification(HttpCertificationPath::exact("/app"))
    )]
    fn etag_scenarios_pass_verification(
        #[from(etag_certificate_tree)] certification_tree: HttpCertificationTree,
        #[case] request: HttpRequest,
        #[case] mut expected_response: HttpResponse,
        #[case] certification_tree_entry: HttpCertificationTreeEntry<'static>,
    ) {
        let req_path = "/app";
        let current_time = get_current_timestamp();

        let V2CertificateFixture {
            root_key,
            canister_id,
            certificate_cbor,
        } = create_v2_certificate_fixture(&certification_tree.root_hash(), &current_time);
        let certificate_header = create_v2_header(
            &certification_tree_entry,
            &certificate_cbor,
            &cbor_encode(
                &certification_tree
                    .witness(&certification_tree_entry, req_path)
                    .unwrap(),
            ),
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
            status_code: Some(expected_response.status_code),
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
        #[from(etag_certificate_tree)] certification_tree: HttpCertificationTree,
        #[from(etag_caching_mismatch_request)] request: HttpRequest,
        #[from(etag_caching_match_response)] mut expected_response: HttpResponse,
    ) {
        let req_path = "/app";
        let http_certification_tree_entry =
            etag_caching_match_certification(HttpCertificationPath::exact("/app"));
        let current_time = get_current_timestamp();

        let V2CertificateFixture {
            root_key,
            canister_id,
            certificate_cbor,
        } = create_v2_certificate_fixture(&certification_tree.root_hash(), &current_time);
        let certificate_header = create_v2_header(
            &http_certification_tree_entry,
            &certificate_cbor,
            &cbor_encode(
                &certification_tree
                    .witness(&http_certification_tree_entry, req_path)
                    .unwrap(),
            ),
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
        DefaultCelBuilder, DefaultFullCelExpression, DefaultResponseCertification,
        DefaultResponseOnlyCelExpression, HttpCertification, HttpCertificationPath,
        HttpCertificationTree, HttpCertificationTreeEntry, HttpRequest, HttpResponse,
    };
    use ic_response_verification_test_utils::{deflate_encode, gzip_encode, hash};
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
            upgrade: None,
        }
    }

    #[fixture]
    pub fn index_html_certification() -> HttpCertificationTreeEntry<'static> {
        HttpCertificationTreeEntry::new(
            HttpCertificationPath::wildcard(""),
            HttpCertification::response_only(&asset_cel(), &index_html_response(), None).unwrap(),
        )
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
            upgrade: None,
        }
    }

    #[fixture]
    pub fn index_js_certification() -> HttpCertificationTreeEntry<'static> {
        HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact("/js/index.js"),
            HttpCertification::response_only(&asset_cel(), &index_js_response(), None).unwrap(),
        )
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
            upgrade: None,
        }
    }

    #[fixture]
    pub fn not_found_certification() -> HttpCertificationTreeEntry<'static> {
        HttpCertificationTreeEntry::new(
            HttpCertificationPath::wildcard("/js"),
            HttpCertification::response_only(&asset_cel(), &not_found_response(), None).unwrap(),
        )
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
            upgrade: None,
        }
    }

    #[fixture]
    pub fn redirect_certification() -> HttpCertificationTreeEntry<'static> {
        HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact("/old-path"),
            HttpCertification::response_only(&redirect_cel(), &redirect_response(), None).unwrap(),
        )
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
            upgrade: None,
        }
    }

    #[fixture]
    pub fn content_encoding_identity_certification() -> HttpCertificationTreeEntry<'static> {
        HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact("/multi-encoded-path"),
            HttpCertification::response_only(
                &asset_cel(),
                &content_encoding_identity_response(),
                None,
            )
            .unwrap(),
        )
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
            upgrade: None,
        }
    }

    #[fixture]
    pub fn content_encoding_gzip_certification() -> HttpCertificationTreeEntry<'static> {
        HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact("/multi-encoded-path"),
            HttpCertification::response_only(&asset_cel(), &content_encoding_gzip_response(), None)
                .unwrap(),
        )
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
            upgrade: None,
        }
    }

    #[fixture]
    pub fn content_encoding_deflate_certification() -> HttpCertificationTreeEntry<'static> {
        HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact("/multi-encoded-path"),
            HttpCertification::response_only(
                &asset_cel(),
                &content_encoding_deflate_response(),
                None,
            )
            .unwrap(),
        )
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
            upgrade: None,
        }
    }

    #[fixture]
    pub fn etag_caching_match_certification(
        #[default(HttpCertificationPath::exact(""))] path: HttpCertificationPath<'static>,
    ) -> HttpCertificationTreeEntry<'static> {
        HttpCertificationTreeEntry::new(
            path,
            HttpCertification::full(
                &etag_caching_match_cel(),
                &etag_caching_match_request(),
                &etag_caching_match_response(),
                None,
            )
            .unwrap(),
        )
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
            upgrade: None,
        }
    }

    #[fixture]
    pub fn etag_caching_mismatch_certification(
        #[default(HttpCertificationPath::exact(""))] path: HttpCertificationPath<'static>,
    ) -> HttpCertificationTreeEntry<'static> {
        HttpCertificationTreeEntry::new(
            path,
            HttpCertification::response_only(
                &etag_caching_mismatch_cel(),
                &etag_caching_mismatch_response(),
                None,
            )
            .unwrap(),
        )
    }

    #[fixture]
    pub fn asset_cel() -> DefaultResponseOnlyCelExpression<'static> {
        DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["Content-Type", "Content-Encoding"],
            ))
            .build()
    }

    #[fixture]
    pub fn redirect_cel() -> DefaultResponseOnlyCelExpression<'static> {
        DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["Location"],
            ))
            .build()
    }

    #[fixture]
    pub fn etag_caching_match_cel() -> DefaultFullCelExpression<'static> {
        DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["If-None-Match"])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["Content-Type", "Content-Encoding", "ETag"],
            ))
            .build()
    }

    #[fixture]
    pub fn etag_caching_mismatch_cel() -> DefaultResponseOnlyCelExpression<'static> {
        DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["Content-Type", "Content-Encoding", "ETag"],
            ))
            .build()
    }

    #[fixture]
    pub fn certificate_tree() -> HttpCertificationTree {
        let mut http_certification_tree = HttpCertificationTree::default();

        http_certification_tree.insert(&index_html_certification());
        http_certification_tree.insert(&index_js_certification());
        http_certification_tree.insert(&not_found_certification());
        http_certification_tree.insert(&redirect_certification());
        http_certification_tree.insert(&content_encoding_identity_certification());
        http_certification_tree.insert(&content_encoding_gzip_certification());
        http_certification_tree.insert(&content_encoding_deflate_certification());

        http_certification_tree
    }

    #[fixture]
    pub fn etag_certificate_tree() -> HttpCertificationTree {
        let mut http_certification_tree = HttpCertificationTree::default();

        http_certification_tree.insert(&etag_caching_match_certification(
            HttpCertificationPath::exact("/app"),
        ));
        http_certification_tree.insert(&etag_caching_match_certification(
            HttpCertificationPath::exact("/app/"),
        ));
        http_certification_tree.insert(&etag_caching_mismatch_certification(
            HttpCertificationPath::exact("/app"),
        ));
        http_certification_tree.insert(&etag_caching_mismatch_certification(
            HttpCertificationPath::exact("/app/"),
        ));

        http_certification_tree
    }
}
