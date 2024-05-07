use crate::{
    Asset, AssetCertificationError, AssetCertificationResult, AssetConfig, AssetFallbackConfig,
    AssetRedirectKind, AssetResponse, NormalizedAssetConfig,
};
use ic_certification::HashTree;
use ic_http_certification::{
    DefaultCelBuilder, DefaultResponseCertification, Hash, HttpCertification,
    HttpCertificationPath, HttpCertificationTree, HttpCertificationTreeEntry, HttpRequest,
    HttpResponse,
};
use std::{borrow::Cow, cell::RefCell, collections::HashMap, rc::Rc};

#[derive(Debug, Clone)]
struct CertifiedAssetResponse<'a> {
    response: AssetResponse<'a>,
    tree_entry: HttpCertificationTreeEntry<'a>,
}

/// A router for certifying and serving static [Assets](Asset).
///
/// [Asset] certification is configured using the [AssetConfig] enum.
///
/// # Example
///
/// ```
/// use ic_http_certification::HttpRequest;
/// use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter, AssetRedirectKind};
///
/// let mut asset_router = AssetRouter::default();
///
/// let index_html_body = b"<html><body><h1>Hello World!</h1></body></html>".as_slice();
/// let app_js_body = b"console.log('Hello World!');".as_slice();
/// let app_css_body = b"html,body{min-height:100vh;}".as_slice();
///
/// let assets = vec![
///     Asset::new("index.html", index_html_body),
///     Asset::new("js/app-488df671.js", app_js_body),
///     Asset::new("css/app-ba74b708.css", app_css_body),
/// ];
///
/// let asset_configs = vec![
///     AssetConfig::File {
///         path: "index.html".to_string(),
///         content_type: Some("text/html".to_string()),
///         headers: vec![(
///             "cache-control".to_string(),
///             "public, no-cache, no-store".to_string(),
///         )],
///         fallback_for: vec![AssetFallbackConfig {
///             scope: "/".to_string(),
///         }],
///         aliased_by: vec!["/".to_string()],
///     },
///     AssetConfig::Pattern {
///         pattern: "**/*.js".to_string(),
///         content_type: Some("text/javascript".to_string()),
///         headers: vec![(
///             "cache-control".to_string(),
///             "public, max-age=31536000, immutable".to_string(),
///         )],
///     },
///     AssetConfig::Pattern {
///         pattern: "**/*.css".to_string(),
///         content_type: Some("text/css".to_string()),
///         headers: vec![(
///             "cache-control".to_string(),
///             "public, max-age=31536000, immutable".to_string(),
///         )],
///     },
///     AssetConfig::Redirect {
///         from: "/old-url".to_string(),
///         to: "/".to_string(),
///         kind: AssetRedirectKind::Permanent,
///     },
///     AssetConfig::Redirect {
///         from: "/css/app.css".to_string(),
///         to: "/css/app-ba74b708.css".to_string(),
///         kind: AssetRedirectKind::Temporary,
///     },
/// ];
///
/// asset_router
///     .certify_assets(assets, asset_configs)
///     .unwrap();
///
/// let index_html_request = HttpRequest {
///     method: "GET".to_string(),
///     url: "/".to_string(),
///     headers: vec![],
///     body: vec![],
/// };
///
/// let (index_html_response, index_html_tree, index_html_expr_path) = asset_router
///     .serve_asset(&index_html_request)
///     .unwrap();
/// ```
///
/// It's also possible to initialize the [AssetRouter] with an external
/// [HttpCertificationTree], for cases where the tree needs to be used to
/// certify other HTTP responses.
///
/// ```
/// use std::{cell::RefCell, rc::Rc};
/// use ic_http_certification::HttpCertificationTree;
/// use ic_asset_certification::AssetRouter;
///
/// let mut http_certification_tree: Rc<RefCell<HttpCertificationTree>> = Default::default();
/// let mut asset_router = AssetRouter::with_tree(http_certification_tree.clone());
/// ```
#[derive(Debug)]
pub struct AssetRouter<'content> {
    tree: Rc<RefCell<HttpCertificationTree>>,
    responses: HashMap<String, CertifiedAssetResponse<'content>>,
    fallback_responses: HashMap<String, CertifiedAssetResponse<'content>>,
}

const IC_CERTIFICATE_EXPRESSION_HEADER: &str = "IC-CertificateExpression";

impl<'content> AssetRouter<'content> {
    /// Creates a new [AssetRouter].
    pub fn new() -> Self {
        AssetRouter {
            tree: Default::default(),
            responses: HashMap::new(),
            fallback_responses: HashMap::new(),
        }
    }

    /// Creates a new [AssetRouter] using the provided
    /// [HttpCertificationTree](ic_http_certification::HttpCertificationTree)
    /// for certifying assets.
    pub fn with_tree(tree: Rc<RefCell<HttpCertificationTree>>) -> Self {
        AssetRouter {
            tree,
            responses: HashMap::new(),
            fallback_responses: HashMap::new(),
        }
    }

    /// Returns the corresponding
    /// [HttpResponse](ic_http_certification::HttpResponse) for the provided
    /// [HttpRequest](ic_http_certification::HttpRequest) if it is found
    /// in the router, along with the
    /// [certification witness](ic_certification::HashTree) and the
    /// corresponding
    /// [expression path](ic_http_certification::HttpCertificationPath).
    ///
    /// If an exact match is not found, then a fallback will
    /// be searched for. See the
    /// [fallback_for](AssetConfig::File::fallback_for) configuration
    /// option for more information on fallbacks.
    ///
    /// Returns [None] if no suitable
    /// [HttpResponse](ic_http_certification::HttpResponse) is found for the
    /// given [HttpRequest](ic_http_certification::HttpRequest).
    pub fn serve_asset(
        &self,
        request: &HttpRequest,
    ) -> AssetCertificationResult<(HttpResponse, HashTree, Vec<String>)> {
        if let Some(CertifiedAssetResponse {
            response,
            tree_entry,
        }) = self.responses.get(&request.url)
        {
            let witness = self.tree.borrow().witness(tree_entry, &request.url)?;
            let expr_path = tree_entry.path.to_expr_path();

            return Ok((response.clone().into(), witness, expr_path));
        }

        let mut url_scopes = request.url.split('/').collect::<Vec<_>>();
        url_scopes.pop();

        while !url_scopes.is_empty() {
            let mut scope = url_scopes.join("/");
            scope.push('/');

            if let Some(CertifiedAssetResponse {
                response,
                tree_entry,
            }) = self.fallback_responses.get(&scope)
            {
                let witness = self.tree.borrow().witness(tree_entry, &request.url)?;
                let expr_path = tree_entry.path.to_expr_path();

                return Ok((response.clone().into(), witness, expr_path));
            }

            scope.pop();

            if let Some(CertifiedAssetResponse {
                response,
                tree_entry,
            }) = self.fallback_responses.get(&scope)
            {
                let witness = self.tree.borrow().witness(tree_entry, &request.url)?;
                let expr_path = tree_entry.path.to_expr_path();

                return Ok((response.clone().into(), witness, expr_path));
            }

            url_scopes.pop();
        }

        Err(AssetCertificationError::NoAssetMatchingRequestUrl {
            request_url: request.url.clone(),
        })
    }

    /// Certifies a single asset and inserts it into the router, to be served
    /// later by the [serve_asset](AssetRouter::serve_asset) method.
    ///
    /// The asset is certified using the provided
    /// [HttpCertificationTree](ic_http_certification::HttpCertificationTree).
    ///
    /// The asset certification is configured using the provided
    /// [AssetConfig] enum.
    ///
    /// If no configuration is provided, the asset will be certified and served
    /// as-is, without headers.
    pub fn certify_asset<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        asset_config: Option<AssetConfig>,
    ) -> AssetCertificationResult {
        let asset_config = asset_config
            .map(TryInto::<NormalizedAssetConfig>::try_into)
            .transpose()?;

        self.certify_asset_impl(asset, asset_config.as_ref())
    }

    /// Certifies multiple assets and inserts them into the router, to be served
    /// later by the [serve_asset](AssetRouter::serve_asset) method.
    ///
    /// The assets are certified using the provided
    /// [HttpCertificationTree](ic_http_certification::HttpCertificationTree).
    ///
    /// The asset certification is configured using the provided [AssetConfig]
    /// enum.
    ///
    /// If no configuration matches an individual asset, the asset will be
    /// served and certified as-is, without headers.
    pub fn certify_assets<'path>(
        &mut self,
        assets: impl IntoIterator<Item = Asset<'content, 'path>>,
        asset_configs: impl IntoIterator<Item = AssetConfig>,
    ) -> AssetCertificationResult {
        let asset_configs: Vec<NormalizedAssetConfig> = asset_configs
            .into_iter()
            .map(TryInto::try_into)
            .collect::<AssetCertificationResult<_>>()?;

        for asset in assets {
            let asset_config = asset_configs.iter().find(|e| e.matches_asset(&asset));

            self.certify_asset_impl(asset, asset_config)?;
        }

        for asset_config in asset_configs {
            if let NormalizedAssetConfig::Redirect { from, to, kind } = asset_config {
                self.insert_redirect(from, to, kind)?;
            }
        }

        Ok(())
    }

    /// Returns the root hash of the underlying
    /// [HttpCertificationTree](ic_http_certification::HttpCertificationTree).
    pub fn root_hash(&self) -> Hash {
        self.tree.borrow().root_hash()
    }

    fn certify_asset_impl<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        asset_config: Option<&NormalizedAssetConfig>,
    ) -> AssetCertificationResult {
        match asset_config {
            Some(NormalizedAssetConfig::Pattern {
                content_type,
                headers,
                ..
            }) => {
                self.insert_static_asset(asset, content_type.clone(), headers.clone())?;
            }
            Some(NormalizedAssetConfig::File {
                content_type,
                headers,
                fallback_for,
                aliased_by,
                ..
            }) => {
                self.insert_static_asset(asset.clone(), content_type.clone(), headers.clone())?;

                for fallback_for in fallback_for.iter() {
                    self.insert_fallback_asset(
                        asset.clone(),
                        content_type.clone(),
                        headers.clone(),
                        fallback_for.clone(),
                    )?;
                }

                for aliased_by in aliased_by.iter() {
                    self.insert_static_asset(
                        Asset::new(aliased_by, asset.content.clone()),
                        content_type.clone(),
                        headers.clone(),
                    )?;
                }
            }
            _ => {
                self.insert_static_asset(asset, None, vec![])?;
            }
        }

        Ok(())
    }

    fn insert_static_asset<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
    ) -> AssetCertificationResult<()> {
        let asset_url = asset.url.to_string();
        let (response, certification) = Self::prepare_asset_response_and_certification(
            asset,
            additional_headers,
            content_type,
        )?;

        let tree_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact(asset_url.clone()),
            certification,
        );

        self.tree.borrow_mut().insert(&tree_entry);

        self.responses.insert(
            asset_url,
            CertifiedAssetResponse {
                response,
                tree_entry,
            },
        );

        Ok(())
    }

    fn insert_fallback_asset<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
        fallback_for: AssetFallbackConfig,
    ) -> AssetCertificationResult<()> {
        let (response, certification) = Self::prepare_asset_response_and_certification(
            asset,
            additional_headers,
            content_type,
        )?;

        let tree_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::wildcard(fallback_for.scope.clone()),
            certification,
        );

        self.tree.borrow_mut().insert(&tree_entry);

        self.fallback_responses.insert(
            fallback_for.scope,
            CertifiedAssetResponse {
                response,
                tree_entry,
            },
        );

        Ok(())
    }

    fn insert_redirect(
        &mut self,
        from: String,
        to: String,
        kind: AssetRedirectKind,
    ) -> AssetCertificationResult<()> {
        let status_code = match kind {
            AssetRedirectKind::Permanent => 301,
            AssetRedirectKind::Temporary => 307,
        };

        let headers = vec![("location".to_string(), to)];

        let (response, certification) = Self::prepare_response_and_certification(
            from.clone(),
            status_code,
            Cow::Owned(vec![]),
            headers,
        )?;

        let tree_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact(from.clone()),
            certification,
        );

        self.tree.borrow_mut().insert(&tree_entry);

        self.responses.insert(
            from,
            CertifiedAssetResponse {
                response,
                tree_entry,
            },
        );

        Ok(())
    }

    fn prepare_asset_response_and_certification<'path>(
        asset: Asset<'content, 'path>,
        additional_headers: Vec<(String, String)>,
        content_type: Option<String>,
    ) -> AssetCertificationResult<(AssetResponse<'content>, HttpCertification)> {
        let mut headers = vec![];

        headers.extend(additional_headers);

        if let Some(content_type) = content_type {
            headers.push(("content-type".to_string(), content_type));
        }

        Self::prepare_response_and_certification(asset.url, 200, asset.content, headers)
    }

    fn prepare_response_and_certification(
        url: String,
        status_code: u16,
        body: Cow<'content, [u8]>,
        additional_headers: Vec<(String, String)>,
    ) -> AssetCertificationResult<(AssetResponse<'content>, HttpCertification)> {
        let mut headers = vec![("content-length".to_string(), body.len().to_string())];

        headers.extend(additional_headers);

        let header_keys = headers.clone();
        let header_keys = header_keys
            .iter()
            .map(|(k, _v)| k.as_str())
            .collect::<Vec<_>>();

        let cel_expr = DefaultCelBuilder::full_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                header_keys,
            ))
            .build();
        let cel_expr_str = cel_expr.to_string();
        headers.push((IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), cel_expr_str));

        let request = HttpRequest {
            method: "GET".to_string(),
            url,
            headers: vec![],
            body: vec![],
        };

        let response = AssetResponse::new(status_code, body, headers);

        let http_response: HttpResponse = response.clone().into();

        let certification = HttpCertification::full(&cel_expr, &request, &http_response, None)?;

        Ok((response, certification))
    }
}

impl Default for AssetRouter<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AssetFallbackConfig;
    use ic_certification::hash_tree::SubtreeLookupResult;
    use ic_http_certification::cel::DefaultFullCelExpressionBuilder;
    use rstest::*;
    use std::vec;

    #[rstest]
    fn test_index_html(
        index_html_body: Vec<u8>,
        asset_cel_expr: String,
        asset_router: AssetRouter,
    ) {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/".to_string(),
            headers: vec![],
            body: vec![],
        };

        let expected_response = HttpResponse {
            status_code: 200,
            body: index_html_body.clone(),
            headers: vec![
                (
                    "content-length".to_string(),
                    index_html_body.len().to_string(),
                ),
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), asset_cel_expr),
            ],
            upgrade: None,
        };

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "", "<$>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);
    }

    #[rstest]
    fn test_index_html_root_fallback(
        index_html_body: Vec<u8>,
        asset_cel_expr: String,
        asset_router: AssetRouter,
    ) {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/something".to_string(),
            headers: vec![],
            body: vec![],
        };

        let expected_response = HttpResponse {
            status_code: 200,
            body: index_html_body.clone(),
            headers: vec![
                (
                    "content-length".to_string(),
                    index_html_body.len().to_string(),
                ),
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), asset_cel_expr),
            ],
            upgrade: None,
        };

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);
    }

    #[rstest]
    fn test_index_html_nested_fallback(
        index_html_body: Vec<u8>,
        asset_cel_expr: String,
        asset_router: AssetRouter,
    ) {
        let expected_response = HttpResponse {
            status_code: 200,
            body: index_html_body.clone(),
            headers: vec![
                (
                    "content-length".to_string(),
                    index_html_body.len().to_string(),
                ),
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), asset_cel_expr),
            ],
            upgrade: None,
        };

        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/assets/css/app.css".to_string(),
            headers: vec![],
            body: vec![],
        };
        let requested_expr_path =
            HttpCertificationPath::exact("/assets/css/app.css").to_expr_path();

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();
        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert!(matches!(
            witness.lookup_subtree(&requested_expr_path),
            SubtreeLookupResult::Absent
        ));
        assert_eq!(response, expected_response);
    }

    #[rstest]
    fn text_app_css(app_css_body: Vec<u8>, asset_cel_expr: String, asset_router: AssetRouter) {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/css/app-ba74b708.css".to_string(),
            headers: vec![],
            body: vec![],
        };

        let expected_response = HttpResponse {
            status_code: 200,
            body: app_css_body.clone(),
            headers: vec![
                ("content-length".to_string(), app_css_body.len().to_string()),
                (
                    "cache-control".to_string(),
                    "public, max-age=31536000, immutable".to_string(),
                ),
                ("content-type".to_string(), "text/css".to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), asset_cel_expr),
            ],
            upgrade: None,
        };

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(
            expr_path,
            vec!["http_expr", "css", "app-ba74b708.css", "<$>"]
        );
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);
    }

    #[rstest]
    fn test_not_found_css(
        not_found_html_body: Vec<u8>,
        asset_cel_expr: String,
        asset_router: AssetRouter,
    ) {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/css/core-8d4jhgy2.js".to_string(),
            headers: vec![],
            body: vec![],
        };
        let expected_response = HttpResponse {
            status_code: 200,
            body: not_found_html_body.to_vec(),
            headers: vec![
                (
                    "content-length".to_string(),
                    not_found_html_body.len().to_string(),
                ),
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), asset_cel_expr),
            ],
            upgrade: None,
        };

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "css", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);
    }

    #[rstest]
    fn test_app_js(app_js_body: Vec<u8>, asset_cel_expr: String, asset_router: AssetRouter) {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/js/app-488df671.js".to_string(),
            headers: vec![],
            body: vec![],
        };

        let expected_response = HttpResponse {
            status_code: 200,
            body: app_js_body.clone(),
            headers: vec![
                ("content-length".to_string(), app_js_body.len().to_string()),
                (
                    "cache-control".to_string(),
                    "public, max-age=31536000, immutable".to_string(),
                ),
                ("content-type".to_string(), "text/javascript".to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), asset_cel_expr),
            ],
            upgrade: None,
        };

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "js", "app-488df671.js", "<$>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);
    }

    #[rstest]
    fn test_not_found_js(
        not_found_html_body: Vec<u8>,
        asset_cel_expr: String,
        asset_router: AssetRouter,
    ) {
        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/js/core-7dk12y45.js".to_string(),
            headers: vec![],
            body: vec![],
        };
        let expected_response = HttpResponse {
            status_code: 200,
            body: not_found_html_body.to_vec(),
            headers: vec![
                (
                    "content-length".to_string(),
                    not_found_html_body.len().to_string(),
                ),
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), asset_cel_expr),
            ],
            upgrade: None,
        };

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "js", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);
    }

    #[rstest]
    fn test_not_found_alias(
        not_found_html_body: Vec<u8>,
        asset_cel_expr: String,
        asset_router: AssetRouter,
    ) {
        let requests = vec![
            HttpRequest {
                method: "GET".to_string(),
                url: "/404".to_string(),
                headers: vec![],
                body: vec![],
            },
            HttpRequest {
                method: "GET".to_string(),
                url: "/404/".to_string(),
                headers: vec![],
                body: vec![],
            },
            HttpRequest {
                method: "GET".to_string(),
                url: "/404.html".to_string(),
                headers: vec![],
                body: vec![],
            },
            HttpRequest {
                method: "GET".to_string(),
                url: "/not-found".to_string(),
                headers: vec![],
                body: vec![],
            },
            HttpRequest {
                method: "GET".to_string(),
                url: "/not-found/".to_string(),
                headers: vec![],
                body: vec![],
            },
            HttpRequest {
                method: "GET".to_string(),
                url: "/not-found/index.html".to_string(),
                headers: vec![],
                body: vec![],
            },
        ];

        let expected_response = HttpResponse {
            status_code: 200,
            body: not_found_html_body.to_vec(),
            headers: vec![
                (
                    "content-length".to_string(),
                    not_found_html_body.len().to_string(),
                ),
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), asset_cel_expr),
            ],
            upgrade: None,
        };

        for request in requests {
            let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

            assert_eq!(
                expr_path,
                HttpCertificationPath::exact(request.url).to_expr_path()
            );
            assert!(matches!(
                witness.lookup_subtree(&expr_path),
                SubtreeLookupResult::Found(_)
            ));
            assert_eq!(response, expected_response);
        }
    }

    #[rstest]
    fn test_redirects(asset_router: AssetRouter) {
        let cel_expr = DefaultFullCelExpressionBuilder::default()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["content-length", "location"],
            ))
            .build()
            .to_string();

        let css_request = HttpRequest {
            method: "GET".to_string(),
            url: "/css/app.css".to_string(),
            headers: vec![],
            body: vec![],
        };
        let old_url_request = HttpRequest {
            method: "GET".to_string(),
            url: "/old-url".to_string(),
            headers: vec![],
            body: vec![],
        };

        let expected_css_response = HttpResponse {
            status_code: 307,
            body: vec![],
            headers: vec![
                ("content-length".to_string(), "0".to_string()),
                ("location".to_string(), "/css/app-ba74b708.css".to_string()),
                (
                    IC_CERTIFICATE_EXPRESSION_HEADER.to_string(),
                    cel_expr.clone(),
                ),
            ],
            upgrade: None,
        };
        let expected_old_url_response = HttpResponse {
            status_code: 301,
            body: vec![],
            headers: vec![
                ("content-length".to_string(), "0".to_string()),
                ("location".to_string(), "/".to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), cel_expr),
            ],
            upgrade: None,
        };

        let (css_response, css_witness, css_expr_path) =
            asset_router.serve_asset(&css_request).unwrap();
        let (old_url_response, old_url_witness, old_url_expr_path) =
            asset_router.serve_asset(&old_url_request).unwrap();

        assert_eq!(css_expr_path, vec!["http_expr", "css", "app.css", "<$>"]);
        assert!(matches!(
            css_witness.lookup_subtree(&css_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(css_response, expected_css_response);

        assert_eq!(old_url_expr_path, vec!["http_expr", "old-url", "<$>"]);
        assert!(matches!(
            old_url_witness.lookup_subtree(&old_url_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(old_url_response, expected_old_url_response);
    }

    #[rstest]
    fn test_init_with_tree(index_html_body: Vec<u8>, asset_cel_expr: String) {
        let http_certification_tree: Rc<RefCell<HttpCertificationTree>> = Default::default();
        let mut asset_router = AssetRouter::with_tree(http_certification_tree.clone());

        let index_html_asset = Asset::new("index.html", &index_html_body);
        let index_html_config = AssetConfig::File {
            path: "index.html".to_string(),
            content_type: Some("text/html".to_string()),
            headers: vec![(
                "cache-control".to_string(),
                "public, no-cache, no-store".to_string(),
            )],
            fallback_for: vec![AssetFallbackConfig {
                scope: "/".to_string(),
            }],
            aliased_by: vec!["/".to_string()],
        };

        asset_router
            .certify_asset(index_html_asset, Some(index_html_config))
            .unwrap();

        let request = HttpRequest {
            method: "GET".to_string(),
            url: "/".to_string(),
            headers: vec![],
            body: vec![],
        };

        let expected_response = HttpResponse {
            status_code: 200,
            body: index_html_body.clone(),
            headers: vec![
                (
                    "content-length".to_string(),
                    index_html_body.len().to_string(),
                ),
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), asset_cel_expr),
            ],
            upgrade: None,
        };

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "", "<$>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);
        assert_eq!(
            asset_router.root_hash(),
            http_certification_tree.borrow().root_hash()
        );
    }

    #[fixture]
    fn index_html_body() -> Vec<u8> {
        b"<html><body><h1>Hello World!</h1></body></html>".to_vec()
    }

    #[fixture]
    fn app_js_body() -> Vec<u8> {
        b"console.log('Hello World!');".to_vec()
    }

    #[fixture]
    fn app_css_body() -> Vec<u8> {
        b"html,body{min-height:100vh;}".to_vec()
    }

    #[fixture]
    fn not_found_html_body() -> Vec<u8> {
        b"<html><body><h1>404 Not Found!</h1></body></html>".to_vec()
    }

    #[fixture]
    fn asset_cel_expr() -> String {
        DefaultFullCelExpressionBuilder::default()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["content-length", "cache-control", "content-type"],
            ))
            .build()
            .to_string()
    }

    #[fixture]
    fn asset_router(
        index_html_body: Vec<u8>,
        app_js_body: Vec<u8>,
        app_css_body: Vec<u8>,
        not_found_html_body: Vec<u8>,
    ) -> AssetRouter<'static> {
        let mut asset_router = AssetRouter::default();
        let assets = vec![
            Asset::new("index.html", index_html_body),
            Asset::new("js/app-488df671.js", app_js_body),
            Asset::new("css/app-ba74b708.css", app_css_body),
            Asset::new("not-found.html", not_found_html_body),
        ];

        let asset_configs = vec![
            AssetConfig::File {
                path: "index.html".to_string(),
                content_type: Some("text/html".to_string()),
                headers: vec![(
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                )],
                fallback_for: vec![AssetFallbackConfig {
                    scope: "/".to_string(),
                }],
                aliased_by: vec!["/".to_string()],
            },
            AssetConfig::Pattern {
                pattern: "**/*.js".to_string(),
                content_type: Some("text/javascript".to_string()),
                headers: vec![(
                    "cache-control".to_string(),
                    "public, max-age=31536000, immutable".to_string(),
                )],
            },
            AssetConfig::Pattern {
                pattern: "**/*.css".to_string(),
                content_type: Some("text/css".to_string()),
                headers: vec![(
                    "cache-control".to_string(),
                    "public, max-age=31536000, immutable".to_string(),
                )],
            },
            AssetConfig::File {
                path: "not-found.html".to_string(),
                content_type: Some("text/html".to_string()),
                headers: vec![(
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                )],
                fallback_for: vec![
                    AssetFallbackConfig {
                        scope: "/js".to_string(),
                    },
                    AssetFallbackConfig {
                        scope: "/css".to_string(),
                    },
                ],
                aliased_by: vec![
                    "/404".to_string(),
                    "/404/".to_string(),
                    "/404.html".to_string(),
                    "/not-found".to_string(),
                    "/not-found/".to_string(),
                    "/not-found/index.html".to_string(),
                ],
            },
            AssetConfig::Redirect {
                from: "/old-url".to_string(),
                to: "/".to_string(),
                kind: AssetRedirectKind::Permanent,
            },
            AssetConfig::Redirect {
                from: "/css/app.css".to_string(),
                to: "/css/app-ba74b708.css".to_string(),
                kind: AssetRedirectKind::Temporary,
            },
        ];

        asset_router.certify_assets(assets, asset_configs).unwrap();

        asset_router
    }
}
