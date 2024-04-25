use crate::{
    Asset, AssetCertificationError, AssetCertificationResult, AssetConfig, AssetFallbackConfig,
    AssetResponse, NormalizedAssetConfig,
};
use ic_certification::HashTree;
use ic_http_certification::{
    DefaultCelBuilder, DefaultResponseCertification, HttpCertification, HttpCertificationPath,
    HttpCertificationTree, HttpCertificationTreeEntry, HttpRequest, HttpResponse,
};
use std::collections::HashMap;

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
/// use ic_http_certification::{HttpRequest, HttpCertificationTree};
/// use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter};
///
/// let mut asset_router = AssetRouter::default();
/// let mut http_certification_tree = HttpCertificationTree::default();
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
///         fallback_for: Some(AssetFallbackConfig {
///             scope: "/".to_string(),
///         }),
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
/// ];
///
/// asset_router
///     .certify_assets(&mut http_certification_tree, assets, asset_configs)
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
///     .serve_asset(&http_certification_tree, &index_html_request)
///     .unwrap();
///
/// ```
#[derive(Debug)]
pub struct AssetRouter<'a> {
    responses: HashMap<String, CertifiedAssetResponse<'a>>,
    fallback_responses: HashMap<String, CertifiedAssetResponse<'a>>,
}

const IC_CERTIFICATE_EXPRESSION_HEADER: &str = "IC-CertificateExpression";

impl<'a> AssetRouter<'a> {
    /// Creates a new [AssetRouter].
    pub fn new() -> Self {
        AssetRouter {
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
        http_certification_tree: &HttpCertificationTree,
        request: &HttpRequest,
    ) -> AssetCertificationResult<(HttpResponse, HashTree, Vec<String>)> {
        if let Some(CertifiedAssetResponse {
            response,
            tree_entry,
        }) = self.responses.get(&request.url)
        {
            let witness = http_certification_tree.witness(tree_entry, &request.url)?;
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
                let witness = http_certification_tree.witness(tree_entry, &request.url)?;
                let expr_path = tree_entry.path.to_expr_path();

                return Ok((response.clone().into(), witness, expr_path));
            }

            scope.pop();

            if let Some(CertifiedAssetResponse {
                response,
                tree_entry,
            }) = self.fallback_responses.get(&scope)
            {
                let witness = http_certification_tree.witness(tree_entry, &request.url)?;
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
    pub fn certify_asset(
        &mut self,
        http_certification_tree: &mut HttpCertificationTree,
        asset: Asset<'a>,
        asset_config: Option<AssetConfig>,
    ) -> AssetCertificationResult {
        let asset_config = asset_config
            .map(TryInto::<NormalizedAssetConfig>::try_into)
            .transpose()?;

        self.certify_asset_impl(http_certification_tree, asset, asset_config.as_ref())
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
    pub fn certify_assets(
        &mut self,
        http_certification_tree: &mut HttpCertificationTree,
        assets: impl IntoIterator<Item = Asset<'a>>,
        asset_configs: impl IntoIterator<Item = AssetConfig>,
    ) -> AssetCertificationResult {
        let asset_configs: Vec<NormalizedAssetConfig> = asset_configs
            .into_iter()
            .map(TryInto::try_into)
            .collect::<AssetCertificationResult<_>>()?;

        for asset in assets {
            let asset_config = asset_configs.iter().find(|e| e.matches_asset(&asset));

            self.certify_asset_impl(http_certification_tree, asset, asset_config)?;
        }

        Ok(())
    }

    fn certify_asset_impl(
        &mut self,
        http_certification_tree: &mut HttpCertificationTree,
        asset: Asset<'a>,
        asset_config: Option<&NormalizedAssetConfig>,
    ) -> AssetCertificationResult {
        match asset_config {
            Some(NormalizedAssetConfig::Pattern {
                content_type,
                headers,
                ..
            }) => {
                self.insert_static_asset(
                    http_certification_tree,
                    asset,
                    content_type.clone(),
                    headers.clone(),
                )?;
            }
            Some(NormalizedAssetConfig::File {
                content_type,
                headers,
                fallback_for,
                ..
            }) => {
                self.insert_static_asset(
                    http_certification_tree,
                    asset.clone(),
                    content_type.clone(),
                    headers.clone(),
                )?;

                if let Some(fallback_for) = fallback_for {
                    self.insert_fallback_asset(
                        http_certification_tree,
                        asset,
                        content_type.clone(),
                        headers.clone(),
                        fallback_for.clone(),
                    )?;
                }
            }
            None => {
                self.insert_static_asset(http_certification_tree, asset, None, vec![])?;
            }
        }

        Ok(())
    }

    fn insert_static_asset(
        &mut self,
        http_certification_tree: &mut HttpCertificationTree,
        asset: Asset<'a>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
    ) -> AssetCertificationResult<()> {
        let asset_url = asset.url.to_string();
        let (response, certification) =
            Self::prepare_response_and_certification(asset, additional_headers, content_type)?;

        let tree_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact(asset_url.clone()),
            certification,
        );

        http_certification_tree.insert(&tree_entry);

        self.responses.insert(
            asset_url,
            CertifiedAssetResponse {
                response,
                tree_entry,
            },
        );

        Ok(())
    }

    fn insert_fallback_asset(
        &mut self,
        http_certification_tree: &mut HttpCertificationTree,
        asset: Asset<'a>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
        fallback_for: AssetFallbackConfig,
    ) -> AssetCertificationResult<()> {
        let (response, certification) =
            Self::prepare_response_and_certification(asset, additional_headers, content_type)?;

        let tree_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::wildcard(fallback_for.scope.clone()),
            certification,
        );

        http_certification_tree.insert(&tree_entry);

        self.fallback_responses.insert(
            fallback_for.scope,
            CertifiedAssetResponse {
                response,
                tree_entry,
            },
        );

        Ok(())
    }

    fn prepare_response_and_certification(
        asset: Asset<'a>,
        additional_headers: Vec<(String, String)>,
        content_type: Option<String>,
    ) -> AssetCertificationResult<(AssetResponse<'a>, HttpCertification)> {
        let mut headers = vec![(
            "content-length".to_string(),
            asset.content.len().to_string(),
        )];

        headers.extend(additional_headers);

        if let Some(content_type) = content_type {
            headers.push(("content-type".to_string(), content_type));
        }

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
            url: asset.url.to_string(),
            headers: vec![],
            body: vec![],
        };

        let response = AssetResponse::new(200, asset.content, headers);

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

    #[rstest]
    fn test_index_html_root_fallback(
        index_html_body: Vec<u8>,
        asset_cel_expr: String,
        certification_fixture: (HttpCertificationTree, AssetRouter),
    ) {
        let (http_certification_tree, asset_router) = certification_fixture;

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

        let (response, witness, expr_path) = asset_router
            .serve_asset(&http_certification_tree, &request)
            .unwrap();

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
        certification_fixture: (HttpCertificationTree, AssetRouter),
    ) {
        let (http_certification_tree, asset_router) = certification_fixture;

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

        let (response, witness, expr_path) = asset_router
            .serve_asset(&http_certification_tree, &request)
            .unwrap();
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
    fn text_app_css(
        app_css_body: Vec<u8>,
        asset_cel_expr: String,
        certification_fixture: (HttpCertificationTree, AssetRouter),
    ) {
        let (http_certification_tree, asset_router) = certification_fixture;

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

        let (response, witness, expr_path) = asset_router
            .serve_asset(&http_certification_tree, &request)
            .unwrap();

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
    fn test_app_js(
        app_js_body: Vec<u8>,
        asset_cel_expr: String,
        certification_fixture: (HttpCertificationTree, AssetRouter),
    ) {
        let (http_certification_tree, asset_router) = certification_fixture;

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

        let (response, witness, expr_path) = asset_router
            .serve_asset(&http_certification_tree, &request)
            .unwrap();

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
        certification_fixture: (HttpCertificationTree, AssetRouter),
    ) {
        let (http_certification_tree, asset_router) = certification_fixture;

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

        let (response, witness, expr_path) = asset_router
            .serve_asset(&http_certification_tree, &request)
            .unwrap();

        assert_eq!(expr_path, vec!["http_expr", "js", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);
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
    fn certification_fixture(
        index_html_body: Vec<u8>,
        app_js_body: Vec<u8>,
        app_css_body: Vec<u8>,
        not_found_html_body: Vec<u8>,
    ) -> (HttpCertificationTree, AssetRouter<'static>) {
        let mut asset_router = AssetRouter::default();
        let mut http_certification_tree = HttpCertificationTree::default();

        let assets = vec![
            Asset::new("index.html", index_html_body),
            Asset::new("js/app-488df671.js", app_js_body),
            Asset::new("js/not-found.html", not_found_html_body),
            Asset::new("css/app-ba74b708.css", app_css_body),
        ];

        let asset_configs = vec![
            AssetConfig::File {
                path: "index.html".to_string(),
                content_type: Some("text/html".to_string()),
                headers: vec![(
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                )],
                fallback_for: Some(AssetFallbackConfig {
                    scope: "/".to_string(),
                }),
            },
            AssetConfig::Pattern {
                pattern: "**/*.js".to_string(),
                content_type: Some("text/javascript".to_string()),
                headers: vec![(
                    "cache-control".to_string(),
                    "public, max-age=31536000, immutable".to_string(),
                )],
            },
            AssetConfig::File {
                path: "js/not-found.html".to_string(),
                content_type: Some("text/html".to_string()),
                headers: vec![(
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                )],
                fallback_for: Some(AssetFallbackConfig {
                    scope: "/js".to_string(),
                }),
            },
            AssetConfig::Pattern {
                pattern: "**/*.css".to_string(),
                content_type: Some("text/css".to_string()),
                headers: vec![(
                    "cache-control".to_string(),
                    "public, max-age=31536000, immutable".to_string(),
                )],
            },
        ];

        asset_router
            .certify_assets(&mut http_certification_tree, assets, asset_configs)
            .unwrap();

        (http_certification_tree, asset_router)
    }
}
