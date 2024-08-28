use crate::{
    Asset, AssetCertificationError, AssetCertificationResult, AssetConfig, AssetEncoding,
    AssetFallbackConfig, AssetRedirectKind, AssetResponse, NormalizedAssetConfig,
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
/// # Examples
///
/// ```
/// use ic_http_certification::HttpRequest;
/// use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter, AssetRedirectKind, AssetEncoding};
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
///         encodings: vec![
///             AssetEncoding::Brotli.default_config(),
///             AssetEncoding::Gzip.default_config(),
///         ],
///     },
///     AssetConfig::Pattern {
///         pattern: "**/*.js".to_string(),
///         content_type: Some("text/javascript".to_string()),
///         headers: vec![(
///             "cache-control".to_string(),
///             "public, max-age=31536000, immutable".to_string(),
///         )],
///         encodings: vec![
///             AssetEncoding::Brotli.default_config(),
///             AssetEncoding::Gzip.default_config(),
///         ],
///     },
///     AssetConfig::Pattern {
///         pattern: "**/*.css".to_string(),
///         content_type: Some("text/css".to_string()),
///         headers: vec![(
///             "cache-control".to_string(),
///             "public, max-age=31536000, immutable".to_string(),
///         )],
///         encodings: vec![
///             AssetEncoding::Brotli.default_config(),
///             AssetEncoding::Gzip.default_config(),
///         ],
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
/// let index_html_request = HttpRequest::get("/").build();
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
    encoded_responses: HashMap<(String, String), CertifiedAssetResponse<'content>>,
    fallback_responses: HashMap<String, CertifiedAssetResponse<'content>>,
    encoded_fallback_responses: HashMap<(String, String), CertifiedAssetResponse<'content>>,
}

const IC_CERTIFICATE_EXPRESSION_HEADER: &str = "IC-CertificateExpression";

impl<'content> AssetRouter<'content> {
    /// Creates a new [AssetRouter].
    pub fn new() -> Self {
        AssetRouter {
            tree: Default::default(),
            responses: HashMap::new(),
            encoded_responses: HashMap::new(),
            fallback_responses: HashMap::new(),
            encoded_fallback_responses: HashMap::new(),
        }
    }

    /// Creates a new [AssetRouter] using the provided
    /// [HttpCertificationTree](ic_http_certification::HttpCertificationTree)
    /// for certifying assets.
    pub fn with_tree(tree: Rc<RefCell<HttpCertificationTree>>) -> Self {
        AssetRouter {
            tree,
            responses: HashMap::new(),
            encoded_responses: HashMap::new(),
            fallback_responses: HashMap::new(),
            encoded_fallback_responses: HashMap::new(),
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
    ) -> AssetCertificationResult<(HttpResponse<'content>, HashTree, Vec<String>)> {
        let preferred_encodings = self.get_preferred_encodings(request);
        let req_path = request.get_path()?;

        if let Some(CertifiedAssetResponse {
            response,
            tree_entry,
        }) = self.get_encoded_asset(&preferred_encodings, &req_path)
        {
            let witness = self.tree.borrow().witness(tree_entry, &req_path)?;
            let expr_path = tree_entry.path.to_expr_path();

            return Ok((response.clone().into(), witness, expr_path));
        }

        if let Some(CertifiedAssetResponse {
            response,
            tree_entry,
        }) = self.responses.get(&req_path)
        {
            let witness = self.tree.borrow().witness(tree_entry, &req_path)?;
            let expr_path = tree_entry.path.to_expr_path();

            return Ok((response.clone().into(), witness, expr_path));
        }

        let mut url_scopes = req_path.split('/').collect::<Vec<_>>();
        url_scopes.pop();

        while !url_scopes.is_empty() {
            let mut scope = url_scopes.join("/");
            scope.push('/');

            if let Some(CertifiedAssetResponse {
                response,
                tree_entry,
            }) = self.get_encoded_fallback_asset(&preferred_encodings, &scope)
            {
                let witness = self.tree.borrow().witness(tree_entry, &req_path)?;
                let expr_path = tree_entry.path.to_expr_path();

                return Ok((response.clone().into(), witness, expr_path));
            }

            if let Some(CertifiedAssetResponse {
                response,
                tree_entry,
            }) = self.fallback_responses.get(&scope)
            {
                let witness = self.tree.borrow().witness(tree_entry, &req_path)?;
                let expr_path = tree_entry.path.to_expr_path();

                return Ok((response.clone().into(), witness, expr_path));
            }

            scope.pop();

            if let Some(CertifiedAssetResponse {
                response,
                tree_entry,
            }) = self.get_encoded_fallback_asset(&preferred_encodings, &scope)
            {
                let witness = self.tree.borrow().witness(tree_entry, &req_path)?;
                let expr_path = tree_entry.path.to_expr_path();

                return Ok((response.clone().into(), witness, expr_path));
            }

            if let Some(CertifiedAssetResponse {
                response,
                tree_entry,
            }) = self.fallback_responses.get(&scope)
            {
                let witness = self.tree.borrow().witness(tree_entry, &req_path)?;
                let expr_path = tree_entry.path.to_expr_path();

                return Ok((response.clone().into(), witness, expr_path));
            }

            url_scopes.pop();
        }

        Err(AssetCertificationError::NoAssetMatchingRequestUrl {
            request_url: req_path.to_string(),
        })
    }

    /// Certifies multiple assets and inserts them into the router, to be served
    /// later by the [serve_asset](AssetRouter::serve_asset) method.
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

        let asset_map = assets
            .into_iter()
            .map(|asset| (asset.path.clone(), asset))
            .collect::<HashMap<_, _>>();

        for asset in asset_map.values() {
            let asset_config = asset_configs.iter().find(|e| e.matches_asset(asset));

            for (encoding, postfix) in asset_config
                .map(|e| match e {
                    NormalizedAssetConfig::File { encodings, .. } => encodings.clone(),
                    NormalizedAssetConfig::Pattern { encodings, .. } => encodings.clone(),
                    _ => vec![],
                })
                .unwrap_or_default()
            {
                let encoded_asset_path = format!("{}.{}", asset.path, postfix);
                let encoded_asset = asset_map.get(encoded_asset_path.as_str()).cloned();

                if let Some(mut encoded_asset) = encoded_asset {
                    encoded_asset.url.clone_from(&asset.url);

                    self.certify_asset_impl(encoded_asset, asset_config, Some(&encoding))?;
                }
            }

            self.certify_asset_impl(asset.clone(), asset_config, None)?;
        }

        for asset_config in asset_configs {
            if let NormalizedAssetConfig::Redirect { from, to, kind } = asset_config {
                self.insert_redirect(from, to, kind)?;
            }
        }

        Ok(())
    }

    /// Deletes multiple assets from the router, including any certification for those assets.
    ///
    /// Depending on the configuration provided to the [certify_assets](AssetRouter::certify_assets) function,
    /// multiple responses may be generated for the same asset. To ensure that all generated responses are deleted,
    /// this function accepts the same configuration.
    pub fn delete_assets<'path>(
        &mut self,
        assets: impl IntoIterator<Item = Asset<'content, 'path>>,
        asset_configs: impl IntoIterator<Item = AssetConfig>,
    ) -> AssetCertificationResult {
        let asset_configs: Vec<NormalizedAssetConfig> = asset_configs
            .into_iter()
            .map(TryInto::try_into)
            .collect::<AssetCertificationResult<_>>()?;

        let asset_map = assets
            .into_iter()
            .map(|asset| (asset.path.clone(), asset))
            .collect::<HashMap<_, _>>();

        for asset in asset_map.values() {
            let asset_config = asset_configs.iter().find(|e| e.matches_asset(asset));

            for (encoding, postfix) in asset_config
                .map(|e| match e {
                    NormalizedAssetConfig::File { encodings, .. } => encodings.clone(),
                    NormalizedAssetConfig::Pattern { encodings, .. } => encodings.clone(),
                    _ => vec![],
                })
                .unwrap_or_default()
            {
                let encoded_asset_path = format!("{}.{}", asset.path, postfix);
                let encoded_asset = asset_map.get(encoded_asset_path.as_str()).cloned();

                if let Some(mut encoded_asset) = encoded_asset {
                    encoded_asset.url.clone_from(&asset.url);

                    self.delete_asset_impl(encoded_asset, asset_config, Some(&encoding))?;
                }
            }

            self.delete_asset_impl(asset.clone(), asset_config, None)?;
        }

        for asset_config in asset_configs {
            if let NormalizedAssetConfig::Redirect { from, to, kind } = asset_config {
                self.delete_redirect(from, to, kind)?;
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
        encoding: Option<&AssetEncoding>,
    ) -> AssetCertificationResult {
        match asset_config {
            Some(NormalizedAssetConfig::Pattern {
                content_type,
                headers,
                ..
            }) => {
                self.insert_static_asset(asset, content_type.clone(), headers.clone(), encoding)?;
            }
            Some(NormalizedAssetConfig::File {
                content_type,
                headers,
                fallback_for,
                aliased_by,
                ..
            }) => {
                self.insert_static_asset(
                    asset.clone(),
                    content_type.clone(),
                    headers.clone(),
                    encoding,
                )?;

                for fallback_for in fallback_for.iter() {
                    self.insert_fallback_asset(
                        asset.clone(),
                        content_type.clone(),
                        headers.clone(),
                        fallback_for.clone(),
                        encoding,
                    )?;
                }

                for aliased_by in aliased_by.iter() {
                    let mut aliased_asset = asset.clone();
                    aliased_asset.url = Cow::Owned(aliased_by.clone());

                    self.insert_static_asset(
                        aliased_asset,
                        content_type.clone(),
                        headers.clone(),
                        encoding,
                    )?;
                }
            }
            _ => {
                self.insert_static_asset(asset, None, vec![], encoding)?;
            }
        }

        Ok(())
    }

    fn delete_asset_impl<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        asset_config: Option<&NormalizedAssetConfig>,
        encoding: Option<&AssetEncoding>,
    ) -> AssetCertificationResult {
        match asset_config {
            Some(NormalizedAssetConfig::Pattern {
                content_type,
                headers,
                ..
            }) => {
                self.delete_static_asset(asset, content_type.clone(), headers.clone(), encoding)?;
            }
            Some(NormalizedAssetConfig::File {
                content_type,
                headers,
                fallback_for,
                aliased_by,
                ..
            }) => {
                self.delete_static_asset(
                    asset.clone(),
                    content_type.clone(),
                    headers.clone(),
                    encoding,
                )?;

                for fallback_for in fallback_for.iter() {
                    self.delete_fallback_asset(
                        asset.clone(),
                        content_type.clone(),
                        headers.clone(),
                        fallback_for.clone(),
                        encoding,
                    )?;
                }

                for aliased_by in aliased_by.iter() {
                    let mut aliased_asset = asset.clone();
                    aliased_asset.url = Cow::Owned(aliased_by.clone());

                    self.delete_static_asset(
                        aliased_asset,
                        content_type.clone(),
                        headers.clone(),
                        encoding,
                    )?;
                }
            }
            _ => {
                self.delete_static_asset(asset, None, vec![], encoding)?;
            }
        }

        Ok(())
    }

    fn insert_static_asset<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
        encoding: Option<&AssetEncoding>,
    ) -> AssetCertificationResult<()> {
        let asset_url = asset.url.to_string();
        let response =
            Self::prepare_static_asset(asset, content_type, additional_headers, encoding)?;

        self.tree.borrow_mut().insert(&response.tree_entry);
        match encoding {
            Some(encoding) => {
                self.encoded_responses
                    .insert((asset_url, encoding.to_string()), response);
            }
            None => {
                self.responses.insert(asset_url.clone(), response);
            }
        }

        Ok(())
    }

    fn delete_static_asset<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
        encoding: Option<&AssetEncoding>,
    ) -> AssetCertificationResult<()> {
        let asset_url = asset.url.to_string();
        let response =
            Self::prepare_static_asset(asset, content_type, additional_headers, encoding)?;

        self.tree.borrow_mut().delete(&response.tree_entry);
        match encoding {
            Some(encoding) => {
                self.encoded_responses
                    .remove(&(asset_url, encoding.to_string()));
            }
            None => {
                self.responses.remove(&asset_url);
            }
        }

        Ok(())
    }

    fn prepare_static_asset<'path>(
        asset: Asset<'content, 'path>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
        encoding: Option<&AssetEncoding>,
    ) -> AssetCertificationResult<CertifiedAssetResponse<'content>> {
        let asset_url = asset.url.to_string();

        let (response, certification) = Self::prepare_asset_response_and_certification(
            asset,
            additional_headers,
            content_type,
            encoding,
        )?;

        let tree_entry =
            HttpCertificationTreeEntry::new(HttpCertificationPath::exact(asset_url), certification);

        Ok(CertifiedAssetResponse {
            response,
            tree_entry,
        })
    }

    fn insert_fallback_asset<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
        fallback_for: AssetFallbackConfig,
        encoding: Option<&AssetEncoding>,
    ) -> AssetCertificationResult<()> {
        let response = Self::prepare_fallback_asset(
            asset,
            additional_headers,
            content_type,
            fallback_for.clone(),
            encoding,
        )?;

        self.tree.borrow_mut().insert(&response.tree_entry);

        if let Some(encoding) = encoding {
            self.encoded_fallback_responses
                .insert((fallback_for.scope, encoding.to_string()), response);
        } else {
            self.fallback_responses.insert(fallback_for.scope, response);
        }

        Ok(())
    }

    fn delete_fallback_asset<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
        fallback_for: AssetFallbackConfig,
        encoding: Option<&AssetEncoding>,
    ) -> AssetCertificationResult<()> {
        let response = Self::prepare_fallback_asset(
            asset,
            additional_headers,
            content_type,
            fallback_for.clone(),
            encoding,
        )?;

        self.tree.borrow_mut().delete(&response.tree_entry);

        if let Some(encoding) = encoding {
            self.encoded_fallback_responses
                .remove(&(fallback_for.scope, encoding.to_string()));
        } else {
            self.fallback_responses.remove(&fallback_for.scope);
        }

        Ok(())
    }

    fn prepare_fallback_asset<'path>(
        asset: Asset<'content, 'path>,
        additional_headers: Vec<(String, String)>,
        content_type: Option<String>,
        fallback_for: AssetFallbackConfig,
        encoding: Option<&AssetEncoding>,
    ) -> AssetCertificationResult<CertifiedAssetResponse<'content>> {
        let (response, certification) = Self::prepare_asset_response_and_certification(
            asset,
            additional_headers,
            content_type,
            encoding,
        )?;

        let tree_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::wildcard(fallback_for.scope.clone()),
            certification,
        );

        Ok(CertifiedAssetResponse {
            response,
            tree_entry,
        })
    }

    fn insert_redirect(
        &mut self,
        from: String,
        to: String,
        kind: AssetRedirectKind,
    ) -> AssetCertificationResult<()> {
        let response = Self::prepare_redirect(from.clone(), to, kind)?;

        self.tree.borrow_mut().insert(&response.tree_entry);

        self.responses.insert(from, response);

        Ok(())
    }

    fn delete_redirect(
        &mut self,
        from: String,
        to: String,
        kind: AssetRedirectKind,
    ) -> AssetCertificationResult<()> {
        let response = Self::prepare_redirect(from.clone(), to, kind)?;

        self.tree.borrow_mut().delete(&response.tree_entry);
        self.responses.remove(&from);

        Ok(())
    }

    fn prepare_redirect(
        from: String,
        to: String,
        kind: AssetRedirectKind,
    ) -> AssetCertificationResult<CertifiedAssetResponse<'content>> {
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

        Ok(CertifiedAssetResponse {
            response,
            tree_entry: HttpCertificationTreeEntry::new(
                HttpCertificationPath::exact(from),
                certification,
            ),
        })
    }

    fn prepare_asset_response_and_certification<'path>(
        asset: Asset<'content, 'path>,
        additional_headers: Vec<(String, String)>,
        content_type: Option<String>,
        encoding: Option<&AssetEncoding>,
    ) -> AssetCertificationResult<(AssetResponse<'content>, HttpCertification)> {
        let mut headers = vec![];

        headers.extend(additional_headers);

        if let Some(content_type) = content_type {
            headers.push(("content-type".to_string(), content_type));
        }

        if let Some(encoding) = encoding {
            headers.push(("content-encoding".to_string(), encoding.to_string()));
        }

        Self::prepare_response_and_certification(asset.url.to_string(), 200, asset.content, headers)
    }

    fn prepare_response_and_certification(
        url: String,
        status_code: u16,
        body: Cow<'content, [u8]>,
        additional_headers: Vec<(String, String)>,
    ) -> AssetCertificationResult<(AssetResponse<'content>, HttpCertification)> {
        let mut headers = vec![("content-length".to_string(), body.len().to_string())];

        headers.extend(additional_headers);

        let cel_expr = DefaultCelBuilder::full_certification()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build();
        let cel_expr_str = cel_expr.to_string();
        headers.push((IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), cel_expr_str));

        let request = HttpRequest::get(url).build();

        let response = AssetResponse::new(status_code, body, headers);

        let http_response: HttpResponse = response.clone().into();

        let certification = HttpCertification::full(&cel_expr, &request, &http_response, None)?;

        Ok((response, certification))
    }

    fn get_encoded_asset(
        &self,
        preferred_encodings: &[&str],
        url: &str,
    ) -> Option<&CertifiedAssetResponse<'content>> {
        for encoding in preferred_encodings {
            if let Some(response) = self
                .encoded_responses
                .get(&(url.to_string(), encoding.to_string()))
            {
                return Some(response);
            }
        }

        None
    }

    fn get_encoded_fallback_asset(
        &self,
        preferred_encodings: &[&str],
        scope: &str,
    ) -> Option<&CertifiedAssetResponse<'content>> {
        for encoding in preferred_encodings {
            if let Some(response) = self
                .encoded_fallback_responses
                .get(&(scope.to_string(), encoding.to_string()))
            {
                return Some(response);
            }
        }

        None
    }

    fn get_preferred_encodings<'a>(&self, request: &'a HttpRequest) -> Vec<&'a str> {
        for (name, value) in request.headers().iter() {
            if name.to_lowercase() == "accept-encoding" {
                return Self::prioritized_encodings(value)
                    .iter()
                    .map(|(encoding, _quality)| *encoding)
                    .collect();
            }
        }

        vec![]
    }

    fn prioritized_encodings(encodings: &str) -> Vec<(&str, f32)> {
        let mut encodings = encodings
            .split(',')
            .filter_map(|encoding| {
                encoding
                    .split(';')
                    .collect::<Vec<_>>()
                    .first()
                    .map(|s| s.trim())
                    .map(|s| (s, Self::default_encoding_quality(s)))
            })
            .collect::<Vec<_>>();

        // this `unwrap()` call is safe as long as the values returned by
        // `default_encoding_quality` are comparable (not NaN)
        encodings.sort_unstable_by(|(_, a), (_, b)| b.partial_cmp(a).unwrap());

        encodings
    }

    fn default_encoding_quality(encoding: &str) -> f32 {
        if encoding.eq_ignore_ascii_case("br") {
            return 1.0;
        }

        if encoding.eq_ignore_ascii_case("zstd") {
            return 0.9;
        }

        if encoding.eq_ignore_ascii_case("gzip") {
            return 0.8;
        }

        if encoding.eq_ignore_ascii_case("deflate") {
            return 0.7;
        }

        if encoding.eq_ignore_ascii_case("identity") {
            return 0.5;
        }

        0.6
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
    use ic_http_certification::{
        assert_response_eq, cel::DefaultFullCelExpressionBuilder, HeaderField,
    };
    use rstest::*;
    use std::vec;

    #[rstest]
    #[case("/")]
    #[case("https://internetcomputer.org/")]
    fn test_index_html(mut asset_router: AssetRouter, #[case] req_url: &str) {
        let request = HttpRequest::get(req_url).build();

        let expected_response = build_response(
            index_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "", "<$>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![Asset::new("index.html", index_html_body())],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == request.get_path().unwrap()
        ));
    }

    #[rstest]
    #[case(index_html_zz_body(), "/", "deflate", "deflate")]
    #[case(index_html_zz_body(), "/", "deflate, identity", "deflate")]
    #[case(index_html_gz_body(), "/", "gzip", "gzip")]
    #[case(index_html_gz_body(), "/", "gzip, identity", "gzip")]
    #[case(index_html_gz_body(), "/", "gzip, deflate", "gzip")]
    #[case(index_html_gz_body(), "/", "gzip, deflate, identity", "gzip")]
    #[case(index_html_br_body(), "/", "br", "br")]
    #[case(index_html_br_body(), "/", "br, gzip, deflate, identity", "br")]
    #[case(index_html_br_body(), "/", "gzip, deflate, identity, br", "br")]
    #[case(index_html_zz_body(), "/index.html", "deflate", "deflate")]
    #[case(index_html_zz_body(), "/index.html", "deflate, identity", "deflate")]
    #[case(index_html_gz_body(), "/index.html", "gzip", "gzip")]
    #[case(index_html_gz_body(), "/index.html", "gzip, identity", "gzip")]
    #[case(index_html_gz_body(), "/index.html", "gzip, deflate", "gzip")]
    #[case(index_html_gz_body(), "/index.html", "gzip, deflate, identity", "gzip")]
    #[case(index_html_br_body(), "/index.html", "br", "br")]
    #[case(
        index_html_br_body(),
        "/index.html",
        "br, gzip, deflate, identity",
        "br"
    )]
    #[case(
        index_html_br_body(),
        "/index.html",
        "gzip, deflate, identity, br",
        "br"
    )]
    fn test_encoded_index_html(
        #[case] expected_body: Vec<u8>,
        #[case] req_url: &str,
        #[case] accept_encoding: &str,
        #[case] expected_encoding: &str,
        mut asset_router: AssetRouter,
    ) {
        let request = HttpRequest::get(req_url)
            .with_headers(vec![(
                "accept-encoding".to_string(),
                accept_encoding.to_string(),
            )])
            .build();
        let expected_response = build_response(
            expected_body,
            encoded_asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (
                    "content-encoding".to_string(),
                    expected_encoding.to_string(),
                ),
            ],
        );
        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(
            expr_path,
            HttpCertificationPath::exact(req_url).to_expr_path()
        );
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("index.html", index_html_body()),
                    Asset::new("index.html.gz", index_html_gz_body()),
                    Asset::new("index.html.zz", index_html_zz_body()),
                    Asset::new("index.html.br", index_html_br_body()),
                ],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == req_url
        ));
    }

    #[rstest]
    #[case(index_html_zz_body(), "/something", "deflate", "deflate")]
    #[case(index_html_zz_body(), "/something", "deflate, identity", "deflate")]
    #[case(index_html_gz_body(), "/something", "gzip", "gzip")]
    #[case(index_html_gz_body(), "/something", "gzip, identity", "gzip")]
    #[case(index_html_gz_body(), "/something", "gzip, deflate", "gzip")]
    #[case(index_html_gz_body(), "/something", "gzip, deflate, identity", "gzip")]
    #[case(index_html_br_body(), "/something", "br", "br")]
    #[case(
        index_html_br_body(),
        "/something",
        "br, gzip, deflate, identity",
        "br"
    )]
    #[case(
        index_html_br_body(),
        "/something",
        "gzip, deflate, identity, br",
        "br"
    )]
    #[case(index_html_zz_body(), "/assets/css/app.css", "deflate", "deflate")]
    #[case(
        index_html_zz_body(),
        "/assets/css/app.css",
        "deflate, identity",
        "deflate"
    )]
    #[case(index_html_gz_body(), "/assets/css/app.css", "gzip", "gzip")]
    #[case(index_html_gz_body(), "/assets/css/app.css", "gzip, identity", "gzip")]
    #[case(index_html_gz_body(), "/assets/css/app.css", "gzip, deflate", "gzip")]
    #[case(
        index_html_gz_body(),
        "/assets/css/app.css",
        "gzip, deflate, identity",
        "gzip"
    )]
    #[case(index_html_br_body(), "/assets/css/app.css", "br", "br")]
    #[case(
        index_html_br_body(),
        "/assets/css/app.css",
        "br, gzip, deflate, identity",
        "br"
    )]
    #[case(
        index_html_br_body(),
        "/assets/css/app.css",
        "gzip, deflate, identity, br",
        "br"
    )]
    fn test_encoded_index_html_fallback(
        #[case] expected_body: Vec<u8>,
        #[case] req_url: &str,
        #[case] accept_encoding: &str,
        #[case] expected_encoding: &str,
        mut asset_router: AssetRouter,
    ) {
        let request = HttpRequest::get(req_url)
            .with_headers(vec![(
                "accept-encoding".to_string(),
                accept_encoding.to_string(),
            )])
            .build();
        let expected_response = build_response(
            expected_body,
            encoded_asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (
                    "content-encoding".to_string(),
                    expected_encoding.to_string(),
                ),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        let requested_expr_path = HttpCertificationPath::exact(req_url).to_expr_path();
        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert!(matches!(
            witness.lookup_subtree(&requested_expr_path),
            SubtreeLookupResult::Absent
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("index.html", index_html_body()),
                    Asset::new("index.html.gz", index_html_gz_body()),
                    Asset::new("index.html.zz", index_html_zz_body()),
                    Asset::new("index.html.br", index_html_br_body()),
                ],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == req_url
        ));
    }

    #[rstest]
    #[case("/something", "/something")]
    #[case("https://internetcomputer.org/something", "/something")]
    fn test_index_html_root_fallback(
        mut asset_router: AssetRouter,
        #[case] req_url: &str,
        #[case] req_path: &str,
    ) {
        let expected_response = build_response(
            index_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let request = HttpRequest::get(req_url).build();
        let requested_expr_path = HttpCertificationPath::exact(req_path).to_expr_path();

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
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("index.html", index_html_body()),
                    Asset::new("index.html.gz", index_html_gz_body()),
                    Asset::new("index.html.zz", index_html_zz_body()),
                    Asset::new("index.html.br", index_html_br_body()),
                ],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == req_path
        ));
    }

    #[rstest]
    #[case("/assets/css/app.css", "/assets/css/app.css")]
    #[case(
        "https://internetcomputer.org/assets/css/app.css",
        "/assets/css/app.css"
    )]
    fn test_index_html_nested_fallback(
        mut asset_router: AssetRouter,
        #[case] req_url: &str,
        #[case] req_path: &str,
    ) {
        let expected_response = build_response(
            index_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let request = HttpRequest::get(req_url).build();
        let requested_expr_path = HttpCertificationPath::exact(req_path).to_expr_path();

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
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("index.html", index_html_body()),
                    Asset::new("index.html.gz", index_html_gz_body()),
                    Asset::new("index.html.zz", index_html_zz_body()),
                    Asset::new("index.html.br", index_html_br_body()),
                ],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == req_path
        ));
    }

    #[rstest]
    #[case("/css/app-ba74b708.css")]
    #[case("https://internetcomputer.org/css/app-ba74b708.css")]
    fn text_app_css(mut asset_router: AssetRouter, #[case] req_url: &str) {
        let request = HttpRequest::get(req_url).build();
        let expected_response = build_response(
            app_css_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, max-age=31536000, immutable".to_string(),
                ),
                ("content-type".to_string(), "text/css".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(
            expr_path,
            vec!["http_expr", "css", "app-ba74b708.css", "<$>"]
        );
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![Asset::new("css/app-ba74b708.css", app_css_body())],
                vec![css_config()],
            )
            .unwrap();
        let expected_response = build_response(
            not_found_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();
        assert_eq!(expr_path, vec!["http_expr", "css", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("not-found.html", not_found_html_body()),
                    Asset::new("not-found.html.gz", not_found_html_gz_body()),
                    Asset::new("not-found.html.zz", not_found_html_zz_body()),
                    Asset::new("not-found.html.br", not_found_html_br_body()),
                ],
                vec![not_found_html_config()],
            )
            .unwrap();
        let expected_response = build_response(
            index_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();
        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("index.html", index_html_body()),
                    Asset::new("index.html.gz", index_html_gz_body()),
                    Asset::new("index.html.zz", index_html_zz_body()),
                    Asset::new("index.html.br", index_html_br_body()),
                ],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == request.get_path().unwrap()
        ));
    }

    #[rstest]
    #[case("/css/core-8d4jhgy2.js")]
    #[case("https://internetcomputer.org/css/core-8d4jhgy2.js")]
    fn test_not_found_css(mut asset_router: AssetRouter, #[case] req_url: &str) {
        let request = HttpRequest::get(req_url).build();
        let expected_response = build_response(
            not_found_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "css", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("not-found.html", not_found_html_body()),
                    Asset::new("not-found.html.gz", not_found_html_gz_body()),
                    Asset::new("not-found.html.zz", not_found_html_zz_body()),
                    Asset::new("not-found.html.br", not_found_html_br_body()),
                ],
                vec![not_found_html_config()],
            )
            .unwrap();
        let expected_response = build_response(
            index_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();
        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("index.html", index_html_body()),
                    Asset::new("index.html.gz", index_html_gz_body()),
                    Asset::new("index.html.zz", index_html_zz_body()),
                    Asset::new("index.html.br", index_html_br_body()),
                ],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == request.get_path().unwrap()
        ));
    }

    #[rstest]
    #[case("/js/app-488df671.js")]
    #[case("https://internetcomputer.org/js/app-488df671.js")]
    fn test_app_js(mut asset_router: AssetRouter, #[case] req_url: &str) {
        let request = HttpRequest::get(req_url).build();
        let expected_response = build_response(
            app_js_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, max-age=31536000, immutable".to_string(),
                ),
                ("content-type".to_string(), "text/javascript".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "js", "app-488df671.js", "<$>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("js/app-488df671.js", app_js_body()),
                    Asset::new("js/app-488df671.js.gz", app_js_gz_body()),
                    Asset::new("js/app-488df671.js.zz", app_js_zz_body()),
                    Asset::new("js/app-488df671.js.br", app_js_br_body()),
                ],
                vec![js_config()],
            )
            .unwrap();
        let expected_response = build_response(
            not_found_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();
        assert_eq!(expr_path, vec!["http_expr", "js", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("not-found.html", not_found_html_body()),
                    Asset::new("not-found.html.gz", not_found_html_gz_body()),
                    Asset::new("not-found.html.zz", not_found_html_zz_body()),
                    Asset::new("not-found.html.br", not_found_html_br_body()),
                ],
                vec![not_found_html_config()],
            )
            .unwrap();
        let expected_response = build_response(
            index_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();
        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("index.html", index_html_body()),
                    Asset::new("index.html.gz", index_html_gz_body()),
                    Asset::new("index.html.zz", index_html_zz_body()),
                    Asset::new("index.html.br", index_html_br_body()),
                ],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == request.get_path().unwrap()
        ));
    }

    #[rstest]
    #[case(
        app_js_zz_body(),
        not_found_html_zz_body(),
        index_html_zz_body(),
        "deflate",
        "deflate"
    )]
    #[case(
        app_js_zz_body(),
        not_found_html_zz_body(),
        index_html_zz_body(),
        "deflate, identity",
        "deflate"
    )]
    #[case(
        app_js_zz_body(),
        not_found_html_zz_body(),
        index_html_zz_body(),
        "identity, deflate",
        "deflate"
    )]
    #[case(
        app_js_gz_body(),
        not_found_html_gz_body(),
        index_html_gz_body(),
        "gzip",
        "gzip"
    )]
    #[case(
        app_js_gz_body(),
        not_found_html_gz_body(),
        index_html_gz_body(),
        "gzip, identity",
        "gzip"
    )]
    #[case(
        app_js_gz_body(),
        not_found_html_gz_body(),
        index_html_gz_body(),
        "identity, gzip",
        "gzip"
    )]
    #[case(
        app_js_gz_body(),
        not_found_html_gz_body(),
        index_html_gz_body(),
        "gzip, deflate",
        "gzip"
    )]
    #[case(
        app_js_gz_body(),
        not_found_html_gz_body(),
        index_html_gz_body(),
        "deflate, gzip",
        "gzip"
    )]
    #[case(
        app_js_gz_body(),
        not_found_html_gz_body(),
        index_html_gz_body(),
        "gzip, deflate, identity",
        "gzip"
    )]
    #[case(
        app_js_gz_body(),
        not_found_html_gz_body(),
        index_html_gz_body(),
        "gzip, identity, deflate",
        "gzip"
    )]
    #[case(
        app_js_gz_body(),
        not_found_html_gz_body(),
        index_html_gz_body(),
        "identity, gzip, deflate",
        "gzip"
    )]
    #[case(
        app_js_gz_body(),
        not_found_html_gz_body(),
        index_html_gz_body(),
        "identity, deflate, gzip",
        "gzip"
    )]
    #[case(
        app_js_gz_body(),
        not_found_html_gz_body(),
        index_html_gz_body(),
        "deflate, gzip, identity",
        "gzip"
    )]
    #[case(
        app_js_gz_body(),
        not_found_html_gz_body(),
        index_html_gz_body(),
        "deflate, identity, gzip",
        "gzip"
    )]
    #[case(
        app_js_br_body(),
        not_found_html_br_body(),
        index_html_br_body(),
        "br",
        "br"
    )]
    #[case(
        app_js_br_body(),
        not_found_html_br_body(),
        index_html_br_body(),
        "br, gzip, deflate, identity",
        "br"
    )]
    #[case(
        app_js_br_body(),
        not_found_html_br_body(),
        index_html_br_body(),
        "gzip, deflate, identity, br",
        "br"
    )]
    fn test_encoded_app_js(
        #[case] expected_body: Vec<u8>,
        #[case] expected_not_found_body: Vec<u8>,
        #[case] expected_index_body: Vec<u8>,
        #[case] accept_encoding: &str,
        #[case] expected_encoding: &str,
        mut asset_router: AssetRouter,
    ) {
        let request = HttpRequest::get("/js/app-488df671.js")
            .with_headers(vec![(
                "accept-encoding".to_string(),
                accept_encoding.to_string(),
            )])
            .build();

        let expected_response = build_response(
            expected_body,
            encoded_asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, max-age=31536000, immutable".to_string(),
                ),
                ("content-type".to_string(), "text/javascript".to_string()),
                (
                    "content-encoding".to_string(),
                    expected_encoding.to_string(),
                ),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "js", "app-488df671.js", "<$>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("js/app-488df671.js", app_js_body()),
                    Asset::new("js/app-488df671.js.gz", app_js_gz_body()),
                    Asset::new("js/app-488df671.js.zz", app_js_zz_body()),
                    Asset::new("js/app-488df671.js.br", app_js_br_body()),
                ],
                vec![js_config()],
            )
            .unwrap();
        let expected_response = build_response(
            expected_not_found_body,
            encoded_asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (
                    "content-encoding".to_string(),
                    expected_encoding.to_string(),
                ),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();
        assert_eq!(expr_path, vec!["http_expr", "js", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("not-found.html", not_found_html_body()),
                    Asset::new("not-found.html.gz", not_found_html_gz_body()),
                    Asset::new("not-found.html.zz", not_found_html_zz_body()),
                    Asset::new("not-found.html.br", not_found_html_br_body()),
                ],
                vec![not_found_html_config()],
            )
            .unwrap();
        let expected_response = build_response(
            expected_index_body,
            encoded_asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (
                    "content-encoding".to_string(),
                    expected_encoding.to_string(),
                ),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();
        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("index.html", index_html_body()),
                    Asset::new("index.html.gz", index_html_gz_body()),
                    Asset::new("index.html.zz", index_html_zz_body()),
                    Asset::new("index.html.br", index_html_br_body()),
                ],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == request.get_path().unwrap()
        ));
    }

    #[rstest]
    #[case("/js/core-7dk12y45.js")]
    #[case("https://internetcomputer.org/js/core-7dk12y45.js")]
    fn test_not_found_js(mut asset_router: AssetRouter, #[case] req_url: &str) {
        let request = HttpRequest::get(req_url).build();
        let expected_response = build_response(
            not_found_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "js", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("not-found.html", not_found_html_body()),
                    Asset::new("not-found.html.gz", not_found_html_gz_body()),
                    Asset::new("not-found.html.zz", not_found_html_zz_body()),
                    Asset::new("not-found.html.br", not_found_html_br_body()),
                ],
                vec![not_found_html_config()],
            )
            .unwrap();

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        let expected_response = build_response(
            index_html_body(),
            asset_cel_expr(),
            vec![
                ("content-type".to_string(), "text/html".to_string()),
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
            ],
        );
        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("index.html", index_html_body()),
                    Asset::new("index.html.gz", index_html_gz_body()),
                    Asset::new("index.html.zz", index_html_zz_body()),
                    Asset::new("index.html.br", index_html_br_body()),
                ],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == request.get_path().unwrap()
        ));
    }

    #[rstest]
    #[case("/404")]
    #[case("https://internetcomputer.org/404")]
    #[case("/404/")]
    #[case("https://internetcomputer.org/404/")]
    #[case("/404.html")]
    #[case("https://internetcomputer.org/404.html")]
    #[case("/not-found")]
    #[case("https://internetcomputer.org/not-found")]
    #[case("/not-found/")]
    #[case("https://internetcomputer.org/not-found/")]
    #[case("/not-found/index.html")]
    #[case("https://internetcomputer.org/not-found/index.html")]
    fn test_not_found_alias(mut asset_router: AssetRouter, #[case] req_url: &str) {
        let request = HttpRequest::get(req_url).build();

        let expected_response = build_response(
            not_found_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(
            expr_path,
            HttpCertificationPath::exact(request.get_path().unwrap()).to_expr_path()
        );
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("not-found.html", not_found_html_body()),
                    Asset::new("not-found.html.gz", not_found_html_gz_body()),
                    Asset::new("not-found.html.zz", not_found_html_zz_body()),
                    Asset::new("not-found.html.br", not_found_html_br_body()),
                ],
                vec![not_found_html_config()],
            )
            .unwrap();

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        let expected_response = build_response(
            index_html_body(),
            asset_cel_expr(),
            vec![
                ("content-type".to_string(), "text/html".to_string()),
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
            ],
        );
        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("index.html", index_html_body()),
                    Asset::new("index.html.gz", index_html_gz_body()),
                    Asset::new("index.html.zz", index_html_zz_body()),
                    Asset::new("index.html.br", index_html_br_body()),
                ],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == request.get_path().unwrap()
        ));
    }

    #[rstest]
    fn test_redirects(mut asset_router: AssetRouter) {
        let cel_expr = DefaultFullCelExpressionBuilder::default()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build()
            .to_string();

        let css_request = HttpRequest::get("/css/app.css").build();
        let old_url_request = HttpRequest::get("/old-url").build();

        let expected_css_response = HttpResponse::builder()
            .with_status_code(307)
            .with_headers(vec![
                ("content-length".to_string(), "0".to_string()),
                ("location".to_string(), "/css/app-ba74b708.css".to_string()),
                (
                    IC_CERTIFICATE_EXPRESSION_HEADER.to_string(),
                    cel_expr.clone(),
                ),
            ])
            .build();
        let expected_old_url_response = HttpResponse::builder()
            .with_status_code(301)
            .with_headers(vec![
                ("content-length".to_string(), "0".to_string()),
                ("location".to_string(), "/".to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), cel_expr),
            ])
            .build();

        let (css_response, css_witness, css_expr_path) =
            asset_router.serve_asset(&css_request).unwrap();
        let (old_url_response, old_url_witness, old_url_expr_path) =
            asset_router.serve_asset(&old_url_request).unwrap();

        assert_eq!(css_expr_path, vec!["http_expr", "css", "app.css", "<$>"]);
        assert!(matches!(
            css_witness.lookup_subtree(&css_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(css_response, expected_css_response);

        assert_eq!(old_url_expr_path, vec!["http_expr", "old-url", "<$>"]);
        assert!(matches!(
            old_url_witness.lookup_subtree(&old_url_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(old_url_response, expected_old_url_response);

        asset_router
            .delete_assets(
                vec![],
                vec![old_url_redirect_config(), css_redirect_config()],
            )
            .unwrap();
        let expected_css_response = build_response(
            not_found_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );
        let expected_old_url_response = build_response(
            index_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (css_response, css_witness, css_expr_path) =
            asset_router.serve_asset(&css_request).unwrap();
        let (old_url_response, old_url_witness, old_url_expr_path) =
            asset_router.serve_asset(&old_url_request).unwrap();

        assert_eq!(css_expr_path, vec!["http_expr", "css", "<*>"]);
        assert!(matches!(
            css_witness.lookup_subtree(&css_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(css_response, expected_css_response);

        assert_eq!(old_url_expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            old_url_witness.lookup_subtree(&old_url_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(old_url_response, expected_old_url_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("not-found.html", not_found_html_body()),
                    Asset::new("not-found.html.gz", not_found_html_gz_body()),
                    Asset::new("not-found.html.zz", not_found_html_zz_body()),
                    Asset::new("not-found.html.br", not_found_html_br_body()),
                ],
                vec![not_found_html_config()],
            )
            .unwrap();
        let expected_css_response = build_response(
            index_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );
        let expected_old_url_response = build_response(
            index_html_body(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (css_response, css_witness, css_expr_path) =
            asset_router.serve_asset(&css_request).unwrap();
        let (old_url_response, old_url_witness, old_url_expr_path) =
            asset_router.serve_asset(&old_url_request).unwrap();

        assert_eq!(css_expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            css_witness.lookup_subtree(&css_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(css_response, expected_css_response);

        assert_eq!(old_url_expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            old_url_witness.lookup_subtree(&old_url_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(old_url_response, expected_old_url_response);

        asset_router
            .delete_assets(
                vec![
                    Asset::new("index.html", index_html_body()),
                    Asset::new("index.html.gz", index_html_gz_body()),
                    Asset::new("index.html.zz", index_html_zz_body()),
                    Asset::new("index.html.br", index_html_br_body()),
                ],
                vec![index_html_config()],
            )
            .unwrap();

        let css_result = asset_router.serve_asset(&css_request);
        let old_url_result = asset_router.serve_asset(&old_url_request);

        assert!(matches!(
            css_result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == css_request.get_path().unwrap()
        ));
        assert!(matches!(
            old_url_result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == old_url_request.get_path().unwrap()
        ));
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
            encodings: vec![],
        };

        asset_router
            .certify_assets(vec![index_html_asset], vec![index_html_config])
            .unwrap();

        let request = HttpRequest::get("/").build();

        let expected_response = build_response(
            index_html_body.clone(),
            asset_cel_expr,
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
            ],
        );

        let (response, witness, expr_path) = asset_router.serve_asset(&request).unwrap();

        assert_eq!(expr_path, vec!["http_expr", "", "<$>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_response_eq(response, expected_response);
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
    fn index_html_gz_body() -> Vec<u8> {
        vec![
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 179, 201, 40, 201, 205, 177, 179, 73, 202, 79, 169,
            180, 179, 201, 48, 180, 243, 72, 205, 201, 201, 87, 8, 207, 47, 202, 73, 81, 180, 209,
            7, 10, 216, 232, 67, 228, 244, 193, 10, 1, 28, 178, 8, 152, 47, 0, 0, 0,
        ]
    }

    #[fixture]
    fn index_html_zz_body() -> Vec<u8> {
        vec![
            78, 9, 3, 9, 28, 9, 1, 3, 49, 4, 9, 4, 3, 9, 30, 4, 3, 48, 9, 9, 57, 8, 2, 49, 51, 4,
            1, 7, 0, 8, 8, 43, 4, 4, 1, 0, 1, 7, 8, 0, 9,
        ]
    }

    #[fixture]
    fn index_html_br_body() -> Vec<u8> {
        vec![
            1, 2, 0, 8, 1, 9, 36, 2, 72, 65, 4, 25, 0, 5, 84, 0, 5, 18, 1, 64, 14, 5, 4, 1, 9, 0,
            3, 4, 42, 2, 1, 59, 13, 14, 3, 19, 69, 18,
        ]
    }

    #[fixture]
    fn app_js_body() -> Vec<u8> {
        b"console.log('Hello World!');".to_vec()
    }

    #[fixture]
    fn app_js_gz_body() -> Vec<u8> {
        vec![
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 75, 206, 207, 43, 206, 207, 73, 213, 203, 201, 79,
            215, 80, 247, 72, 205, 201, 201, 87, 8, 207, 47, 202, 73, 81, 84, 215, 180, 6, 0, 186,
            42, 111, 142, 28, 0, 0, 0,
        ]
    }

    #[fixture]
    fn app_js_zz_body() -> Vec<u8> {
        vec![
            120, 156, 75, 206, 207, 43, 206, 207, 73, 213, 203, 201, 79, 215, 80, 247, 72, 205,
            201, 201, 87, 8, 207, 47, 202, 73, 81, 84, 215, 180, 6, 0, 148, 149, 9, 123,
        ]
    }

    #[fixture]
    fn app_js_br_body() -> Vec<u8> {
        vec![
            8, 0, 80, 63, 6, 6, 73, 6, 6, 65, 2, 6, 6, 67, 28, 27, 48, 65, 6, 6, 6, 20, 57, 6, 72,
            6, 64, 21, 27, 29, 3, 3,
        ]
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
    fn not_found_html_gz_body() -> Vec<u8> {
        vec![
            49, 19, 9, 8, 0, 0, 0, 0, 0, 0, 3, 23, 9, 32, 1, 64, 32, 1, 32, 5, 23, 7, 23, 9, 115,
            32, 2, 121, 22, 9, 24, 0, 23, 9, 32, 1, 72, 24, 0, 81, 73, 72, 129, 36, 0, 32, 3, 71,
            129, 17, 2, 32, 3, 71, 32, 5, 117, 129, 24, 0, 32, 9, 7, 16, 33, 7, 35, 2, 103, 16, 0,
            36, 5, 25, 3, 116, 1, 37, 4, 36, 9, 17, 0, 114, 73, 0, 0, 0,
        ]
    }

    #[fixture]
    fn not_found_html_zz_body() -> Vec<u8> {
        vec![
            120, 156, 179, 201, 40, 201, 205, 177, 179, 73, 202, 79, 169, 180, 179, 201, 48, 180,
            51, 49, 48, 81, 240, 203, 47, 81, 112, 203, 47, 205, 75, 81, 180, 209, 7, 10, 217, 232,
            67, 100, 245, 193, 74, 1, 133, 210, 15, 136,
        ]
    }

    #[fixture]
    fn not_found_html_br_body() -> Vec<u8> {
        vec![
            27, 48, 0, 248, 45, 14, 108, 27, 88, 249, 245, 45, 213, 3, 233, 193, 146, 199, 9, 173,
            64, 104, 10, 230, 173, 67, 124, 216, 218, 84, 12, 93, 47, 66, 139, 48, 3, 233, 78, 128,
            105, 198, 36, 242, 83, 62, 179, 122, 129, 33, 16, 12,
        ]
    }

    #[fixture]
    fn asset_cel_expr() -> String {
        DefaultFullCelExpressionBuilder::default()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build()
            .to_string()
    }

    #[fixture]
    fn encoded_asset_cel_expr() -> String {
        DefaultFullCelExpressionBuilder::default()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build()
            .to_string()
    }

    #[fixture]
    fn index_html_config() -> AssetConfig {
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
            encodings: vec![
                AssetEncoding::Gzip.default_config(),
                AssetEncoding::Deflate.default_config(),
                AssetEncoding::Brotli.default_config(),
            ],
        }
    }

    #[fixture]
    fn js_config() -> AssetConfig {
        AssetConfig::Pattern {
            pattern: r"**/*.js".to_string(),
            content_type: Some("text/javascript".to_string()),
            headers: vec![(
                "cache-control".to_string(),
                "public, max-age=31536000, immutable".to_string(),
            )],
            encodings: vec![
                AssetEncoding::Gzip.default_config(),
                AssetEncoding::Deflate.default_config(),
                AssetEncoding::Brotli.default_config(),
            ],
        }
    }

    #[fixture]
    fn css_config() -> AssetConfig {
        AssetConfig::Pattern {
            pattern: "**/*.css".to_string(),
            content_type: Some("text/css".to_string()),
            headers: vec![(
                "cache-control".to_string(),
                "public, max-age=31536000, immutable".to_string(),
            )],
            encodings: vec![
                AssetEncoding::Gzip.default_config(),
                AssetEncoding::Deflate.default_config(),
                AssetEncoding::Brotli.default_config(),
            ],
        }
    }

    #[fixture]
    fn not_found_html_config() -> AssetConfig {
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
            encodings: vec![
                AssetEncoding::Gzip.default_config(),
                AssetEncoding::Deflate.default_config(),
                AssetEncoding::Brotli.default_config(),
            ],
        }
    }

    #[fixture]
    fn old_url_redirect_config() -> AssetConfig {
        AssetConfig::Redirect {
            from: "/old-url".to_string(),
            to: "/".to_string(),
            kind: AssetRedirectKind::Permanent,
        }
    }

    #[fixture]
    fn css_redirect_config() -> AssetConfig {
        AssetConfig::Redirect {
            from: "/css/app.css".to_string(),
            to: "/css/app-ba74b708.css".to_string(),
            kind: AssetRedirectKind::Temporary,
        }
    }

    #[fixture]
    fn asset_router() -> AssetRouter<'static> {
        let mut asset_router = AssetRouter::default();

        let assets = vec![
            Asset::new("index.html", index_html_body()),
            Asset::new("index.html.gz", index_html_gz_body()),
            Asset::new("index.html.zz", index_html_zz_body()),
            Asset::new("index.html.br", index_html_br_body()),
            Asset::new("js/app-488df671.js", app_js_body()),
            Asset::new("js/app-488df671.js.gz", app_js_gz_body()),
            Asset::new("js/app-488df671.js.zz", app_js_zz_body()),
            Asset::new("js/app-488df671.js.br", app_js_br_body()),
            Asset::new("css/app-ba74b708.css", app_css_body()),
            Asset::new("not-found.html", not_found_html_body()),
            Asset::new("not-found.html.gz", not_found_html_gz_body()),
            Asset::new("not-found.html.zz", not_found_html_zz_body()),
            Asset::new("not-found.html.br", not_found_html_br_body()),
        ];

        let asset_configs = vec![
            index_html_config(),
            js_config(),
            css_config(),
            not_found_html_config(),
            old_url_redirect_config(),
            css_redirect_config(),
        ];

        asset_router.certify_assets(assets, asset_configs).unwrap();

        asset_router
    }

    fn build_response<'a>(
        body: Vec<u8>,
        cel_expr: String,
        headers: Vec<HeaderField>,
    ) -> HttpResponse<'a> {
        let combined_headers = headers
            .into_iter()
            .chain(vec![
                ("content-length".to_string(), body.len().to_string()),
                (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), cel_expr),
            ])
            .collect();

        HttpResponse::builder()
            .with_status_code(200)
            .with_body(body)
            .with_headers(combined_headers)
            .build()
    }
}
