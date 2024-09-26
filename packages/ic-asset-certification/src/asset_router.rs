use crate::{
    Asset, AssetCertificationError, AssetCertificationResult, AssetConfig, AssetEncoding,
    AssetFallbackConfig, AssetRedirectKind, NormalizedAssetConfig,
};
use ic_http_certification::{
    utils::add_v2_certificate_header, DefaultCelBuilder, DefaultResponseCertification, Hash,
    HttpCertification, HttpCertificationPath, HttpCertificationTree, HttpCertificationTreeEntry,
    HttpRequest, HttpResponse, CERTIFICATE_EXPRESSION_HEADER_NAME,
};
use regex::Regex;
use std::{borrow::Cow, cell::RefCell, cmp, collections::HashMap, rc::Rc};

#[derive(Debug, Clone)]
struct CertifiedAssetResponse<'a> {
    response: HttpResponse<'a>,
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
/// // this should normally be retrieved using `ic_cdk::api::data_certificate()`.
/// let data_certificate = vec![1, 2, 3];
/// let index_html_response = asset_router
///     .serve_asset(&data_certificate, &index_html_request)
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
    responses: HashMap<RequestKey, CertifiedAssetResponse<'content>>,
    fallback_responses: HashMap<RequestKey, CertifiedAssetResponse<'content>>,
}

/// A key created from request data, to retrieve the corresponding response.
#[derive(Debug, Eq, Hash, PartialEq)]
pub struct RequestKey {
    /// Path of the requested asset.
    pub path: String,
    /// The encoding of the asset.
    pub encoding: Option<String>,
    /// The beginning of the requested range (if any), counting from 0.
    pub range_begin: Option<usize>,
}

impl RequestKey {
    fn new(path: &str, encoding: Option<String>, range_begin: Option<usize>) -> Self {
        Self {
            path: path.to_string(),
            encoding,
            range_begin,
        }
    }
}

#[derive(Debug, PartialEq)]
struct RangeRequestValues {
    pub range_begin: usize,
    #[allow(unused)]
    pub range_end: Option<usize>,
}

const ASSET_CHUNK_SIZE: usize = 2_000_000;

fn encoding_str(maybe_encoding: Option<AssetEncoding>) -> Option<String> {
    maybe_encoding.map(|enc| enc.to_string())
}

fn parse_range_header_str(str_value: &str) -> Result<RangeRequestValues, String> {
    // expected format: `bytes <range-begin>-[<range-end>]`
    let re = Regex::new(r"bytes=(\d+)-(\d*)").expect("internal: wrong RE");
    let Some(caps) = re.captures(str_value) else {
        return Err("malformed Range header".to_string());
    };
    let range_begin: usize = caps
        .get(1)
        .ok_or_else(|| "missing range-begin".to_string())?
        .as_str()
        .parse()
        .map_err(|_| "malformed range-begin".to_string())?;
    let range_end: Option<usize> = caps.get(2).map(|v| v.as_str().parse().ok()).flatten();

    // TODO: add sanity checks for the parsed values
    Ok(RangeRequestValues {
        range_begin,
        range_end,
    })
}

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

    fn maybe_get_range_begin(request: &HttpRequest) -> AssetCertificationResult<Option<usize>> {
        if let Some(range_str) = Self::get_range_header(request) {
            parse_range_header_str(range_str)
                .map(|e| Some(e.range_begin))
                .map_err(AssetCertificationError::RequestError)
        } else {
            Ok(None)
        }
    }

    /// Returns the corresponding
    /// [HttpResponse](ic_http_certification::HttpResponse) for the provided
    /// [HttpRequest](ic_http_certification::HttpRequest) if it is found
    /// in the router.
    ///
    /// # Arguments
    ///
    /// * `data_certificate` - A byte slice representing the data certificate used for asset certification.
    ///     This should be retrieved using `ic_cdk::api::data_certificate()`.
    /// * `request` - A reference to an [HttpRequest](ic_http_certification::HttpRequest) object representing the incoming HTTP request.
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
        data_certificate: &[u8],
        request: &HttpRequest,
    ) -> AssetCertificationResult<HttpResponse<'content>> {
        let preferred_encodings = self.get_preferred_encodings(request);
        let request_url = request.get_path()?;
        let maybe_range_begin = Self::maybe_get_range_begin(request)?;
        let mut cert_response = self
            .get_asset_for_request(&request_url, preferred_encodings, maybe_range_begin)
            .cloned()?;
        let witness = self
            .tree
            .borrow()
            .witness(&cert_response.tree_entry, &request_url)?;
        let expr_path = cert_response.tree_entry.path.to_expr_path();
        add_v2_certificate_header(
            data_certificate,
            &mut cert_response.response,
            &witness,
            &expr_path,
        );
        Ok(cert_response.response.clone())
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

                    self.certify_asset_impl(encoded_asset, asset_config, Some(encoding))?;
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

                    self.delete_asset_impl(encoded_asset, asset_config, Some(encoding))?;
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

    fn get_asset_for_request<'a>(
        &self,
        req_path: &'a str,
        preferred_encodings: Vec<&'a str>,
        maybe_range_begin: Option<usize>,
    ) -> AssetCertificationResult<&CertifiedAssetResponse<'content>> {
        if let Some(response) = self.get_encoded_asset(&preferred_encodings, &req_path) {
            return Ok(response);
        }

        if let Some(response) =
            self.responses
                .get(&RequestKey::new(&req_path, None, maybe_range_begin))
        {
            if response.response.body().len() > ASSET_CHUNK_SIZE {
                if let Some(first_chunk_response) =
                    self.responses
                        .get(&RequestKey::new(&req_path, None, Some(0)))
                {
                    return Ok(first_chunk_response);
                }
            } else {
                return Ok(response);
            }
        }

        let mut url_scopes = req_path.split('/').collect::<Vec<_>>();
        url_scopes.pop();

        while !url_scopes.is_empty() {
            let mut scope = url_scopes.join("/");
            scope.push('/');

            if let Some(response) = self.get_encoded_fallback_asset(&preferred_encodings, &scope) {
                return Ok(response);
            }

            if let Some(response) = self
                .fallback_responses
                .get(&RequestKey::new(&scope, None, None))
            {
                return Ok(response);
            }

            scope.pop();

            if let Some(response) = self.get_encoded_fallback_asset(&preferred_encodings, &scope) {
                return Ok(response);
            }

            if let Some(response) = self
                .fallback_responses
                .get(&RequestKey::new(&scope, None, None))
            {
                return Ok(response);
            }

            url_scopes.pop();
        }
        Err(AssetCertificationError::NoAssetMatchingRequestUrl {
            request_url: req_path.to_string(),
        })
    }

    fn certify_asset_impl<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        asset_config: Option<&NormalizedAssetConfig>,
        encoding: Option<AssetEncoding>,
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
        encoding: Option<AssetEncoding>,
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
        encoding: Option<AssetEncoding>,
    ) -> AssetCertificationResult<()> {
        let asset_url = asset.url.to_string();
        let total_length = asset.content.len();

        if total_length > ASSET_CHUNK_SIZE {
            let mut range_begin = 0;
            while range_begin < asset.content.len() {
                let response = Self::prepare_static_asset(
                    asset.clone(),
                    content_type.clone(),
                    additional_headers.clone(),
                    encoding,
                    Some(range_begin),
                )?;
                self.responses.insert(
                    RequestKey::new(&asset_url, encoding_str(encoding), Some(range_begin)),
                    response,
                );
                range_begin += ASSET_CHUNK_SIZE;
            }
        }

        let response =
            Self::prepare_static_asset(asset, content_type, additional_headers, encoding, None)?;

        self.tree.borrow_mut().insert(&response.tree_entry);
        self.responses.insert(
            RequestKey::new(&asset_url, encoding_str(encoding), None),
            response,
        );
        Ok(())
    }

    fn delete_static_asset<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
        encoding: Option<AssetEncoding>,
    ) -> AssetCertificationResult<()> {
        let asset_url = asset.url.to_string();
        let response =
            Self::prepare_static_asset(asset, content_type, additional_headers, encoding, None)?;

        self.tree.borrow_mut().delete(&response.tree_entry);
        self.responses
            .remove(&RequestKey::new(&asset_url, encoding_str(encoding), None));

        if response.response.body().len() > ASSET_CHUNK_SIZE {
            // Delete also chunks.
            let mut range_begin: usize = 0;
            while range_begin < response.response.body().len() {
                self.responses.remove(&RequestKey::new(
                    &asset_url,
                    encoding_str(encoding),
                    Some(range_begin),
                ));
                range_begin += ASSET_CHUNK_SIZE;
            }
        }

        Ok(())
    }

    fn prepare_static_asset<'path>(
        asset: Asset<'content, 'path>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
        encoding: Option<AssetEncoding>,
        range_begin: Option<usize>,
    ) -> AssetCertificationResult<CertifiedAssetResponse<'content>> {
        let asset_url = asset.url.to_string();

        let (response, certification) = Self::prepare_asset_response_and_certification(
            asset,
            additional_headers,
            content_type,
            encoding,
            range_begin,
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
        encoding: Option<AssetEncoding>,
    ) -> AssetCertificationResult<()> {
        let response = Self::prepare_fallback_asset(
            asset,
            additional_headers,
            content_type,
            fallback_for.clone(),
            encoding,
        )?;

        self.tree.borrow_mut().insert(&response.tree_entry);
        self.fallback_responses.insert(
            RequestKey::new(&fallback_for.scope, encoding_str(encoding), None),
            response,
        );
        Ok(())
    }

    fn delete_fallback_asset<'path>(
        &mut self,
        asset: Asset<'content, 'path>,
        content_type: Option<String>,
        additional_headers: Vec<(String, String)>,
        fallback_for: AssetFallbackConfig,
        encoding: Option<AssetEncoding>,
    ) -> AssetCertificationResult<()> {
        let response = Self::prepare_fallback_asset(
            asset,
            additional_headers,
            content_type,
            fallback_for.clone(),
            encoding,
        )?;

        self.tree.borrow_mut().delete(&response.tree_entry);
        self.fallback_responses.remove(&RequestKey::new(
            &fallback_for.scope,
            encoding_str(encoding),
            None,
        ));
        Ok(())
    }

    fn prepare_fallback_asset<'path>(
        asset: Asset<'content, 'path>,
        additional_headers: Vec<(String, String)>,
        content_type: Option<String>,
        fallback_for: AssetFallbackConfig,
        encoding: Option<AssetEncoding>,
    ) -> AssetCertificationResult<CertifiedAssetResponse<'content>> {
        let (response, certification) = Self::prepare_asset_response_and_certification(
            asset,
            additional_headers,
            content_type,
            encoding,
            None,
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

        self.responses
            .insert(RequestKey::new(&from, None, None), response);

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
        self.responses.remove(&RequestKey::new(&from, None, None));

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
        encoding: Option<AssetEncoding>,
        range_begin: Option<usize>,
    ) -> AssetCertificationResult<(HttpResponse<'content>, HttpCertification)> {
        let mut content = asset.content;
        let mut status_code = 200;
        let mut headers = vec![];
        headers.extend(additional_headers);

        if let Some(content_type) = content_type {
            headers.push(("content-type".to_string(), content_type));
        }

        if let Some(encoding) = encoding {
            headers.push(("content-encoding".to_string(), encoding.to_string()));
        }

        if let Some(range_begin) = range_begin {
            let total_length = content.len();
            let range_end = cmp::min(range_begin + ASSET_CHUNK_SIZE, total_length) - 1;
            content = content[range_begin..(range_end + 1)].to_owned().into();
            status_code = 206;
            headers.push((
                http::header::CONTENT_RANGE.to_string(),
                format!("bytes {range_begin}-{range_end}/{total_length}"),
            ));
        };

        Self::prepare_response_and_certification(
            asset.url.to_string(),
            status_code,
            content,
            headers,
        )
    }

    fn prepare_response_and_certification(
        url: String,
        status_code: u16,
        body: Cow<'content, [u8]>,
        additional_headers: Vec<(String, String)>,
    ) -> AssetCertificationResult<(HttpResponse<'content>, HttpCertification)> {
        let mut headers = vec![("content-length".to_string(), body.len().to_string())];

        headers.extend(additional_headers);

        let cel_expr = DefaultCelBuilder::full_certification()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build();
        let cel_expr_str = cel_expr.to_string();
        headers.push((CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), cel_expr_str));

        let request = HttpRequest::get(url).build();

        let response = HttpResponse::builder()
            .with_status_code(status_code)
            .with_body(body)
            .with_headers(headers)
            .build();

        let certification = HttpCertification::full(&cel_expr, &request, &response, None)?;

        Ok((response, certification))
    }

    fn get_encoded_asset(
        &self,
        preferred_encodings: &[&str],
        url: &str,
    ) -> Option<&CertifiedAssetResponse<'content>> {
        for encoding in preferred_encodings {
            if let Some(response) =
                self.responses
                    .get(&RequestKey::new(url, Some(encoding.to_string()), None))
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
            if let Some(response) = self.fallback_responses.get(&RequestKey::new(
                scope,
                Some(encoding.to_string()),
                None,
            )) {
                return Some(response);
            }
        }

        None
    }

    fn get_range_header<'a>(request: &'a HttpRequest) -> Option<&'a str> {
        for (name, value) in request.headers().iter() {
            if name.to_lowercase().eq(&http::header::RANGE.as_str()) {
                return Some(value);
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
    use assert_matches::assert_matches;
    use ic_certification::{hash_tree::SubtreeLookupResult, HashTree};
    use ic_http_certification::{
        cel::DefaultFullCelExpressionBuilder, HeaderField, CERTIFICATE_HEADER_NAME,
    };
    use ic_response_verification::CertificateHeader;
    use ic_response_verification_test_utils::{base64_decode, hash};
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;
    use rstest::*;
    use std::vec;

    const ONE_CHUNK_ASSET_LEN: usize = ASSET_CHUNK_SIZE;
    const TWO_CHUNKS_ASSET_LEN: usize = ASSET_CHUNK_SIZE + 1;
    const SIX_CHUNKS_ASSET_LEN: usize = 5 * ASSET_CHUNK_SIZE + 12;
    const TEN_CHUNKS_ASSET_LEN: usize = 10 * ASSET_CHUNK_SIZE;

    const ONE_CHUNK_ASSET_NAME: &str = "long_asset_one_chunk";
    const TWO_CHUNKS_ASSET_NAME: &str = "long_asset_two_chunks";
    const SIX_CHUNKS_ASSET_NAME: &str = "long_asset_six_chunks";
    const TEN_CHUNKS_ASSET_NAME: &str = "long_asset_ten_chunks";

    #[rstest]
    #[case(0, None)]
    #[case(ASSET_CHUNK_SIZE, None)]
    #[case(ASSET_CHUNK_SIZE*4, None)]
    #[case(0, Some(0))]
    #[case(100, Some(2000))]
    #[case(10_000, Some(300_000))]
    #[case(ASSET_CHUNK_SIZE, Some(2 * ASSET_CHUNK_SIZE - 1))]
    fn should_parse_range_header_str(#[case] range_begin: usize, #[case] range_end: Option<usize>) {
        let input = if let Some(range_end) = range_end {
            format!("bytes={}-{}", range_begin, range_end)
        } else {
            format!("bytes={}-", range_begin)
        };
        let result = parse_range_header_str(&input);
        let output = result.unwrap_or_else(|_| panic!("failed parsing '{input}'"));
        assert_eq!(
            RangeRequestValues {
                range_begin,
                range_end
            },
            output
        );
    }

    #[rstest]
    #[case("byte 1-2/3")]
    #[case("bites 2-4")]
    #[case("bytes 100-end")]
    #[case("bytes 12345")]
    #[case("something else")]
    #[case("bytes dead-beef")]
    fn should_fail_parse_range_header_str_on_malformed_input(#[case] malformed_input: &str) {
        let result = parse_range_header_str(malformed_input);
        assert_matches!(result, Err(e) if e.to_string().contains("malformed Range header"));
    }

    #[rstest]
    #[case("/")]
    #[case("https://internetcomputer.org/")]
    fn test_index_html(mut asset_router: AssetRouter, #[case] req_url: &str) {
        let request = HttpRequest::get(req_url).build();

        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "", "<$>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

        asset_router
            .delete_assets(
                vec![Asset::new("index.html", index_html_body())],
                vec![index_html_config()],
            )
            .unwrap();

        let result = asset_router.serve_asset(&data_certificate(), &request);
        assert!(matches!(
            result,
            Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                request_url,
             }) if request_url == request.get_path().unwrap()
        ));
    }

    #[rstest]
    #[case(TWO_CHUNKS_ASSET_NAME)]
    #[case(SIX_CHUNKS_ASSET_NAME)]
    #[case(TEN_CHUNKS_ASSET_NAME)]
    fn test_long_asset_served_in_chunks(long_asset_router: AssetRouter, #[case] asset_name: &str) {
        let req_url = format!("/{asset_name}");
        let asset_body = long_asset_body(asset_name);
        let asset_len = asset_body.len();
        // Request the entire asset, should obtain the first chunk.
        let request = HttpRequest::get(&req_url).build();
        let mut expected_response = build_206_response(
            asset_body[0..ASSET_CHUNK_SIZE].to_vec(),
            asset_cel_expr(),
            vec![
                (
                    "cache-control".to_string(),
                    "public, no-cache, no-store".to_string(),
                ),
                ("content-type".to_string(), "text/html".to_string()),
                (
                    "content-range".to_string(),
                    format!("bytes 0-{}/{}", ASSET_CHUNK_SIZE - 1, asset_len),
                ),
            ],
        );

        let response = long_asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", &req_url[1..], "<$>"]);
        assert_matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        );
        assert_eq!(response, expected_response);

        // Request the subsequent chunks, should obtain them.
        let expected_number_of_chunks =
            (asset_len as f32 / ASSET_CHUNK_SIZE as f32).ceil() as usize;
        let mut asset_len_so_far = response.body().len();
        let mut number_of_chunks_so_far = 1;
        while asset_len_so_far < asset_len {
            let chunk_request = HttpRequest::get(&req_url)
                .with_headers(vec![(
                    "range".to_string(),
                    format!("bytes={}-", asset_len_so_far),
                )])
                .build();
            let expected_range_end = cmp::min(asset_len_so_far + ASSET_CHUNK_SIZE, asset_len) - 1;
            let mut expected_response = build_206_response(
                asset_body[asset_len_so_far..=expected_range_end].to_vec(),
                asset_cel_expr(),
                vec![
                    (
                        "cache-control".to_string(),
                        "public, no-cache, no-store".to_string(),
                    ),
                    ("content-type".to_string(), "text/html".to_string()),
                    (
                        "content-range".to_string(),
                        format!(
                            "bytes {}-{}/{}",
                            asset_len_so_far, expected_range_end, asset_len
                        ),
                    ),
                ],
            );
            let response = long_asset_router
                .serve_asset(&data_certificate(), &chunk_request)
                .unwrap();
            let (witness, expr_path) = extract_witness_expr_path(&response);
            assert_matches!(
                witness.lookup_subtree(&expr_path),
                SubtreeLookupResult::Found(_)
            );
            add_v2_certificate_header(
                &data_certificate(),
                &mut expected_response,
                &witness,
                &expr_path,
            );
            assert_eq!(response, expected_response);
            asset_len_so_far += response.body().len();
            number_of_chunks_so_far += 1;
        }
        assert_eq!(number_of_chunks_so_far, expected_number_of_chunks)
    }

    #[rstest]
    #[case(TWO_CHUNKS_ASSET_NAME)]
    #[case(SIX_CHUNKS_ASSET_NAME)]
    #[case(TEN_CHUNKS_ASSET_NAME)]
    fn test_long_asset_deletion_removes_chunks(
        mut long_asset_router: AssetRouter,
        #[case] asset_name: &str,
    ) {
        let req_url = format!("/{asset_name}");
        let asset_body = long_asset_body(asset_name);
        let asset_len = asset_body.len();
        let mut all_requests = vec![];
        // Request the entire asset and the chunks, all should succeed.
        // First the asset...
        let request = HttpRequest::get(&req_url).build();
        let response = long_asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);

        assert_eq!(expr_path, vec!["http_expr", &req_url[1..], "<$>"]);
        assert_matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        );
        assert_eq!(response.status_code(), 206);
        all_requests.push(request);

        // ... then the subsequent chunks.
        let expected_number_of_chunks =
            (asset_len as f32 / ASSET_CHUNK_SIZE as f32).ceil() as usize;
        let mut asset_len_so_far = response.body().len();
        let mut number_of_chunks_so_far = 1;
        while asset_len_so_far < asset_len {
            let chunk_request = HttpRequest::get(&req_url)
                .with_headers(vec![(
                    "range".to_string(),
                    format!("bytes={}-", asset_len_so_far),
                )])
                .build();
            let response = long_asset_router
                .serve_asset(&data_certificate(), &chunk_request)
                .unwrap();
            let (witness, expr_path) = extract_witness_expr_path(&response);
            assert_matches!(
                witness.lookup_subtree(&expr_path),
                SubtreeLookupResult::Found(_)
            );
            assert_eq!(response.status_code(), 206);
            asset_len_so_far += response.body().len();
            number_of_chunks_so_far += 1;
            all_requests.push(chunk_request);
        }
        assert_eq!(number_of_chunks_so_far, expected_number_of_chunks);
        assert_eq!(all_requests.len(), expected_number_of_chunks);

        // Delete the asset.
        long_asset_router
            .delete_assets(
                vec![Asset::new(&req_url, asset_body)],
                vec![long_asset_config(asset_name)],
            )
            .expect("Asset deletion failed");

        // Re-request the asset and the chunks, all should fail.
        for request in all_requests {
            let result = long_asset_router.serve_asset(&data_certificate(), &request);
            assert_matches!(
                result,
                Err(AssetCertificationError::NoAssetMatchingRequestUrl {
                    request_url,
                 }) if request_url == request.get_path().unwrap()
            );
        }
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
        let mut expected_response = build_200_response(
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
        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(
            expr_path,
            HttpCertificationPath::exact(req_url).to_expr_path()
        );
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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

        let result = asset_router.serve_asset(&data_certificate(), &request);
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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

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
        assert_eq!(response, expected_response);

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

        let result = asset_router.serve_asset(&data_certificate(), &request);
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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

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

        let result = asset_router.serve_asset(&data_certificate(), &request);
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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

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

        let result = asset_router.serve_asset(&data_certificate(), &request);
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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(
            expr_path,
            vec!["http_expr", "css", "app-ba74b708.css", "<$>"]
        );
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

        asset_router
            .delete_assets(
                vec![Asset::new("css/app-ba74b708.css", app_css_body())],
                vec![css_config()],
            )
            .unwrap();
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "css", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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

        let result = asset_router.serve_asset(&data_certificate(), &request);
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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "css", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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

        let result = asset_router.serve_asset(&data_certificate(), &request);
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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "js", "app-488df671.js", "<$>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "js", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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

        let result = asset_router.serve_asset(&data_certificate(), &request);
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

        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "js", "app-488df671.js", "<$>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "js", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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

        let result = asset_router.serve_asset(&data_certificate(), &request);
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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "js", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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

        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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

        let result = asset_router.serve_asset(&data_certificate(), &request);
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
        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(
            expr_path,
            HttpCertificationPath::exact(request.get_path().unwrap()).to_expr_path()
        );
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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

        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

        assert_eq!(expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            witness.lookup_subtree(&expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(response, expected_response);

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

        let result = asset_router.serve_asset(&data_certificate(), &request);
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

        let mut expected_css_response = HttpResponse::builder()
            .with_status_code(307)
            .with_headers(vec![
                ("content-length".to_string(), "0".to_string()),
                ("location".to_string(), "/css/app-ba74b708.css".to_string()),
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(),
                    cel_expr.clone(),
                ),
            ])
            .build();
        let mut expected_old_url_response = HttpResponse::builder()
            .with_status_code(301)
            .with_headers(vec![
                ("content-length".to_string(), "0".to_string()),
                ("location".to_string(), "/".to_string()),
                (CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), cel_expr),
            ])
            .build();

        let css_response = asset_router
            .serve_asset(&data_certificate(), &css_request)
            .unwrap();
        let (css_witness, css_expr_path) = extract_witness_expr_path(&css_response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_css_response,
            &css_witness,
            &css_expr_path,
        );
        let old_url_response = asset_router
            .serve_asset(&data_certificate(), &old_url_request)
            .unwrap();
        let (old_url_witness, old_url_expr_path) = extract_witness_expr_path(&old_url_response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_old_url_response,
            &old_url_witness,
            &old_url_expr_path,
        );

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

        asset_router
            .delete_assets(
                vec![],
                vec![old_url_redirect_config(), css_redirect_config()],
            )
            .unwrap();
        let mut expected_css_response = build_200_response(
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
        let mut expected_old_url_response = build_200_response(
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

        let css_response = asset_router
            .serve_asset(&data_certificate(), &css_request)
            .unwrap();
        let (css_witness, css_expr_path) = extract_witness_expr_path(&css_response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_css_response,
            &css_witness,
            &css_expr_path,
        );
        let old_url_response = asset_router
            .serve_asset(&data_certificate(), &old_url_request)
            .unwrap();
        let (old_url_witness, old_url_expr_path) = extract_witness_expr_path(&old_url_response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_old_url_response,
            &old_url_witness,
            &old_url_expr_path,
        );

        assert_eq!(css_expr_path, vec!["http_expr", "css", "<*>"]);
        assert!(matches!(
            css_witness.lookup_subtree(&css_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(css_response, expected_css_response);

        assert_eq!(old_url_expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            old_url_witness.lookup_subtree(&old_url_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(old_url_response, expected_old_url_response);

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
        let mut expected_css_response = build_200_response(
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
        let mut expected_old_url_response = build_200_response(
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

        let css_response = asset_router
            .serve_asset(&data_certificate(), &css_request)
            .unwrap();
        let (css_witness, css_expr_path) = extract_witness_expr_path(&css_response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_css_response,
            &css_witness,
            &css_expr_path,
        );
        let old_url_response = asset_router
            .serve_asset(&data_certificate(), &old_url_request)
            .unwrap();
        let (old_url_witness, old_url_expr_path) = extract_witness_expr_path(&old_url_response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_old_url_response,
            &old_url_witness,
            &old_url_expr_path,
        );

        assert_eq!(css_expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            css_witness.lookup_subtree(&css_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(css_response, expected_css_response);

        assert_eq!(old_url_expr_path, vec!["http_expr", "", "<*>"]);
        assert!(matches!(
            old_url_witness.lookup_subtree(&old_url_expr_path),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(old_url_response, expected_old_url_response);

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

        let css_result = asset_router.serve_asset(&data_certificate(), &css_request);
        let old_url_result = asset_router.serve_asset(&data_certificate(), &old_url_request);

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

        let mut expected_response = build_200_response(
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

        let response = asset_router
            .serve_asset(&data_certificate(), &request)
            .unwrap();
        let (witness, expr_path) = extract_witness_expr_path(&response);
        add_v2_certificate_header(
            &data_certificate(),
            &mut expected_response,
            &witness,
            &expr_path,
        );

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

    fn long_asset_body(asset_name: &str) -> Vec<u8> {
        let asset_length = match asset_name {
            ONE_CHUNK_ASSET_NAME => ONE_CHUNK_ASSET_LEN,
            TWO_CHUNKS_ASSET_NAME => TWO_CHUNKS_ASSET_LEN,
            SIX_CHUNKS_ASSET_NAME => SIX_CHUNKS_ASSET_LEN,
            TEN_CHUNKS_ASSET_NAME => TEN_CHUNKS_ASSET_LEN,
            _ => ASSET_CHUNK_SIZE * 2 + 1,
        };
        let mut rng = ChaCha20Rng::from_seed(hash(asset_name));
        let mut body = vec![0u8; asset_length];
        rng.fill_bytes(&mut body);
        body
    }

    // Gzip compressed version of `index_html_body`,
    // compressed using https://www.zickty.com/texttogzip/,
    // and then converted to bytes using https://conv.darkbyte.ru/.
    #[fixture]
    fn index_html_gz_body() -> Vec<u8> {
        vec![
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 179, 201, 40, 201, 205, 177, 179, 73, 202, 79, 169,
            180, 179, 201, 48, 180, 243, 72, 205, 201, 201, 87, 8, 207, 47, 202, 73, 81, 180, 209,
            7, 10, 216, 232, 67, 228, 244, 193, 10, 1, 28, 178, 8, 152, 47, 0, 0, 0,
        ]
    }

    // Deflate compressed version of `index_html_body`,
    // compressed using https://www.zickty.com/texttogzip/,
    // and then converted to bytes using https://conv.darkbyte.ru/.
    #[fixture]
    fn index_html_zz_body() -> Vec<u8> {
        vec![
            78, 9, 3, 9, 28, 9, 1, 3, 49, 4, 9, 4, 3, 9, 30, 4, 3, 48, 9, 9, 57, 8, 2, 49, 51, 4,
            1, 7, 0, 8, 8, 43, 4, 4, 1, 0, 1, 7, 8, 0, 9,
        ]
    }

    // Deflate compressed version of `index_html_body`,
    // compressed using https://facia.dev/tools/compress-decompress/brotli-compress/,
    // and then converted to bytes using https://conv.darkbyte.ru/.
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

    // Gzip compressed version of `app_js_body`,
    // compressed using https://www.zickty.com/texttogzip/,
    // and then converted to bytes using https://conv.darkbyte.ru/.
    #[fixture]
    fn app_js_gz_body() -> Vec<u8> {
        vec![
            31, 139, 8, 0, 0, 0, 0, 0, 0, 3, 75, 206, 207, 43, 206, 207, 73, 213, 203, 201, 79,
            215, 80, 247, 72, 205, 201, 201, 87, 8, 207, 47, 202, 73, 81, 84, 215, 180, 6, 0, 186,
            42, 111, 142, 28, 0, 0, 0,
        ]
    }

    // Deflate compressed version of `app_js_body`,
    // compressed using https://www.zickty.com/texttogzip/,
    // and then converted to bytes using https://conv.darkbyte.ru/.
    #[fixture]
    fn app_js_zz_body() -> Vec<u8> {
        vec![
            120, 156, 75, 206, 207, 43, 206, 207, 73, 213, 203, 201, 79, 215, 80, 247, 72, 205,
            201, 201, 87, 8, 207, 47, 202, 73, 81, 84, 215, 180, 6, 0, 148, 149, 9, 123,
        ]
    }

    // Brotli compressed version of `app_js_body`,
    // compressed using https://facia.dev/tools/compress-decompress/brotli-compress/,
    // and then converted to bytes using https://conv.darkbyte.ru/.
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

    // Gzip compressed version of `not_found_html_body`,
    // compressed using https://www.zickty.com/texttogzip/,
    // and then converted to bytes using https://conv.darkbyte.ru/.
    #[fixture]
    fn not_found_html_gz_body() -> Vec<u8> {
        vec![
            49, 19, 9, 8, 0, 0, 0, 0, 0, 0, 3, 23, 9, 32, 1, 64, 32, 1, 32, 5, 23, 7, 23, 9, 115,
            32, 2, 121, 22, 9, 24, 0, 23, 9, 32, 1, 72, 24, 0, 81, 73, 72, 129, 36, 0, 32, 3, 71,
            129, 17, 2, 32, 3, 71, 32, 5, 117, 129, 24, 0, 32, 9, 7, 16, 33, 7, 35, 2, 103, 16, 0,
            36, 5, 25, 3, 116, 1, 37, 4, 36, 9, 17, 0, 114, 73, 0, 0, 0,
        ]
    }

    // Deflate compressed version of `not_found_html_body`,
    // compressed using https://www.zickty.com/texttogzip/,
    // and then converted to bytes using https://conv.darkbyte.ru/.
    #[fixture]
    fn not_found_html_zz_body() -> Vec<u8> {
        vec![
            120, 156, 179, 201, 40, 201, 205, 177, 179, 73, 202, 79, 169, 180, 179, 201, 48, 180,
            51, 49, 48, 81, 240, 203, 47, 81, 112, 203, 47, 205, 75, 81, 180, 209, 7, 10, 217, 232,
            67, 100, 245, 193, 74, 1, 133, 210, 15, 136,
        ]
    }

    // Brotli compressed version of `not_found_html_body`,
    // compressed using https://facia.dev/tools/compress-decompress/brotli-compress/,
    // and then converted to bytes using https://conv.darkbyte.ru/.
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

    fn long_asset_config(path: &str) -> AssetConfig {
        AssetConfig::File {
            path: path.to_string(),
            content_type: Some("text/html".to_string()),
            headers: vec![(
                "cache-control".to_string(),
                "public, no-cache, no-store".to_string(),
            )],
            fallback_for: vec![],
            aliased_by: vec![],
            encodings: vec![],
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

    fn long_asset(name: &str) -> Asset {
        Asset::new(name, long_asset_body(name))
    }

    #[fixture]
    fn long_asset_router() -> AssetRouter<'static> {
        let mut asset_router = AssetRouter::default();
        let mut assets = vec![];
        let mut asset_configs = vec![];

        for name in vec![
            ONE_CHUNK_ASSET_NAME,
            TWO_CHUNKS_ASSET_NAME,
            SIX_CHUNKS_ASSET_NAME,
            TEN_CHUNKS_ASSET_NAME,
        ] {
            assets.push(long_asset(name));
            asset_configs.push(long_asset_config(name));
        }
        asset_router.certify_assets(assets, asset_configs).unwrap();
        asset_router
    }

    fn build_200_response<'a>(
        body: Vec<u8>,
        cel_expr: String,
        headers: Vec<HeaderField>,
    ) -> HttpResponse<'a> {
        build_response(200, body, cel_expr, headers)
    }

    fn build_206_response<'a>(
        body: Vec<u8>,
        cel_expr: String,
        headers: Vec<HeaderField>,
    ) -> HttpResponse<'a> {
        build_response(206, body, cel_expr, headers)
    }

    // A certificate taken from a real response on mainnet. It doesn't matter what it contains,
    // as long as it's a valid certificate. If we ever decide to run response verification in these
    // tests then the content of the certificate will matter.
    #[fixture]
    fn data_certificate() -> Vec<u8> {
        base64_decode("2dn3o2R0cmVlgwGDAYMBggRYIKZa+jjiJCKIY6ieu3PP5Vz5wLXmyPh1bDmIzXg5dl6LgwJIY2FuaXN0ZXKDAYMBggRYIM/g0MyVpl3VttUo8bFaIM3krNFLeWDQlazn4vVmbs12gwGDAYMBgwGDAYIEWCCrjGIsFv7RroK/KT/vV4dT/8o6c6Q8uFH3A372mLl7I4MBggRYIIILxwOzUO8JeUy1GuQk1oRnBKc7mlApt5csrszervQDgwGDAYIEWCBlMbtdoKygLVFQVorKucJVgVLHtLscN5S8BBykjfmQ+4MBgwGCBFgg680ttF9A023RfxGHUK7ceDdxxyHb6Cbg4qjinLrq+6mDAYIEWCCURcqsdMxTygYlQwS+KseXWp9QWrCCtb446pyKsj3lOoMCSgAAAAABgAmUAQGDAYMBgwJOY2VydGlmaWVkX2RhdGGCA1ggk/T8pnqZAQeSmaKDG8U/GSSBWQTEZfior9A2Wo/FZTSCBFgggt6vD1DPdgxNs+gKICbk3nRcQI5Tkp5syXYnM9GFJmCCBFggP4ZGeJfdyQHomGieqWx6e2QVSVgmctlGDoHCTcTrXWOCBFggILD+6U1L9j+vw02XY6JkB17xt0k6Esl/mcWDSifUPGyCBFggmUXnX4i82sN5AJqyUuIq4i9ErZ47rVK637kTCrOT7eSCBFggNqmXjq9JIe/CbAZW3wpfG12ofFrV8a7+tL5SL0tQ5ymCBFggFI5GZ/bYvjr0BzJiwPwH1yI7Rmd6jam1yj81cX8EqCWCBFggHHprIPk9m3zr3vFaSCA2JJiHSbLLfHzd+a0Rs90Ay7eCBFgg/5TQFWqdhgGiUF6Vy8qFpoKghCMgdXuYrc6pm7nSdpSCBFggzWD0/+Mf+jkRU4F1Xegk5vpPLOuDIfmneS92N03AdpyCBFggtNKNmO74J7jAsbkLgC5DQTEvIelYUdINiDtCOwUPLOWDAYIEWCC8BmcZ/cRsbnrLwEIfk310vWtBYg1iZAh9uLo+rxEtQYMCRHRpbWWCA0nZ/7r03qCj+hdpc2lnbmF0dXJlWDCU4tWKn7kUwxBiXeWihdpAEsfRN8YXvlz8/U7/NzTeb9t3mIdUlyj+YcQVEu9nxBdqZGVsZWdhdGlvbqJpc3VibmV0X2lkWB0QtkczSlQGmHeWsvi2sUzTLwh20/1PyEUhBYMlAmtjZXJ0aWZpY2F0ZVkCfdnZ96JkdHJlZYMBggRYIEe+kyDbAopvNlKUKa90j7vq/mnGs3p+1NUR03ZZjauCgwGDAYIEWCDSkWhnwtRPFDffqILBSu0cTmpQgjY9a5IEFfY8yKUxfIMCRnN1Ym5ldIMBgwGDAYMBgwGCBFgg0dOP/K78SbZBfvb185tLrkYoD1X09di+aBvUgAg+iJeDAYMCWB0QtkczSlQGmHeWsvi2sUzTLwh20/1PyEUhBYMlAoMBgwJPY2FuaXN0ZXJfcmFuZ2VzggNYG9nZ94GCSgAAAAABgAAAAQFKAAAAAAGP//8BAYMCSnB1YmxpY19rZXmCA1iFMIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAKkibyL1MUdfYEy6XJin1b3PH7O2dsscd7G1feb0chACzBZOV+iXsL2AkjXe5cpqmwj6EZ3voSNz0aXeskewXOtFE4acjAp8pqDHx5EzUer76iqMIwraljfu94OFUhGBZIIEWCDGWnxJxMbpfrLKS1SIeWornghRMHDsKLoA4Ht6k/jqo4IEWCC8jzyQpYOJ/fqhwEmB2toxxu/hn7B9fcDMuS1/S/bYA4IEWCCI/qDbafOPnPP7qI+KBA88rcmud3L6GkBqbqRk+oWLnoIEWCBpYe8TfCruCwRnCC7208EsA+kwE7YCpMtiFCcOSEhj8YIEWCCbMGsgdP3vD+1UB+zEnG32tlisH7P9tl/aAiIVQIKEM4MCRHRpbWWCA0nEoN6ai4me+hdpc2lnbmF0dXJlWDCxK5IGNwccdX4Xs5HPctDb3AjfHV2QPScDneQJ7VFFOVN1+47TiJCYsFDPVSkKXVs=")
    }

    fn build_response<'a>(
        status_code: u16,
        body: Vec<u8>,
        cel_expr: String,
        headers: Vec<HeaderField>,
    ) -> HttpResponse<'a> {
        let combined_headers = headers
            .into_iter()
            .chain(vec![
                ("content-length".to_string(), body.len().to_string()),
                (CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(), cel_expr),
            ])
            .collect();

        HttpResponse::builder()
            .with_status_code(status_code)
            .with_body(body)
            .with_headers(combined_headers)
            .build()
    }

    fn extract_witness_expr_path(response: &HttpResponse) -> (HashTree, Vec<String>) {
        let (_, certificate_header_str) = response
            .headers()
            .iter()
            .find(|(name, _)| name.to_lowercase() == CERTIFICATE_HEADER_NAME.to_lowercase())
            .unwrap();

        let certificate_header = CertificateHeader::from(certificate_header_str).unwrap();
        (
            certificate_header.tree,
            certificate_header.expr_path.unwrap(),
        )
    }
}
