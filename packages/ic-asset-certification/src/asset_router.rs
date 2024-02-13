use crate::{Asset, AssetCertificationResult, AssetConfig, AssetFallbackConfig, AssetResponse};
use ic_certification::HashTree;
use ic_http_certification::{
    DefaultCelBuilder, DefaultResponseCertification, HttpCertification, HttpCertificationPath,
    HttpCertificationTree, HttpCertificationTreeEntry, HttpRequest, HttpResponse,
};
use std::{borrow::Cow, collections::HashMap};

#[derive(Debug, Clone)]
pub struct CertifiedAssetResponse<'a> {
    response: AssetResponse<'a>,
    tree_entry: HttpCertificationTreeEntry<'a>,
}

#[derive(Debug)]
pub struct AssetRouter<'a> {
    pub responses: HashMap<String, CertifiedAssetResponse<'a>>,
    pub fallback_responses: HashMap<String, CertifiedAssetResponse<'a>>,
}

const IC_CERTIFICATE_EXPRESSION_HEADER: &str = "IC-CertificateExpression";

impl<'a> AssetRouter<'a> {
    pub fn new() -> Self {
        AssetRouter {
            responses: HashMap::new(),
            fallback_responses: HashMap::new(),
        }
    }

    pub fn serve_asset(
        &self,
        http_certification_tree: &HttpCertificationTree,
        request: &HttpRequest,
    ) -> Option<(HttpResponse, HashTree, Vec<String>)> {
        if let Some(CertifiedAssetResponse {
            response,
            tree_entry,
        }) = self.responses.get(&request.url)
        {
            let witness = http_certification_tree.witness(tree_entry, &request.url);
            let expr_path = tree_entry.path.to_expr_path();

            return Some((response.clone().into(), witness, expr_path));
        }

        let mut url_scopes = request.url.split('/').collect::<Vec<_>>();

        while url_scopes.len() > 0 {
            let scope = url_scopes.join("/");

            if let Some(CertifiedAssetResponse {
                response,
                tree_entry,
            }) = self.fallback_responses.get(&scope)
            {
                let witness = http_certification_tree.witness(tree_entry, &scope);
                let expr_path = tree_entry.path.to_expr_path();

                return Some((response.clone().into(), witness, expr_path));
            }

            url_scopes.pop();
        }

        None
    }

    pub fn certify_assets(
        &mut self,
        http_certification_tree: &mut HttpCertificationTree,
        assets: impl IntoIterator<Item = Asset<'a>>,
        asset_configs: impl IntoIterator<Item = AssetConfig>,
    ) -> AssetCertificationResult<()> {
        let asset_configs: Vec<_> = asset_configs.into_iter().collect();

        for asset in assets {
            let asset_config = asset_configs.iter().find(|e| e.matches_asset(&asset));

            match asset_config {
                Some(AssetConfig::Pattern {
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
                Some(AssetConfig::File {
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
        let asset_url = asset.url().to_string();
        let (response, certification) =
            Self::prepare_response_and_certification(asset, additional_headers, content_type)?;

        let tree_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::Exact(Cow::Owned(asset_url.clone())),
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
            HttpCertificationPath::Wildcard(Cow::Owned(fallback_for.scope.clone())),
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
    ) -> AssetCertificationResult<(AssetResponse, HttpCertification)> {
        let mut headers = vec![];

        headers.extend(additional_headers);

        if let Some(content_type) = content_type {
            headers.push(("content-type".to_string(), content_type));
        }

        let header_keys = headers
            .clone()
            .into_iter()
            .map(|(key, _value)| key)
            .collect::<Vec<_>>();
        let header_keys = header_keys.iter().map(|e| e.as_str()).collect::<Vec<_>>();

        let cel_expr = DefaultCelBuilder::full_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                &header_keys,
            ))
            .build();
        let cel_expr_str = cel_expr.to_string();
        headers.push((IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), cel_expr_str));

        let response = AssetResponse::new(200, asset.content.clone(), headers);

        let http_response: HttpResponse = response.clone().into();

        let request = HttpRequest {
            method: "GET".to_string(),
            url: asset.url().to_string(),
            headers: vec![],
            body: vec![],
        };

        let certification = HttpCertification::full(&cel_expr, &request, &http_response, None)?;

        Ok((response, certification))
    }
}

#[cfg(test)]
mod tests {
    use crate::AssetFallbackConfig;

    use super::*;
    use rstest::*;

    #[rstest]
    fn test_asset_router() {
        let mut asset_router = AssetRouter::new();
        let mut http_certification_tree = HttpCertificationTree::default();

        let assets = vec![
            Asset::new(
                "index.html",
                b"<html><body><h1>Hello World!</h1></body></html>".as_slice(),
            ),
            Asset::new(
                "app-488df671.js",
                b"console.log('Hello World!');".as_slice(),
            ),
            Asset::new(
                "app-ba74b708.css",
                b"html,body{min-height:100vh;}".as_slice(),
            ),
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
    }
}
