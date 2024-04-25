/// Asset certification result type.
pub type AssetCertificationResult<T = ()> = Result<T, AssetCertificationError>;

/// Asset certification error type.
#[derive(thiserror::Error, Debug)]
pub enum AssetCertificationError {
    /// Thrown when a suitable asset cannot be found for a given request url.
    #[error(r#"No asset was found matching the current request url: {request_url}"#)]
    NoAssetMatchingRequestUrl {
        /// The request url that was not matched to any asset.
        request_url: String,
    },

    /// Thrown when the asset certification process fails.
    #[error(r#"HTTP Certification Error: "{0}""#)]
    HttpCertificationError(#[from] ic_http_certification::HttpCertificationError),

    /// Thrown when glob pattern parsing fails.
    #[error(r#"Glob error: {0}"#)]
    GlobsetError(#[from] globset::Error),
}
