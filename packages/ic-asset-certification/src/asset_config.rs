use crate::Asset;

#[derive(Debug, Clone)]
pub enum AssetConfig {
    File {
        path: String,
        content_type: Option<String>,
        headers: Vec<(String, String)>,
        fallback_for: Option<AssetFallbackConfig>,
    },
    Pattern {
        pattern: String,
        content_type: Option<String>,
        headers: Vec<(String, String)>,
    },
}

#[derive(Debug, Clone)]
pub struct AssetFallbackConfig {
    pub scope: String,
}

impl AssetConfig {
    pub(crate) fn matches_asset<'a>(&self, asset: &'a Asset<'a>) -> bool {
        match self {
            Self::File { path, .. } => path == asset.path(),
            Self::Pattern { pattern, .. } => asset.matches(pattern),
        }
    }
}
