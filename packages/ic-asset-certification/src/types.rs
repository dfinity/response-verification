use ic_http_certification::{HttpCertificationTreeEntry, HttpResponse};

#[derive(Debug, Clone)]
pub(crate) struct CertifiedAssetResponse<'a> {
    pub(crate) response: HttpResponse<'a>,
    pub(crate) tree_entry: HttpCertificationTreeEntry<'a>,
}

/// A key created from request data, to retrieve the corresponding response.
#[derive(Debug, Eq, Hash, PartialEq, Clone)]
pub(crate) struct RequestKey {
    /// Path of the requested asset.
    pub(crate) path: String,
    /// The encoding of the asset.
    pub(crate) encoding: Option<String>,
    /// The beginning of the requested range (if any), counting from 0.
    pub(crate) range_begin: Option<usize>,
}

impl RequestKey {
    pub(crate) fn new(
        path: impl Into<String>,
        encoding: Option<String>,
        range_begin: Option<usize>,
    ) -> Self {
        Self {
            path: path.into(),
            encoding,
            range_begin,
        }
    }
}
