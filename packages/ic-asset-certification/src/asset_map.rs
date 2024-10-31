use crate::{AssetEncoding, CertifiedAssetResponse, RequestKey};
use ic_http_certification::HttpResponse;
use std::collections::{hash_map::Iter, HashMap};

/// A map of assets, indexed by path, encoding, and the starting range.
pub trait AssetMap<'content> {
    /// Get an asset by path, encoding, and starting range.
    ///
    /// For standard assets, the path refers to the asset's path, e.g. `/index.html`.
    ///
    /// For fallback assets, the path refers to the scope that the fallback is valid for, e.g. `/`.
    /// See the [fallback_for](crate::AssetConfig::File::fallback_for) config option for more information
    /// on fallback scopes.
    ///
    /// For all types of assets, the encoding refers to the encoding of the asset, see [AssetEncoding].
    ///
    /// Assets greater than 2mb are split into multiple ranges, the starting range allows retrieval of
    /// individual chunks of these large assets. The first range is `Some(0)`, the second range is
    /// `Some(ASSET_CHUNK_SIZE)`, the third range is `Some(ASSET_CHUNK_SIZE * 2)`, and so on. The entire asset can
    /// also be retrieved by passing `None` as the starting range. See [ASSET_CHUNK_SIZE](crate::ASSET_CHUNK_SIZE) for the size of each chunk.
    fn get(
        &self,
        path: impl Into<String>,
        encoding: Option<AssetEncoding>,
        starting_range: Option<usize>,
    ) -> Option<&HttpResponse<'content>>;

    /// Returns the number of assets in the map.
    fn len(&self) -> usize;

    /// Returns `true` if the map contains no assets.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over the assets in the map.
    fn iter(&'content self) -> AssetMapIterator<'content>;
}

impl<'content> AssetMap<'content> for HashMap<RequestKey, CertifiedAssetResponse<'content>> {
    fn get(
        &self,
        path: impl Into<String>,
        encoding: Option<AssetEncoding>,
        range_begin: Option<usize>,
    ) -> Option<&HttpResponse<'content>> {
        let req_key = RequestKey::new(path, encoding.map(|e| e.to_string()), range_begin);

        self.get(&req_key).map(|e| &e.response)
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn iter(&'content self) -> AssetMapIterator<'content> {
        AssetMapIterator { inner: self.iter() }
    }
}

/// An iterator over the assets in an asset map.
#[derive(Debug)]
pub struct AssetMapIterator<'content> {
    inner: Iter<'content, RequestKey, CertifiedAssetResponse<'content>>,
}

impl<'content> Iterator for AssetMapIterator<'content> {
    type Item = (
        (&'content str, Option<&'content str>, Option<usize>),
        &'content HttpResponse<'content>,
    );

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(key, asset)| {
            (
                (key.path.as_str(), key.encoding.as_deref(), key.range_begin),
                &asset.response,
            )
        })
    }
}
