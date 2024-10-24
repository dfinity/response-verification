use crate::{AssetEncoding, AssetRequestKey, CertifiedAssetResponse};
use ic_http_certification::HttpResponse;
use std::collections::{hash_map::Iter, HashMap};

///
pub trait AssetMap<'content> {
    ///
    fn get(
        &self,
        path: impl Into<String>,
        encoding: Option<AssetEncoding>,
        range_begin: Option<usize>,
    ) -> Option<&HttpResponse<'content>>;

    ///
    fn len(&self) -> usize;

    ///
    fn iter(&'content self) -> AssetMapIterator<'content>;
}

impl<'content> AssetMap<'content> for HashMap<AssetRequestKey, CertifiedAssetResponse<'content>> {
    fn get(
        &self,
        path: impl Into<String>,
        encoding: Option<AssetEncoding>,
        range_begin: Option<usize>,
    ) -> Option<&HttpResponse<'content>> {
        let req_key = AssetRequestKey::new(path, encoding.map(|e| e.to_string()), range_begin);

        self.get(&req_key).map(|e| &e.response)
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn iter(&'content self) -> AssetMapIterator<'content> {
        AssetMapIterator { inner: self.iter() }
    }
}

///
#[derive(Debug)]
pub struct AssetMapIterator<'content> {
    inner: Iter<'content, AssetRequestKey, CertifiedAssetResponse<'content>>,
}

impl<'content> Iterator for AssetMapIterator<'content> {
    type Item = (
        (&'content str, Option<&'content str>, Option<usize>),
        &'content HttpResponse<'content>,
    );

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(key, asset)| {
            (
                (
                    key.path.as_str(),
                    key.encoding.as_ref().map(|e| e.as_str()),
                    key.range_begin,
                ),
                &asset.response,
            )
        })
    }
}
