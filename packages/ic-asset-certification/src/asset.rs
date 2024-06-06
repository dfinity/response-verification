use std::{
    borrow::Cow,
    fmt::{Display, Formatter},
};

/// An asset to be certified and served by an [AssetRouter](crate::AssetRouter).
///
/// Use the [new](Asset::new) associated function to create instances of
/// this struct.
///
/// # Examples
///
/// ## With owned values
///
/// ```
/// use ic_asset_certification::Asset;
///
/// let path = String::from("foo");
/// let content = vec![1, 2, 3];
///
/// let asset = Asset::new(path, content);
/// ```
///
/// ## With borrowed values
///
/// ```
/// use ic_asset_certification::Asset;
///
/// let path = "foo";
/// let content = [1, 2, 3].as_slice();
///
/// let asset = Asset::new(path, content);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset<'content, 'path> {
    pub(crate) path: Cow<'path, str>,
    pub(crate) url: Cow<'path, str>,
    pub(crate) content: Cow<'content, [u8]>,
    pub(crate) encoding: AssetEncoding,
}

impl<'content, 'path> Asset<'content, 'path> {
    /// Creates a new asset with the given path and content.
    /// Both parameters may be owned values, or references so developers are free to
    /// choose whichever option is best suited for their use case.
    pub fn new(path: impl Into<Cow<'path, str>>, content: impl Into<Cow<'content, [u8]>>) -> Self {
        let path = path.into();

        Asset {
            url: Cow::Owned(path_to_url(path.as_ref())),
            path,
            content: content.into(),
            encoding: AssetEncoding::Identity,
        }
    }

    /// Sets the encoding of the asset.
    /// This method is chainable.
    pub fn with_encoding(
        path: impl Into<Cow<'path, str>>,
        content: impl Into<Cow<'content, [u8]>>,
        url: impl Into<Cow<'path, str>>,
        encoding: AssetEncoding,
    ) -> Self {
        Asset {
            url: url.into(),
            path: path.into(),
            content: content.into(),
            encoding,
        }
    }
}

/// The encoding of an asset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssetEncoding {
    /// The asset is encoded with the Brotli algorithm.
    Brotli,

    /// The asset is encoded with the Zstd algorithm.
    Zstd,

    /// The asset is encoded with the Gzip algorithm.
    Gzip,

    /// The asset is encoded with the Deflate algorithm.
    Deflate,

    /// The asset is not encoded.
    Identity,
}

impl Display for AssetEncoding {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            AssetEncoding::Brotli => "br".to_string(),
            AssetEncoding::Zstd => "zstd".to_string(),
            AssetEncoding::Gzip => "gzip".to_string(),
            AssetEncoding::Deflate => "deflate".to_string(),
            AssetEncoding::Identity => "identity".to_string(),
        };

        write!(f, "{}", str)
    }
}

fn path_to_url(path: &str) -> String {
    if !path.starts_with('/') {
        format!("/{}", path)
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    fn asset_new_owned_values() {
        let path = String::from("foo");
        let content = vec![1, 2, 3];

        let asset = Asset::new(path.clone(), content.clone());

        assert_eq!(asset.path, path);
        assert_eq!(asset.url, "/foo");
        assert_eq!(asset.content, content);
        assert_eq!(asset.encoding, AssetEncoding::Identity);
    }

    #[rstest]
    fn asset_new_borrowed_values() {
        let path = "foo";
        let content = [1, 2, 3].as_slice();

        let asset = Asset::new(path, content);

        assert_eq!(asset.path, path);
        assert_eq!(asset.url, "/foo");
        assert_eq!(asset.content, content);
        assert_eq!(asset.encoding, AssetEncoding::Identity);
    }

    #[rstest]
    fn asset_with_encoding() {
        let path = "foo";
        let content = [1, 2, 3].as_slice();
        let url = "bar";
        let encoding = AssetEncoding::Brotli;

        let asset = Asset::with_encoding(path, content, url, encoding.clone());

        assert_eq!(asset.path, path);
        assert_eq!(asset.url, url);
        assert_eq!(asset.content, content);
        assert_eq!(asset.encoding, encoding);
    }

    #[rstest]
    fn asset_encoding_to_string() {
        assert_eq!(AssetEncoding::Brotli.to_string(), "br");
        assert_eq!(AssetEncoding::Zstd.to_string(), "zstd");
        assert_eq!(AssetEncoding::Gzip.to_string(), "gzip");
        assert_eq!(AssetEncoding::Deflate.to_string(), "deflate");
        assert_eq!(AssetEncoding::Identity.to_string(), "identity");
    }
}
