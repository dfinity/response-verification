use std::borrow::Cow;

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
    pub(crate) url: String,
    pub(crate) content: Cow<'content, [u8]>,
}

impl<'content, 'path> Asset<'content, 'path> {
    /// Creates a new asset with the given path and content.
    /// Both parameters may be owned values, or references so developers are free to
    /// choose whichever option is best suited for their use case.
    pub fn new(path: impl Into<Cow<'path, str>>, content: impl Into<Cow<'content, [u8]>>) -> Self {
        let path = path.into();

        Asset {
            url: path_to_url(path.as_ref()),
            path,
            content: content.into(),
        }
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

        let asset = Asset::new(path, content);

        assert_eq!(asset.path, "foo");
        assert_eq!(asset.url, "/foo");
        assert_eq!(asset.content, vec![1, 2, 3]);
    }

    #[rstest]
    fn asset_new_borrowed_values() {
        let path = "foo";
        let content = [1, 2, 3].as_slice();

        let asset = Asset::new(path, content);

        assert_eq!(asset.path, "foo");
        assert_eq!(asset.url, "/foo");
        assert_eq!(asset.content, vec![1, 2, 3]);
    }
}
