use crate::utils::{
    EXACT_PATH_TERMINATOR, EXACT_PATH_TERMINATOR_BYTES, PATH_PREFIX, WILDCARD_PATH_TERMINATOR,
    WILDCARD_PATH_TERMINATOR_BYTES,
};
use std::borrow::Cow;

pub(super) type CertificationTreePathSegment = Vec<u8>;
pub(super) type InnerTreePath = Vec<CertificationTreePathSegment>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum HttpCertificationPathType<'a> {
    Exact(Cow<'a, str>),
    Wildcard(Cow<'a, str>),
}

/// A path to an [HttpCertification](crate::HttpCertification) in an
/// [HttpCertificationTree](crate::HttpCertificationTree).
///
/// Two variants are supported:
///
/// - The [Exact](HttpCertificationPath::exact()) variant is used for paths that match a full URL path.
/// For example, `HttpCertificationPath::exact('/foo')` will match the URL path `/foo` but not `/foo/bar`
/// or `/foo/baz`.
///
/// - The [Wildcard](HttpCertificationPath::wildcard()) variant is used for paths that match a URL path prefix.
/// For example, `HttpCertificationPath::wildcard('/foo')` will match the URL paths `/foo/bar` and `/foo/baz`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCertificationPath<'a>(HttpCertificationPathType<'a>);

impl<'a> HttpCertificationPath<'a> {
    /// An exact path to an [HttpCertification](crate::HttpCertification) in an
    /// [HttpCertificationTree](crate::HttpCertificationTree). This path will match only
    /// [HttpRequest](crate::HttpRequest) URL paths that are exactly the same as the given path.
    pub fn exact(path: impl Into<Cow<'a, str>>) -> Self {
        Self(HttpCertificationPathType::Exact(path.into()))
    }

    /// A wildcard path to an [HttpCertification](crate::HttpCertification) in an
    /// [HttpCertificationTree](crate::HttpCertificationTree). This path will match all
    /// [HttpRequest](crate::HttpRequest) URL paths that start with the given prefix.
    pub fn wildcard(path: impl Into<Cow<'a, str>>) -> Self {
        Self(HttpCertificationPathType::Wildcard(path.into()))
    }

    pub(super) fn to_tree_path(&self) -> InnerTreePath {
        match &self.0 {
            HttpCertificationPathType::Exact(path) => {
                Self::path_to_segments(path.as_ref(), EXACT_PATH_TERMINATOR_BYTES)
            }
            HttpCertificationPathType::Wildcard(path) => {
                Self::path_to_segments(path.as_ref(), WILDCARD_PATH_TERMINATOR_BYTES)
            }
        }
    }

    pub(super) fn get_type(&self) -> &HttpCertificationPathType<'a> {
        &self.0
    }

    /// Converts this path into a format suitable for use in the `expr_path` field of the `IC-Certificate` header.
    pub fn to_expr_path(&self) -> Vec<String> {
        match &self.0 {
            HttpCertificationPathType::Exact(path) => {
                Self::path_to_string_segments(path.as_ref(), EXACT_PATH_TERMINATOR)
            }
            HttpCertificationPathType::Wildcard(path) => {
                Self::path_to_string_segments(path.as_ref(), WILDCARD_PATH_TERMINATOR)
            }
        }
    }

    fn path_to_segments(path: &str, terminator: &[u8]) -> InnerTreePath {
        let mut path_segments = path
            .split('/')
            .filter(|e| !e.is_empty())
            .map(str::as_bytes)
            .map(Vec::from)
            .collect::<InnerTreePath>();
        if path.ends_with('/') {
            path_segments.push("".as_bytes().to_vec());
        }

        path_segments.push(terminator.to_vec());

        path_segments
    }

    fn path_to_string_segments(path: &str, terminator: &str) -> Vec<String> {
        let mut path_segments = vec![PATH_PREFIX.to_string()];
        path_segments.append(
            &mut path
                .split('/')
                .filter(|e| !e.is_empty())
                .map(String::from)
                .collect(),
        );
        if path.ends_with('/') {
            path_segments.push("".to_string());
        }

        path_segments.push(terminator.to_string());

        path_segments
    }
}

impl<'a> From<HttpCertificationPath<'a>> for Cow<'a, HttpCertificationPath<'a>> {
    fn from(path: HttpCertificationPath<'a>) -> Cow<'a, HttpCertificationPath<'a>> {
        Cow::Owned(path)
    }
}

impl<'a> From<&'a HttpCertificationPath<'a>> for Cow<'a, HttpCertificationPath<'a>> {
    fn from(path: &'a HttpCertificationPath<'a>) -> Cow<'a, HttpCertificationPath<'a>> {
        Cow::Borrowed(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use rstest_reuse::*;

    #[template]
    #[rstest]
    #[case("", vec!["<$>"])]
    #[case("/", vec!["", "<$>"])]
    #[case("/foo", vec!["foo", "<$>"])]
    #[case("foo", vec!["foo", "<$>"])]
    #[case("/foo/", vec!["foo", "", "<$>"])]
    #[case("foo/", vec!["foo", "", "<$>"])]
    #[case("/foo/bar", vec!["foo", "bar", "<$>"])]
    #[case("foo/bar", vec!["foo", "bar", "<$>"])]
    #[case("/foo/bar/", vec!["foo", "bar", "", "<$>"])]
    #[case("foo/bar/", vec!["foo", "bar", "", "<$>"])]
    fn exact_paths(#[case] path: &str, #[case] expected: Vec<&str>) {}

    #[template]
    #[rstest]
    #[case("", vec!["<*>"])]
    #[case("/", vec!["", "<*>"])]
    #[case("/foo", vec!["foo", "<*>"])]
    #[case("foo", vec!["foo", "<*>"])]
    #[case("/foo/", vec!["foo", "", "<*>"])]
    #[case("foo/", vec!["foo", "", "<*>"])]
    #[case("/foo/bar", vec!["foo", "bar", "<*>"])]
    #[case("foo/bar", vec!["foo", "bar", "<*>"])]
    #[case("/foo/bar/", vec!["foo", "bar", "", "<*>"])]
    #[case("foo/bar/", vec!["foo", "bar", "", "<*>"])]
    fn wildcard_paths(#[case] path: &str, #[case] expected: Vec<&str>) {}

    #[apply(exact_paths)]
    fn exact_path_to_tree_path(#[case] path: &str, #[case] expected: Vec<&str>) {
        let path = HttpCertificationPath::exact(path);

        let result = path.to_tree_path();
        let expected = expected
            .iter()
            .map(|segment| segment.as_bytes().to_vec())
            .collect::<InnerTreePath>();

        assert_eq!(result, expected);
    }

    #[apply(wildcard_paths)]
    fn wildcard_path_to_tree_path(#[case] path: &str, #[case] expected: Vec<&str>) {
        let path = HttpCertificationPath::wildcard(path);

        let result = path.to_tree_path();
        let expected = expected
            .iter()
            .map(|segment| segment.as_bytes().to_vec())
            .collect::<InnerTreePath>();

        assert_eq!(result, expected);
    }

    #[apply(exact_paths)]
    fn exact_path_to_expr_path(#[case] path: &str, #[case] expected: Vec<&str>) {
        let path = HttpCertificationPath::exact(path);

        let result = path.to_expr_path();
        let expected = [PATH_PREFIX]
            .iter()
            .chain(expected.iter())
            .map(|segment| segment.to_string())
            .collect::<Vec<_>>();

        assert_eq!(result, expected);
    }

    #[apply(wildcard_paths)]
    fn wildcard_path_to_expr_path(#[case] path: &str, #[case] expected: Vec<&str>) {
        let path = HttpCertificationPath::wildcard(path);

        let result = path.to_expr_path();
        let expected = [PATH_PREFIX]
            .iter()
            .chain(expected.iter())
            .map(|segment| segment.to_string())
            .collect::<Vec<_>>();

        assert_eq!(result, expected);
    }
}
