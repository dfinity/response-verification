pub(super) type CertificationTreePathSegment = Vec<u8>;
pub(super) type InnerTreePath = Vec<CertificationTreePathSegment>;

pub(super) const PATH_PREFIX: &str = "http_expr";
pub(super) const PATH_PREFIX_BYTES: &[u8] = PATH_PREFIX.as_bytes();

pub(super) const EXACT_PATH_TERMINATOR: &str = "<$>";
pub(super) const EXACT_PATH_TERMINATOR_BYTES: &[u8] = EXACT_PATH_TERMINATOR.as_bytes();

pub(super) const WILDCARD_PATH_TERMINATOR: &str = "<*>";
pub(super) const WILDCARD_PATH_TERMINATOR_BYTES: &[u8] = WILDCARD_PATH_TERMINATOR.as_bytes();

/// A path to an [HttpCertification](crate::HttpCertification) in an
/// [HttpCertificationTree](crate::HttpCertificationTree).
///
/// Two variants are supported:
///
/// - The [Exact](HttpCertificationPath::Exact) variant is used for paths that match a full URL path.
/// For example, `HttpCertificationPath::Exact('/foo')` will match the URL path `/foo` but not `/foo/bar`
/// or `/foo/baz`.
///
/// - The [Wildcard](HttpCertificationPath::Wildcard) variant is used for paths that match a URL path prefix.
/// For example, `HttpCertificationPath::Wildcard('/foo')` will match the URL paths `/foo/bar` and `/foo/baz`.
#[derive(Debug)]
pub enum HttpCertificationPath<'a> {
    /// An exact path to an [HttpCertification](crate::HttpCertification) in an
    /// [HttpCertificationTree](crate::HttpCertificationTree). This path will match only
    /// [HttpRequest](crate::HttpRequest) URL paths that are exactly the same as the given path.
    Exact(&'a str),

    /// A wildcard path to an [HttpCertification](crate::HttpCertification) in an
    /// [HttpCertificationTree](crate::HttpCertificationTree). This path will match all
    /// [HttpRequest](crate::HttpRequest) URL paths that start with the given prefix.
    Wildcard(&'a str),
}

impl<'a> HttpCertificationPath<'a> {
    pub(super) fn to_tree_path(&self) -> InnerTreePath {
        match self {
            Self::Exact(path) => Self::path_to_segments(path, EXACT_PATH_TERMINATOR_BYTES),
            Self::Wildcard(path) => Self::path_to_segments(path, WILDCARD_PATH_TERMINATOR_BYTES),
        }
    }

    /// Converts this path into a format suitable for use in the `expr_path` field of the `IC-Certificate` header.
    pub fn to_expr_path(&self) -> Vec<String> {
        match self {
            Self::Exact(path) => Self::path_to_string_segments(path, EXACT_PATH_TERMINATOR),
            Self::Wildcard(path) => Self::path_to_string_segments(path, WILDCARD_PATH_TERMINATOR),
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
        let path = HttpCertificationPath::Exact(path);

        let result = path.to_tree_path();
        let expected = expected
            .iter()
            .map(|segment| segment.as_bytes().to_vec())
            .collect::<InnerTreePath>();

        assert_eq!(result, expected);
    }

    #[apply(wildcard_paths)]
    fn wildcard_path_to_tree_path(#[case] path: &str, #[case] expected: Vec<&str>) {
        let path = HttpCertificationPath::Wildcard(path);

        let result = path.to_tree_path();
        let expected = expected
            .iter()
            .map(|segment| segment.as_bytes().to_vec())
            .collect::<InnerTreePath>();

        assert_eq!(result, expected);
    }

    #[apply(exact_paths)]
    fn exact_path_to_expr_path(#[case] path: &str, #[case] expected: Vec<&str>) {
        let path = HttpCertificationPath::Exact(path);

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
        let path = HttpCertificationPath::Wildcard(path);

        let result = path.to_expr_path();
        let expected = [PATH_PREFIX]
            .iter()
            .chain(expected.iter())
            .map(|segment| segment.to_string())
            .collect::<Vec<_>>();

        assert_eq!(result, expected);
    }
}
