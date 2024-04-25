use super::certification_tree_path::{HttpCertificationPath, InnerTreePath};
use crate::HttpCertification;
use std::borrow::Cow;

/// An entry in an [HttpCertificationTree](crate::HttpCertificationTree).
///
/// It requires two properties:
///
/// - [path](HttpCertificationTreeEntry::path) specifies the path of an
/// [HttpCertification] definition within the tree. This path will define
/// what [HttpRequest](crate::HttpRequest) URLs the
/// [certification](HttpCertificationTreeEntry::certification) will be valid for.
///
/// - [certification](HttpCertificationTreeEntry::certification) that specifies the
/// [HttpCertification] definition itself.
///
/// Use the [new](HttpCertificationTreeEntry::new) associated function to create a new `HttpCertificationTreeEntry`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpCertificationTreeEntry<'a> {
    /// The path of an [HttpCertification] definition within the tree.
    /// This path will define what [HttpRequest](crate::HttpRequest) URLs the
    /// [certification](HttpCertificationTreeEntry::certification) will be valid for.
    pub path: Cow<'a, HttpCertificationPath<'a>>,

    /// The [HttpCertification] definition itself.
    pub certification: Cow<'a, HttpCertification>,
}

impl<'a> HttpCertificationTreeEntry<'a> {
    /// Creates a new [HttpCertificationTreeEntry] with the given `path` and `certification`.
    /// This is a convenience method for creating a [HttpCertificationTreeEntry]
    /// without having to directly deal with the [Cow] type.
    pub fn new(
        path: impl Into<Cow<'a, HttpCertificationPath<'a>>>,
        certification: impl Into<Cow<'a, HttpCertification>>,
    ) -> Self {
        Self {
            path: path.into(),
            certification: certification.into(),
        }
    }

    pub(super) fn to_tree_path(&self) -> InnerTreePath {
        let mut tree_path = vec![];
        tree_path.append(&mut self.path.to_tree_path());
        tree_path.append(&mut self.certification.to_tree_path());

        tree_path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        request_hash, response_hash, DefaultCelBuilder, DefaultResponseCertification, HttpRequest,
        HttpResponse,
    };
    use ic_representation_independent_hash::hash;
    use rstest::*;
    use rstest_reuse::*;

    #[template]
    #[rstest]
    #[case(HttpCertificationPath::exact("/foo/bar"), vec!["foo", "bar", "<$>"])]
    #[case(HttpCertificationPath::wildcard("/foo/bar"), vec!["foo", "bar", "<*>"])]
    fn certification_paths(
        #[case] path: HttpCertificationPath<'static>,
        #[case] expected: Vec<&str>,
    ) {
    }

    #[apply(certification_paths)]
    fn skip_certification_path(
        #[case] path: HttpCertificationPath<'static>,
        #[case] expected: Vec<&str>,
    ) {
        let cel_expr = DefaultCelBuilder::skip_certification().to_string();
        let cel_expr_hash = hash(cel_expr.as_bytes());

        let certification = HttpCertification::skip();
        let entry = HttpCertificationTreeEntry::new(&path, certification);

        let result = entry.to_tree_path();

        let path_segments: Vec<_> = expected
            .into_iter()
            .map(|segment| segment.as_bytes().to_vec())
            .collect();
        let expected = vec![cel_expr_hash.to_vec().to_owned()];

        let expected: Vec<_> = path_segments
            .into_iter()
            .chain(expected.into_iter())
            .collect();

        assert_eq!(result, expected);
    }

    #[apply(certification_paths)]
    fn response_only_certification_path(
        #[case] path: HttpCertificationPath<'static>,
        #[case] expected: Vec<&str>,
    ) {
        let cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec![],
            ))
            .build();
        let cel_expr_hash = hash(cel_expr.to_string().as_bytes());

        let response = HttpResponse {
            status_code: 200,
            body: vec![],
            headers: vec![("IC-CertificateExpression".to_string(), cel_expr.to_string())],
            upgrade: None,
        };
        let expected_response_hash = response_hash(&response, &cel_expr.response, None);

        let certification = HttpCertification::response_only(&cel_expr, &response, None).unwrap();
        let entry = HttpCertificationTreeEntry::new(&path, certification);

        let result = entry.to_tree_path();

        let path_segments: Vec<_> = expected
            .into_iter()
            .map(|segment| segment.as_bytes().to_vec())
            .collect();
        let expected = vec![
            cel_expr_hash.to_vec().to_owned(),
            "".as_bytes().to_vec(),
            expected_response_hash.to_vec(),
        ];

        let expected: Vec<_> = path_segments
            .into_iter()
            .chain(expected.into_iter())
            .collect();

        assert_eq!(result, expected);
    }

    #[apply(certification_paths)]
    fn full_certification_path(
        #[case] path: HttpCertificationPath<'static>,
        #[case] expected: Vec<&str>,
    ) {
        let cel_expr = DefaultCelBuilder::full_certification().build();
        let cel_expr_hash = hash(cel_expr.to_string().as_bytes());

        let request = HttpRequest {
            body: vec![],
            headers: vec![],
            method: "GET".to_string(),
            url: "/index.html".to_string(),
        };
        let expected_request_hash = request_hash(&request, &cel_expr.request).unwrap();

        let response = HttpResponse {
            status_code: 200,
            body: vec![],
            headers: vec![("IC-CertificateExpression".to_string(), cel_expr.to_string())],
            upgrade: None,
        };
        let expected_response_hash = response_hash(&response, &cel_expr.response, None);

        let certification = HttpCertification::full(&cel_expr, &request, &response, None).unwrap();
        let entry = HttpCertificationTreeEntry::new(&path, certification);

        let result = entry.to_tree_path();

        let path_segments: Vec<_> = expected
            .into_iter()
            .map(|segment| segment.as_bytes().to_vec())
            .collect();
        let expected = vec![
            cel_expr_hash.to_vec().to_owned(),
            expected_request_hash.to_vec(),
            expected_response_hash.to_vec(),
        ];

        let expected: Vec<_> = path_segments
            .into_iter()
            .chain(expected.into_iter())
            .collect();

        assert_eq!(result, expected);
    }
}
