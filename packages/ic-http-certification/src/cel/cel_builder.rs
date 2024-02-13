use super::{
    CelExpression, DefaultCelExpression, DefaultFullCelExpression, DefaultRequestCertification,
    DefaultResponseCertification, DefaultResponseOnlyCelExpression,
};
use std::borrow::Cow;

/// A CEL expression builder for creating a default certification expression.
#[derive(Debug, Clone)]
pub struct DefaultCelBuilder {}

impl DefaultCelBuilder {
    /// Create a CEL expression that skips certification entirely.
    pub fn skip_certification<'a>() -> CelExpression<'a> {
        CelExpression::Default(DefaultCelExpression::Skip)
    }

    /// Creates a builder for a CEL expression that will only certify a response.
    /// Request certification will not be included with this builder.
    /// See [DefaultResponseOnlyCelBuilder] for more details on this builder's interface.
    /// See [full_certification](DefaultCelBuilder::full_certification()) for a builder that will certify both the request and response.
    pub fn response_only_certification<'a>() -> DefaultResponseOnlyCelBuilder<'a> {
        DefaultResponseOnlyCelBuilder::default()
    }

    /// Creates a builder for a CEL expression that will certify both the request and response.
    /// See [DefaultFullCelExpressionBuilder] for more details on this builder's interface.
    /// See [response_only_certification](DefaultCelBuilder::response_only_certification()) for a builder that will only certify the response.
    pub fn full_certification<'a>() -> DefaultFullCelExpressionBuilder<'a> {
        DefaultFullCelExpressionBuilder::default()
    }
}

/// A CEL expression builder for creating expressions that will only certify a response.
/// To create an expression that certifies both the request and response, see [DefaultFullCelExpressionBuilder].
#[derive(Debug, Clone, Default)]
pub struct DefaultResponseOnlyCelBuilder<'a> {
    response_certification: DefaultResponseCertification<'a>,
}

impl<'a> DefaultResponseOnlyCelBuilder<'a> {
    /// Configure the response headers that will be included in certification.
    ///
    /// See [DefaultResponseCertification] for details on how to configure this.
    /// Not calling this method will result in no response headers being certified.
    pub fn with_response_certification(
        mut self,
        headers_config: DefaultResponseCertification<'a>,
    ) -> Self {
        self.response_certification = headers_config;

        self
    }

    /// Build the CEL expression, consuming the builder.
    pub fn build(self) -> DefaultResponseOnlyCelExpression<'a> {
        DefaultResponseOnlyCelExpression {
            response: self.response_certification,
        }
    }
}

/// A CEL expression builder for creating expressions that will certify both the request and response.
/// To create an expression that only certifies the response, see [DefaultResponseOnlyCelBuilder].
#[derive(Debug, Clone, Default)]
pub struct DefaultFullCelExpressionBuilder<'a> {
    request_headers: Cow<'a, [&'a str]>,
    request_query_parameters: Cow<'a, [&'a str]>,
    response_certification: DefaultResponseCertification<'a>,
}

impl<'a> DefaultFullCelExpressionBuilder<'a> {
    /// Configure the request headers that will be included in certification.
    ///
    /// As many or as little headers can be provided as desired.
    /// Providing an empty list, or not calling this method, will result in no request query parameters being certified.
    pub fn with_request_headers(mut self, headers: impl Into<Cow<'a, [&'a str]>>) -> Self {
        self.request_headers = headers.into();

        self
    }

    /// Configure the request query parameters that will be included in certification.
    ///
    /// As many or as little query parameters can be provided as desired.
    /// Providing an empty list, or not calling this method, will result in no request query parameters being certified.
    pub fn with_request_query_parameters(
        mut self,
        query_params: impl Into<Cow<'a, [&'a str]>>,
    ) -> Self {
        self.request_query_parameters = query_params.into();

        self
    }

    /// Configure the response headers that will be included in certification.
    ///
    /// See [DefaultResponseCertification] for details on how to configure this.
    /// Not calling this method will result in no response headers being certified.
    pub fn with_response_certification(
        mut self,
        headers_config: DefaultResponseCertification<'a>,
    ) -> Self {
        self.response_certification = headers_config;

        self
    }

    /// Build the CEL expression, consuming the builder.
    pub fn build(self) -> DefaultFullCelExpression<'a> {
        let request_certification =
            DefaultRequestCertification::new(self.request_headers, self.request_query_parameters);

        DefaultFullCelExpression {
            request: request_certification,
            response: self.response_certification,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cel::fixtures::*;
    use rstest::*;

    #[rstest]
    fn no_certification(no_certification_cel: String) {
        let cel_expr = DefaultCelBuilder::skip_certification().to_string();

        assert_eq!(cel_expr, no_certification_cel);
    }

    #[rstest]
    fn no_request_response_inclusions(no_request_response_inclusions_cel: String) {
        let cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec![
                    "Cache-Control",
                    "ETag",
                    "Content-Length",
                    "Content-Type",
                    "Content-Encoding",
                ],
            ))
            .build()
            .to_string();

        assert_eq!(cel_expr, no_request_response_inclusions_cel);
    }

    #[rstest]
    fn no_request_response_exclusions(no_request_response_exclusions_cel: String) {
        let cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec!["Date", "Cookie", "Set-Cookie"],
            ))
            .build()
            .to_string();

        assert_eq!(cel_expr, no_request_response_exclusions_cel);
    }

    #[rstest]
    fn no_request_empty_response_inclusions(no_request_empty_response_inclusions_cel: String) {
        let implicit_cel_expr = DefaultCelBuilder::response_only_certification()
            .build()
            .to_string();
        let explicit_cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec![],
            ))
            .build()
            .to_string();
        let default_cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::default())
            .build()
            .to_string();

        assert_eq!(implicit_cel_expr, no_request_empty_response_inclusions_cel);
        assert_eq!(explicit_cel_expr, no_request_empty_response_inclusions_cel);
        assert_eq!(default_cel_expr, no_request_empty_response_inclusions_cel);
    }

    #[rstest]
    fn no_request_empty_response_exclusions(no_request_empty_response_exclusions_cel: String) {
        let cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build()
            .to_string();

        assert_eq!(cel_expr, no_request_empty_response_exclusions_cel);
    }

    #[rstest]
    fn include_request_response_header_inclusions(
        include_request_response_header_inclusions_cel: String,
    ) {
        let cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(vec!["foo", "bar", "baz"])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec![
                    "Cache-Control",
                    "ETag",
                    "Content-Length",
                    "Content-Type",
                    "Content-Encoding",
                ],
            ))
            .build()
            .to_string();

        assert_eq!(cel_expr, include_request_response_header_inclusions_cel);
    }

    #[rstest]
    fn include_request_response_header_exclusions(
        include_request_response_header_exclusions_cel: String,
    ) {
        let cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(vec!["foo", "bar", "baz"])
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec!["Date", "Cookie", "Set-Cookie"],
            ))
            .build()
            .to_string();

        assert_eq!(cel_expr, include_request_response_header_exclusions_cel);
    }

    #[rstest]
    fn include_request_empty_response_inclusions(
        include_request_empty_response_inclusions_cel: String,
    ) {
        let implicit_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(vec!["foo", "bar", "baz"])
            .build()
            .to_string();
        let explicit_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(vec!["foo", "bar", "baz"])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec![],
            ))
            .build()
            .to_string();
        let default_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(vec!["foo", "bar", "baz"])
            .with_response_certification(DefaultResponseCertification::default())
            .build()
            .to_string();

        assert_eq!(
            implicit_cel_expr,
            include_request_empty_response_inclusions_cel
        );
        assert_eq!(
            explicit_cel_expr,
            include_request_empty_response_inclusions_cel
        );
        assert_eq!(
            default_cel_expr,
            include_request_empty_response_inclusions_cel
        );
    }

    #[rstest]
    fn include_request_empty_response_exclusions(
        include_request_empty_response_exclusions_cel: String,
    ) {
        let cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(vec!["foo", "bar", "baz"])
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build()
            .to_string();

        assert_eq!(cel_expr, include_request_empty_response_exclusions_cel);
    }

    #[rstest]
    fn empty_request_response_inclusions(empty_request_response_inclusions_cel: String) {
        let implicit_cel_expr = DefaultCelBuilder::full_certification().build().to_string();
        let explicit_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec![])
            .with_request_query_parameters(vec![])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec![],
            ))
            .build()
            .to_string();
        let default_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec![])
            .with_request_query_parameters(vec![])
            .with_response_certification(DefaultResponseCertification::default())
            .build()
            .to_string();

        assert_eq!(implicit_cel_expr, empty_request_response_inclusions_cel);
        assert_eq!(explicit_cel_expr, empty_request_response_inclusions_cel);
        assert_eq!(default_cel_expr, empty_request_response_inclusions_cel);
    }

    #[rstest]
    fn empty_request_response_exclusions(empty_request_response_exclusions_cel: String) {
        let implicit_cel_expr = DefaultCelBuilder::full_certification()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build()
            .to_string();
        let explicit_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec![])
            .with_request_query_parameters(vec![])
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build()
            .to_string();

        assert_eq!(implicit_cel_expr, empty_request_response_exclusions_cel);
        assert_eq!(explicit_cel_expr, empty_request_response_exclusions_cel);
    }
}
