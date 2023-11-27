use super::{
    CelExpression, DefaultCertification, DefaultRequestCertification, DefaultResponseCertification,
};

/// A CEL expression builder for creating a default certification expression.
#[derive(Debug, Clone)]
pub struct DefaultCelBuilder {}

impl DefaultCelBuilder {
    /// Create a CEL expression that skips certification entirely.
    pub fn skip_certification<'a>() -> CelExpression<'a> {
        CelExpression::DefaultCertification(None)
    }

    /// Creates a builder for a CEL expression that will only certify a response.
    /// Request certification will not be included with this builder.
    /// See [DefaultResponseCelBuilder] for more details on this builder's interface.
    /// See [full_certification](DefaultCelBuilder::full_certification()) for a builder that will certify both the request and response.
    pub fn response_certification<'a>() -> DefaultResponseCelBuilder<'a> {
        Default::default()
    }

    /// Creates a builder for a CEL expression that will certify both the request and response.
    /// See [DefaultFullCelExpressionBuilder] for more details on this builder's interface.
    /// See [response_certification](DefaultCelBuilder::response_certification()) for a builder that will only certify the response.
    pub fn full_certification<'a>() -> DefaultFullCelExpressionBuilder<'a> {
        Default::default()
    }
}

/// A CEL expression builder for creating expressions that will only certify a response.
/// To create an expression that certifies both the request and response, see [DefaultFullCelExpressionBuilder].
#[derive(Debug, Clone, Default)]
pub struct DefaultResponseCelBuilder<'a> {
    response_certification: DefaultResponseCertification<'a>,
}

impl<'a> DefaultResponseCelBuilder<'a> {
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
    pub fn build(self) -> CelExpression<'a> {
        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification: None,
            response_certification: self.response_certification,
        }))
    }
}

/// A CEL expression builder for creating expressions that will certify both the request and response.
/// To create an expression that only certifies the response, see [DefaultResponseCelBuilder].
#[derive(Debug, Clone, Default)]
pub struct DefaultFullCelExpressionBuilder<'a> {
    request_headers: &'a [&'a str],
    request_query_parameters: &'a [&'a str],
    response_certification: DefaultResponseCertification<'a>,
}

impl<'a> DefaultFullCelExpressionBuilder<'a> {
    /// Configure the request headers that will be included in certification.
    ///
    /// As many or as little headers can be provided as desired.
    /// Providing an empty list, or not calling this method, will result in no request query parameters being certified.
    pub fn with_request_headers(mut self, headers: &'a [&'a str]) -> Self {
        self.request_headers = headers;

        self
    }

    /// Configure the request query parameters that will be included in certification.
    ///
    /// As many or as little query parameters can be provided as desired.
    /// Providing an empty list, or not calling this method, will result in no request query parameters being certified.
    pub fn with_request_query_parameters(mut self, query_params: &'a [&'a str]) -> Self {
        self.request_query_parameters = query_params;

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
    pub fn build(self) -> CelExpression<'a> {
        let request_certification = Some(DefaultRequestCertification {
            headers: self.request_headers,
            query_parameters: self.request_query_parameters,
        });

        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification,
            response_certification: self.response_certification,
        }))
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
        let cel_expr = DefaultCelBuilder::response_certification()
            .with_response_certification(DefaultResponseCertification::CertifiedResponseHeaders(&[
                "Cache-Control",
                "ETag",
                "Content-Length",
                "Content-Type",
                "Content-Encoding",
            ]))
            .build()
            .to_string();

        assert_eq!(cel_expr, no_request_response_inclusions_cel);
    }

    #[rstest]
    fn no_request_response_exclusions(no_request_response_exclusions_cel: String) {
        let cel_expr = DefaultCelBuilder::response_certification()
            .with_response_certification(DefaultResponseCertification::ResponseHeaderExclusions(&[
                "Date",
                "Cookie",
                "Set-Cookie",
            ]))
            .build()
            .to_string();

        assert_eq!(cel_expr, no_request_response_exclusions_cel);
    }

    #[rstest]
    fn no_request_empty_response_inclusions(no_request_empty_response_inclusions_cel: String) {
        let implicit_cel_expr = DefaultCelBuilder::response_certification()
            .build()
            .to_string();
        let explicit_cel_expr = DefaultCelBuilder::response_certification()
            .with_response_certification(
                DefaultResponseCertification::CertifiedResponseHeaders(&[]),
            )
            .build()
            .to_string();
        let default_cel_expr = DefaultCelBuilder::response_certification()
            .with_response_certification(DefaultResponseCertification::default())
            .build()
            .to_string();

        assert_eq!(implicit_cel_expr, no_request_empty_response_inclusions_cel);
        assert_eq!(explicit_cel_expr, no_request_empty_response_inclusions_cel);
        assert_eq!(default_cel_expr, no_request_empty_response_inclusions_cel);
    }

    #[rstest]
    fn no_request_empty_response_exclusions(no_request_empty_response_exclusions_cel: String) {
        let cel_expr = DefaultCelBuilder::response_certification()
            .with_response_certification(
                DefaultResponseCertification::ResponseHeaderExclusions(&[]),
            )
            .build()
            .to_string();

        assert_eq!(cel_expr, no_request_empty_response_exclusions_cel);
    }

    #[rstest]
    fn include_request_response_header_inclusions(
        include_request_response_header_inclusions_cel: String,
    ) {
        let cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(&["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(&["foo", "bar", "baz"])
            .with_response_certification(DefaultResponseCertification::CertifiedResponseHeaders(&[
                "Cache-Control",
                "ETag",
                "Content-Length",
                "Content-Type",
                "Content-Encoding",
            ]))
            .build()
            .to_string();

        assert_eq!(cel_expr, include_request_response_header_inclusions_cel);
    }

    #[rstest]
    fn include_request_response_header_exclusions(
        include_request_response_header_exclusions_cel: String,
    ) {
        let cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(&["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(&["foo", "bar", "baz"])
            .with_response_certification(DefaultResponseCertification::ResponseHeaderExclusions(&[
                "Date",
                "Cookie",
                "Set-Cookie",
            ]))
            .build()
            .to_string();

        assert_eq!(cel_expr, include_request_response_header_exclusions_cel);
    }

    #[rstest]
    fn include_request_empty_response_inclusions(
        include_request_empty_response_inclusions_cel: String,
    ) {
        let implicit_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(&["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(&["foo", "bar", "baz"])
            .build()
            .to_string();
        let explicit_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(&["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(&["foo", "bar", "baz"])
            .with_response_certification(
                DefaultResponseCertification::CertifiedResponseHeaders(&[]),
            )
            .build()
            .to_string();
        let default_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(&["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(&["foo", "bar", "baz"])
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
            .with_request_headers(&["Accept", "Accept-Encoding", "If-Match"])
            .with_request_query_parameters(&["foo", "bar", "baz"])
            .with_response_certification(
                DefaultResponseCertification::ResponseHeaderExclusions(&[]),
            )
            .build()
            .to_string();

        assert_eq!(cel_expr, include_request_empty_response_exclusions_cel);
    }

    #[rstest]
    fn empty_request_response_inclusions(empty_request_response_inclusions_cel: String) {
        let implicit_cel_expr = DefaultCelBuilder::full_certification().build().to_string();
        let explicit_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(&[])
            .with_request_query_parameters(&[])
            .with_response_certification(
                DefaultResponseCertification::CertifiedResponseHeaders(&[]),
            )
            .build()
            .to_string();
        let default_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(&[])
            .with_request_query_parameters(&[])
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
            .with_response_certification(
                DefaultResponseCertification::ResponseHeaderExclusions(&[]),
            )
            .build()
            .to_string();
        let explicit_cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(&[])
            .with_request_query_parameters(&[])
            .with_response_certification(
                DefaultResponseCertification::ResponseHeaderExclusions(&[]),
            )
            .build()
            .to_string();

        assert_eq!(implicit_cel_expr, empty_request_response_exclusions_cel);
        assert_eq!(explicit_cel_expr, empty_request_response_exclusions_cel);
    }
}
