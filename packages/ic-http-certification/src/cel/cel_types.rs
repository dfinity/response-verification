use super::create_cel_expr;
use std::borrow::Cow;

/// A certification CEL expression defintion.
/// Contains an enum variant for each CEL function supported for certification.
/// Currently only one variant is supported: [CelExpression::DefaultCertification].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CelExpression<'a> {
    /// A certification CEL expression definition that uses the `default_certification` function.
    /// This is currently the only supported function.
    ///
    /// The enum's inner value is an [Option] to allow for opting in, or out of certification.
    /// Providing [None] will opt out of certification, while providing [Some] will opt in to certification.
    /// See [DefaultCertification] for more details on its available parameters.
    DefaultCertification(Option<DefaultCertification<'a>>),
}

impl<'a> CelExpression<'a> {
    /// Converts a [CelExpression] object into it's [String] representation.
    /// Alias of [create_cel_expr](create_cel_expr()).
    pub fn to_string(&self) -> String {
        create_cel_expr(self)
    }
}

/// A certification CEL expression definition that uses the `default_certification` function.
///
/// [request_certification](DefaultCertification::request_certification) is used for configuring request certification, and
/// [response_certification](DefaultCertification::response_certification) is used for configuring response certification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultCertification<'a> {
    /// Options for configuring certification of a request.
    ///
    /// This is an [Option] to allow for opting in, or out of request certification.
    /// See [DefaultRequestCertification] for more details on its available parameters.
    pub request_certification: Option<DefaultRequestCertification<'a>>,

    /// Options for configuring certification of a response.
    ///
    /// This is not an [Option] because response certification is the minimum required
    /// when certifying a request and response pair.
    /// See [DefaultResponseCertification] for more details on its available parameters.
    pub response_certification: DefaultResponseCertification<'a>,
}

/// Options for configuring certification of a request.
///
/// The request method and body are always certified, but this struct allows configuring the
/// certification of request [headers](DefaultRequestCertification::headers) and
/// [query parameters](DefaultRequestCertification::query_parameters).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultRequestCertification<'a> {
    /// A list of request headers to include in certification.
    ///
    /// As many or as little headers can be provided as desired.
    /// Providing an empty list will result in no request headers being certified.
    pub headers: Cow<'a, [&'a str]>,

    /// A list of request query parameters to include in certification.
    ///
    /// As many or as little query parameters can be provided as desired.
    /// Providing an empty list will result in no request query parameters being certified.
    pub query_parameters: Cow<'a, [&'a str]>,
}

/// Options for configuring certification of a response.
///
/// The response body and status code are always certified, but this struct allows configuring the
/// certification of response headers. Response headers may be included using the
/// [CertifiedResponseHeaders](DefaultResponseCertification::CertifiedResponseHeaders) variant,
/// and response headers may be excluded using the
/// [ResponseHeaderExclusions](DefaultResponseCertification::ResponseHeaderExclusions) variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultResponseCertification<'a> {
    /// A list of response headers to include in certification.
    ///
    /// As many or as little headers can be provided as desired.
    /// Providing an empty list will result in no response headers being certified.
    CertifiedResponseHeaders(Cow<'a, [&'a str]>),

    /// A list of response headers to exclude from certification.
    ///
    /// As many or as little headers can be provided as desired.
    /// Providing an empty list will result in all response headers being certified.
    ResponseHeaderExclusions(Cow<'a, [&'a str]>),
}

impl<'a> DefaultResponseCertification<'a> {
    /// A list of response headers to include in certification.
    ///
    /// As many or as little headers can be provided as desired.
    /// Providing an empty list will result in no response headers being certified.
    pub fn certified_response_headers(headers: &'a [&'a str]) -> Self {
        Self::CertifiedResponseHeaders(Cow::Borrowed(headers))
    }

    /// A list of response headers to exclude from certification.
    ///
    /// As many or as little headers can be provided as desired.
    /// Providing an empty list will result in all response headers being certified.
    pub fn response_header_exclusions(headers: &'a [&'a str]) -> Self {
        Self::ResponseHeaderExclusions(Cow::Borrowed(headers))
    }
}

impl Default for DefaultResponseCertification<'_> {
    fn default() -> Self {
        DefaultResponseCertification::CertifiedResponseHeaders(Cow::Borrowed(&[]))
    }
}
