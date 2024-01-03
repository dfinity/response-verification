use super::{
    create_cel_expr, create_default_cel_expr, create_default_full_cel_expr,
    create_default_response_only_cel_expr,
};
use std::borrow::Cow;

/// A certification CEL expression defintion.
/// Contains an enum variant for each CEL function supported for certification.
/// Currently only one variant is supported: [CelExpression::Default].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CelExpression<'a> {
    /// A certification CEL expression definition that uses the `default_certification` function.
    /// This is currently the only supported function.
    ///
    /// The enum's inner value is an [Option] to allow for opting in, or out of certification.
    /// Providing [None] will opt out of certification, while providing [Some] will opt in to certification.
    /// See [DefaultCelExpression] for more details on its available parameters.
    Default(DefaultCelExpression<'a>),
}

impl<'a> CelExpression<'a> {
    /// Converts a [CelExpression] object into it's [String] representation.
    /// Alias of [create_cel_expr](create_cel_expr()).
    pub fn to_string(&self) -> String {
        create_cel_expr(self)
    }
}

/// A certification CEL expression definition that uses the default CEL function.
///
/// This enum has three variants:
///
/// - The [Full](DefaultCelExpression::Full) variant includes both the [HTTP request](crate::HttpRequest) and the
/// corresponding [HTTP response](crate::HttpResponse) in certification. See the [DefaultFullCelExpression] struct
/// for details on how to configure this variant.
///
/// - The [ResponseOnly](DefaultCelExpression::ResponseOnly) variant includes the
/// [HTTP response](crate::HttpResponse) in certification, but excludes the corresponding
/// [HTTP request](crate::HttpRequest) from certification. See the [DefaultResponseOnlyCelExpression] struct for
/// details on how to configure this variant.
///
/// - The [Skip](DefaultCelExpression::Skip) variant excludes both the [HTTP request](crate::HttpRequest) and the
/// corresponding [HTTP response](crate::HttpResponse) from certification. This variant does not require any
/// configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultCelExpression<'a> {
    /// Includes both the [HTTP request](crate::HttpRequest) and the corresponding
    /// [HTTP response](crate::HttpResponse) in certification.
    Full(DefaultFullCelExpression<'a>),

    /// Includes an [HTTP response](crate::HttpResponse) in certification, but excludes the corresponding
    /// [HTTP request](crate::HttpRequest) from certification.
    ResponseOnly(DefaultResponseOnlyCelExpression<'a>),

    /// Skips certification entirely by excluding both the [HTTP request](crate::HttpRequest) and
    /// [HTTP response](crate::HttpResponse) from certification.
    Skip,
}

impl<'a> DefaultCelExpression<'a> {
    /// Converts a [DefaultCelExpression] object into it's [String] representation.
    ///
    /// Alias of [create_default_cel_expr](create_default_cel_expr()).
    pub fn to_string(&self) -> String {
        create_default_cel_expr(self)
    }
}

/// Options for configuring a CEL expression that includes only the [HTTP response](crate::HttpResponse) in
/// certification and excludes the [HTTP request](crate::HttpRequest) from certification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultResponseOnlyCelExpression<'a> {
    /// Options for configuring response certification for this CEL expression.
    /// See [DefaultResponseCertification] for details on how to configure response certification.
    pub response: DefaultResponseCertification<'a>,
}

impl<'a> DefaultResponseOnlyCelExpression<'a> {
    /// Converts a [DefaultResponseOnlyCelExpression] object into it's [String] representation.
    ///
    /// Alias of [create_default_response_only_cel_expr](create_default_response_only_cel_expr()).
    pub fn to_string(&self) -> String {
        create_default_response_only_cel_expr(self)
    }
}

/// Options for configuring a CEL expression that includes both the [HTTP response](crate::HttpResponse) and
/// [HTTP request](crate::HttpRequest) in certification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultFullCelExpression<'a> {
    /// Options for configuring request certification for this CEL expression.
    /// See [DefaultRequestCertification] for details on how to configure request certification.
    pub request: DefaultRequestCertification<'a>,

    /// Options for configuring response certification for this CEL expression.
    /// See [DefaultResponseCertification] for details on how to configure response certification.
    pub response: DefaultResponseCertification<'a>,
}

impl<'a> DefaultFullCelExpression<'a> {
    /// Converts a [DefaultFullCelExpression] object into it's [String] representation.
    /// Alias of [create_default_full_cel_expr](create_default_full_cel_expr()).
    pub fn to_string(&self) -> String {
        create_default_full_cel_expr(self)
    }
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
    ///
    /// See [certified_response_headers](DefaultResponseCertification::certified_response_headers())
    /// for a more ergonomic way of doing this.
    CertifiedResponseHeaders(Cow<'a, [&'a str]>),

    /// A list of response headers to exclude from certification.
    ///
    /// As many or as little headers can be provided as desired.
    /// Providing an empty list will result in all response headers being certified.
    ///
    /// See [response_header_exclusions](DefaultResponseCertification::response_header_exclusions())
    /// for a more ergonomic way of doing this.
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
