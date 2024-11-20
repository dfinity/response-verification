use crate::{HeaderField, HttpCertificationError, HttpCertificationResult};
use candid::{
    types::{Serializer, Type, TypeInner},
    CandidType, Deserialize,
};
use std::{borrow::Cow, fmt::Debug};

/// An enumeration of all possible HTTP status codes.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum HttpStatusCode {
    /// 100 Continue
    Continue = 100,
    /// 101 Switching Protocols
    SwitchingProtocols = 101,
    /// 102 Processing
    Processing = 102,
    /// 103 Early Hints
    EarlyHints = 103,
    /// 200 OK
    Ok = 200,
    /// 201 Created
    Created = 201,
    /// 202 Accepted
    Accepted = 202,
    /// 203 Non-Authoritative Information
    NonAuthoritativeInformation = 203,
    /// 204 No Content
    NoContent = 204,
    /// 205 Reset Content
    ResetContent = 205,
    /// 206 Partial Content
    PartialContent = 206,
    /// 207 Multi-Status
    MultiStatus = 207,
    /// 208 Already Reported
    AlreadyReported = 208,
    /// 226 IM Used
    ImUsed = 226,
    /// 300 Multiple Choices
    MultipleChoices = 300,
    /// 301 Moved Permanently
    MovedPermanently = 301,
    /// 302 Found
    Found = 302,
    /// 303 See Other
    SeeOther = 303,
    /// 304 Not Modified
    NotModified = 304,
    /// 305 Use Proxy
    UseProxy = 305,
    /// 306 Switch Proxy
    /// Note that this is a reserved and currently unused statis code.
    SwitchProxy = 306,
    /// 307 Temporary Redirect
    TemporaryRedirect = 307,
    /// 308 Permanent Redirect
    PermanentRedirect = 308,
    /// 400 Bad Request
    BadRequest = 400,
    /// 401 Unauthorized
    Unauthorized = 401,
    /// 402 Payment Required
    PaymentRequired = 402,
    /// 403 Forbidden
    Forbidden = 403,
    /// 404 Not Found
    NotFound = 404,
    /// 405 Method Not Allowed
    MethodNotAllowed = 405,
    /// 406 Not Acceptable
    NotAcceptable = 406,
    /// 407 Proxy Authentication Required
    ProxyAuthenticationRequired = 407,
    /// 408 Request Timeout
    RequestTimeout = 408,
    /// 409 Conflict
    Conflict = 409,
    /// 410 Gone
    Gone = 410,
    /// 411 Length Required
    LengthRequired = 411,
    /// 412 Precondition Failed
    PreconditionFailed = 412,
    /// 413 Content Too Large
    ContentTooLarge = 413,
    /// 414 URI Too Long
    UriTooLong = 414,
    /// 415 Unsupported Media Type
    UnsupportedMediaType = 415,
    /// 416 Range Not Satisfiable
    RangeNotSatisfiable = 416,
    /// 417 Expectation Failed
    ExpectationFailed = 417,
    /// 418 I'm a teapot
    ImATeapot = 418,
    /// 421 Misdirected Request
    MisdirectedRequest = 421,
    /// 422 Unprocessable Content
    UnprocessableContent = 422,
    /// 423 Locked
    Locked = 423,
    /// 424 Failed Dependency
    FailedDependency = 424,
    /// 425 Too Early
    TooEarly = 425,
    /// 426 Upgrade Required
    UpgradeRequired = 426,
    /// 428 Precondition Required
    PreconditionRequired = 428,
    /// 429 Too Many Requests
    TooManyRequests = 429,
    /// 431 Request Header Fields Too Large
    RequestHeaderFieldsTooLarge = 431,
    /// 451 Unavailable For Legal Reasons
    UnavailableForLegalReasons = 451,
    /// 500 Internal Server Error
    InternalServerError = 500,
    /// 501 Not Implemented
    NotImplemented = 501,
    /// 502 Bad Gateway
    BadGateway = 502,
    /// 503 Service Unavailable
    ServiceUnavailable = 503,
    /// 504 Gateway Timeout
    GatewayTimeout = 504,
    /// 505 HTTP Version Not Supported
    HttpVersionNotSupported = 505,
    /// 506 Variant Also Negotiates
    VariantAlsoNegotiates = 506,
    /// 507 Insufficient Storage
    InsufficientStorage = 507,
    /// 508 Loop Detected
    LoopDetected = 508,
    /// 510 Not Extended
    NotExtended = 510,
    /// 511 Network Authentication Required
    NetworkAuthenticationRequired = 511,
}

impl CandidType for HttpStatusCode {
    fn _ty() -> Type {
        TypeInner::Nat16.into()
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: Serializer,
    {
        (*self as u16).idl_serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HttpStatusCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u16::deserialize(deserializer).and_then(|status_code| {
            HttpStatusCode::try_from(status_code)
                .map_err(|_| serde::de::Error::custom("Invalid HTTP Status Code."))
        })
    }
}

impl From<HttpStatusCode> for u64 {
    fn from(status_code: HttpStatusCode) -> u64 {
        status_code as u64
    }
}

impl From<HttpStatusCode> for u16 {
    fn from(status_code: HttpStatusCode) -> u16 {
        status_code as u16
    }
}

impl TryFrom<u16> for HttpStatusCode {
    type Error = HttpCertificationError;

    fn try_from(value: u16) -> HttpCertificationResult<Self> {
        match value {
            100 => Ok(Self::Continue),
            101 => Ok(Self::SwitchingProtocols),
            102 => Ok(Self::Processing),
            103 => Ok(Self::EarlyHints),
            200 => Ok(Self::Ok),
            201 => Ok(Self::Created),
            202 => Ok(Self::Accepted),
            203 => Ok(Self::NonAuthoritativeInformation),
            204 => Ok(Self::NoContent),
            205 => Ok(Self::ResetContent),
            206 => Ok(Self::PartialContent),
            207 => Ok(Self::MultiStatus),
            208 => Ok(Self::AlreadyReported),
            226 => Ok(Self::ImUsed),
            300 => Ok(Self::MultipleChoices),
            301 => Ok(Self::MovedPermanently),
            302 => Ok(Self::Found),
            303 => Ok(Self::SeeOther),
            304 => Ok(Self::NotModified),
            305 => Ok(Self::UseProxy),
            306 => Ok(Self::SwitchProxy),
            307 => Ok(Self::TemporaryRedirect),
            308 => Ok(Self::PermanentRedirect),
            400 => Ok(Self::BadRequest),
            401 => Ok(Self::Unauthorized),
            402 => Ok(Self::PaymentRequired),
            403 => Ok(Self::Forbidden),
            404 => Ok(Self::NotFound),
            405 => Ok(Self::MethodNotAllowed),
            406 => Ok(Self::NotAcceptable),
            407 => Ok(Self::ProxyAuthenticationRequired),
            408 => Ok(Self::RequestTimeout),
            409 => Ok(Self::Conflict),
            410 => Ok(Self::Gone),
            411 => Ok(Self::LengthRequired),
            412 => Ok(Self::PreconditionFailed),
            413 => Ok(Self::ContentTooLarge),
            414 => Ok(Self::UriTooLong),
            415 => Ok(Self::UnsupportedMediaType),
            416 => Ok(Self::RangeNotSatisfiable),
            417 => Ok(Self::ExpectationFailed),
            418 => Ok(Self::ImATeapot),
            421 => Ok(Self::MisdirectedRequest),
            422 => Ok(Self::UnprocessableContent),
            423 => Ok(Self::Locked),
            424 => Ok(Self::FailedDependency),
            425 => Ok(Self::TooEarly),
            426 => Ok(Self::UpgradeRequired),
            428 => Ok(Self::PreconditionRequired),
            429 => Ok(Self::TooManyRequests),
            431 => Ok(Self::RequestHeaderFieldsTooLarge),
            451 => Ok(Self::UnavailableForLegalReasons),
            500 => Ok(Self::InternalServerError),
            501 => Ok(Self::NotImplemented),
            502 => Ok(Self::BadGateway),
            503 => Ok(Self::ServiceUnavailable),
            504 => Ok(Self::GatewayTimeout),
            505 => Ok(Self::HttpVersionNotSupported),
            506 => Ok(Self::VariantAlsoNegotiates),
            507 => Ok(Self::InsufficientStorage),
            508 => Ok(Self::LoopDetected),
            510 => Ok(Self::NotExtended),
            511 => Ok(Self::NetworkAuthenticationRequired),
            _ => Err(HttpCertificationError::InvalidHttpStatusCode { status_code: value }),
        }
    }
}

/// A Candid-encodable representation of an HTTP response. This struct is used
/// by the `http_request` method of the HTTP Gateway Protocol's Candid interface.
///
/// # Examples
///
/// ```
/// use ic_http_certification::{HttpResponse, HttpStatusCode};
///
/// let response = HttpResponse::builder()
///     .with_status_code(HttpStatusCode::Ok)
///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
///     .with_body(b"Hello, World!")
///     .with_upgrade(false)
///     .build();
///
/// assert_eq!(response.status_code(), HttpStatusCode::Ok);
/// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into())]);
/// assert_eq!(response.body(), b"Hello, World!");
/// assert_eq!(response.upgrade(), Some(false));
/// ```
#[derive(Clone, CandidType, Deserialize)]
pub struct HttpResponse<'a> {
    /// HTTP response status code.
    status_code: HttpStatusCode,

    /// HTTP response headers.
    headers: Vec<HeaderField>,

    /// HTTP response body as an array of bytes.
    body: Cow<'a, [u8]>,

    /// Whether the corresponding HTTP request should be upgraded to an update
    /// call.
    upgrade: Option<bool>,
}

impl<'a> HttpResponse<'a> {
    /// Creates and returns an instance of [HttpResponseBuilder], a builder-style
    /// object that can be used to construct an [HttpResponse].
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::{HttpResponse, HttpStatusCode};
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(HttpStatusCode::Ok)
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .with_body(b"Hello, World!")
    ///     .with_upgrade(false)
    ///     .build();
    ///
    /// assert_eq!(response.status_code(), HttpStatusCode::Ok);
    /// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into())]);
    /// assert_eq!(response.body(), b"Hello, World!");
    /// assert_eq!(response.upgrade(), Some(false));
    /// ```
    #[inline]
    pub fn builder() -> HttpResponseBuilder<'a> {
        HttpResponseBuilder::new()
    }

    /// Returns the HTTP status code of the response.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::{HttpResponse, HttpStatusCode};
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(HttpStatusCode::Ok)
    ///     .build();
    ///
    /// assert_eq!(response.status_code(), HttpStatusCode::Ok);
    /// ```
    #[inline]
    pub fn status_code(&self) -> HttpStatusCode {
        self.status_code
    }

    /// Returns the HTTP headers of the response.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .build();
    ///
    /// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into())]);
    /// ```
    #[inline]
    pub fn headers(&self) -> &[HeaderField] {
        &self.headers
    }

    /// Returns a mutable reference to the HTTP headers of the response.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let mut response = HttpResponse::builder()
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .build();
    ///
    /// response.headers_mut().push(("Content-Length".into(), "13".into()));
    ///
    /// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into()), ("Content-Length".into(), "13".into())]);
    /// ```
    #[inline]
    pub fn headers_mut(&mut self) -> &mut Vec<HeaderField> {
        &mut self.headers
    }

    /// Adds an additional header to the HTTP response.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let mut response = HttpResponse::builder()
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .build();
    ///
    /// response.add_header(("Content-Length".into(), "13".into()));
    ///
    /// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into()), ("Content-Length".into(), "13".into())]);
    /// ```
    #[inline]
    pub fn add_header(&mut self, header: HeaderField) {
        self.headers.push(header);
    }

    /// Returns the HTTP body of the response.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_body(b"Hello, World!")
    ///     .build();
    ///
    /// assert_eq!(response.body(), b"Hello, World!");
    /// ```
    #[inline]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns the upgrade flag of the response. This will determine if the HTTP Gateway will
    /// upgrade the request to an update call.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_upgrade(true)
    ///     .build();
    ///
    /// assert_eq!(response.upgrade(), Some(true));
    /// ```
    #[inline]
    pub fn upgrade(&self) -> Option<bool> {
        self.upgrade
    }
}

/// An HTTP response builder.
///
/// This type can be used to construct an instance of an [HttpResponse] using a builder-like
/// pattern.
///
/// # Examples
///
/// ```
/// use ic_http_certification::{HttpResponse, HttpStatusCode};
///
/// let response = HttpResponse::builder()
///     .with_status_code(HttpStatusCode::Ok)
///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
///     .with_body(b"Hello, World!")
///     .with_upgrade(false)
///     .build();
///
/// assert_eq!(response.status_code(), HttpStatusCode::Ok);
/// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into())]);
/// assert_eq!(response.body(), b"Hello, World!");
/// assert_eq!(response.upgrade(), Some(false));
/// ```
#[derive(Debug, Clone, Default)]
pub struct HttpResponseBuilder<'a> {
    status_code: Option<HttpStatusCode>,
    headers: Vec<HeaderField>,
    body: Cow<'a, [u8]>,
    upgrade: Option<bool>,
}

impl<'a> HttpResponseBuilder<'a> {
    /// Creates a new instance of the [HttpResponseBuilder] that can be used to
    /// constract an [HttpResponse].
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::{HttpResponse, HttpStatusCode};
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(HttpStatusCode::Ok)
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .with_body(b"Hello, World!")
    ///     .with_upgrade(false)
    ///     .build();
    ///
    /// assert_eq!(response.status_code(), HttpStatusCode::Ok);
    /// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into())]);
    /// assert_eq!(response.body(), b"Hello, World!");
    /// assert_eq!(response.upgrade(), Some(false));
    /// ```
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the status code of the HTTP response.
    ///
    /// By default, the status code will be set to `200`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::{HttpResponse, HttpStatusCode};
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(HttpStatusCode::Ok)
    ///     .build();
    ///
    /// assert_eq!(response.status_code(), HttpStatusCode::Ok);
    /// ```
    pub fn with_status_code(mut self, status_code: HttpStatusCode) -> Self {
        self.status_code = Some(status_code);

        self
    }

    /// Sets the headers of the HTTP response.
    ///
    /// By default, the headers will be set to an empty array.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .build();
    ///
    /// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into())]);
    /// ```
    pub fn with_headers(mut self, headers: Vec<HeaderField>) -> Self {
        self.headers = headers;

        self
    }

    /// Sets the body of the HTTP response.
    ///
    /// This function will accept both owned and borrowed values. By default,
    /// the body will be set to an empty array.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_body(b"Hello, World!")
    ///     .build();
    ///
    /// assert_eq!(response.body(), b"Hello, World!");
    /// ```
    pub fn with_body(mut self, body: impl Into<Cow<'a, [u8]>>) -> Self {
        self.body = body.into();

        self
    }

    /// Sets the upgrade flag of the HTTP response. This will determine if the HTTP Gateway will
    /// upgrade the request to an update call.
    ///
    /// By default, the upgrade flag will be set to `None`, which is the same as `Some(false)`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_upgrade(true)
    ///     .build();
    ///
    /// assert_eq!(response.upgrade(), Some(true));
    /// ```
    pub fn with_upgrade(mut self, upgrade: bool) -> Self {
        self.upgrade = Some(upgrade);

        self
    }

    /// Build an [HttpResponse] from the builder.
    ///
    /// If the status code is not set, it will default to `200`.
    /// If the upgrade flag is not set, it will default to `None`.
    /// If the headers or body are not set, they will default to empty arrays.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::{HttpResponse, HttpStatusCode};
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(HttpStatusCode::Ok)
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .with_body(b"Hello, World!")
    ///     .with_upgrade(false)
    ///     .build();
    ///
    /// assert_eq!(response.status_code(), HttpStatusCode::Ok);
    /// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into())]);
    /// assert_eq!(response.body(), b"Hello, World!");
    /// assert_eq!(response.upgrade(), Some(false));
    /// ```
    pub fn build(self) -> HttpResponse<'a> {
        HttpResponse {
            status_code: self.status_code.unwrap_or(HttpStatusCode::Ok),
            headers: self.headers,
            body: self.body,
            upgrade: self.upgrade,
        }
    }

    /// Build an [HttpUpdateResponse] from the builder.
    ///
    /// If the status code is not set, it will default to `200`.
    /// If the headers or body are not set, they will default to empty arrays.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::{HttpResponse, HttpUpdateResponse, HttpStatusCode};
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(HttpStatusCode::Ok)
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .with_body(b"Hello, World!")
    ///     .build();
    ///
    /// let update_response = HttpUpdateResponse::from(response);
    ///
    /// assert_eq!(update_response.status_code(), HttpStatusCode::Ok);
    /// assert_eq!(update_response.headers(), &[("Content-Type".into(), "text/plain".into())]);
    /// assert_eq!(update_response.body(), b"Hello, World!");
    /// ```
    pub fn build_update(self) -> HttpUpdateResponse<'a> {
        HttpUpdateResponse {
            status_code: self.status_code.unwrap_or(HttpStatusCode::Ok),
            headers: self.headers,
            body: self.body,
        }
    }
}

impl<'a> From<HttpResponse<'a>> for HttpResponseBuilder<'a> {
    fn from(response: HttpResponse<'a>) -> Self {
        Self {
            status_code: Some(response.status_code),
            headers: response.headers,
            body: response.body,
            upgrade: response.upgrade,
        }
    }
}

impl PartialEq for HttpResponse<'_> {
    fn eq(&self, other: &Self) -> bool {
        let mut a_headers = self.headers().to_vec();
        a_headers.sort();

        let mut b_headers = other.headers().to_vec();
        b_headers.sort();

        self.status_code == other.status_code
            && a_headers == b_headers
            && self.body == other.body
            && self.upgrade == other.upgrade
    }
}

impl Debug for HttpResponse<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Truncate body to 100 characters for debug output
        let max_body_len = 100;
        let formatted_body = if self.body.len() > max_body_len {
            format!("{:?}...", &self.body[..max_body_len])
        } else {
            format!("{:?}", &self.body)
        };

        f.debug_struct("HttpResponse")
            .field("status_code", &self.status_code)
            .field("headers", &self.headers)
            .field("body", &formatted_body)
            .field("upgrade", &self.upgrade)
            .finish()
    }
}

/// A Candid-encodable representation of an HTTP update response. This struct is used
/// by the `http_update_request` method of the HTTP Gateway Protocol.
///
/// This is the same as [HttpResponse], excluding the
/// [upgrade](HttpResponse::upgrade) field.
///
/// # Examples
///
/// ```
/// use ic_http_certification::{HttpResponse, HttpUpdateResponse, HttpStatusCode};
///
/// let response = HttpResponse::builder()
///     .with_status_code(HttpStatusCode::Ok)
///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
///     .with_body(b"Hello, World!")
///     .build();
///
/// let update_response = HttpUpdateResponse::from(response);
///
/// assert_eq!(update_response.status_code(), HttpStatusCode::Ok);
/// assert_eq!(update_response.headers(), &[("Content-Type".into(), "text/plain".into())]);
/// assert_eq!(update_response.body(), b"Hello, World!");
/// ```
#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct HttpUpdateResponse<'a> {
    /// HTTP response status code.
    status_code: HttpStatusCode,

    /// HTTP response headers.
    headers: Vec<HeaderField>,

    /// HTTP response body as an array of bytes.
    body: Cow<'a, [u8]>,
}

impl<'a> HttpUpdateResponse<'a> {
    /// Returns the HTTP status code of the response.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::{HttpResponse, HttpStatusCode};
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(HttpStatusCode::Ok)
    ///     .build_update();
    ///
    /// assert_eq!(response.status_code(), HttpStatusCode::Ok);
    /// ```
    #[inline]
    pub fn status_code(&self) -> HttpStatusCode {
        self.status_code
    }

    /// Returns the HTTP headers of the response.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .build_update();
    ///
    /// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into())]);
    /// ```
    #[inline]
    pub fn headers(&self) -> &[HeaderField] {
        &self.headers
    }

    /// Returns a mutable reference to the HTTP headers of the response.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let mut response = HttpResponse::builder()
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .build_update();
    ///
    /// response.headers_mut().push(("Content-Length".into(), "13".into()));
    ///
    /// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into()), ("Content-Length".into(), "13".into())]);
    /// ```
    #[inline]
    pub fn headers_mut(&mut self) -> &mut Vec<HeaderField> {
        &mut self.headers
    }

    /// Adds an additional header to the HTTP response.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let mut response = HttpResponse::builder()
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .build_update();
    ///
    /// response.add_header(("Content-Length".into(), "13".into()));
    ///
    /// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into()), ("Content-Length".into(), "13".into())]);
    /// ```
    #[inline]
    pub fn add_header(&mut self, header: HeaderField) {
        self.headers.push(header);
    }

    /// Returns the HTTP body of the response.
    ///
    /// # Examples
    ///
    /// ```
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_body(b"Hello, World!")
    ///     .build_update();
    ///
    /// assert_eq!(response.body(), b"Hello, World!");
    /// ```
    #[inline]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl<'a> From<HttpResponse<'a>> for HttpUpdateResponse<'a> {
    fn from(response: HttpResponse<'a>) -> Self {
        Self {
            status_code: response.status_code,
            headers: response.headers,
            body: response.body,
        }
    }
}
