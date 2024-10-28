use crate::HeaderField;
use candid::{CandidType, Deserialize};
use std::{borrow::Cow, fmt::Debug};

/// A Candid-encodable representation of an HTTP response. This struct is used
/// by the `http_request` method of the HTTP Gateway Protocol's Candid interface.
///
/// # Examples
///
/// ```
/// use ic_http_certification::HttpResponse;
///
/// let response = HttpResponse::builder()
///     .with_status_code(200)
///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
///     .with_body(b"Hello, World!")
///     .with_upgrade(false)
///     .build();
///
/// assert_eq!(response.status_code(), 200);
/// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into())]);
/// assert_eq!(response.body(), b"Hello, World!");
/// assert_eq!(response.upgrade(), Some(false));
/// ```
#[derive(Clone, CandidType, Deserialize)]
pub struct HttpResponse<'a> {
    /// HTTP response status code.
    status_code: u16,

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
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(200)
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .with_body(b"Hello, World!")
    ///     .with_upgrade(false)
    ///     .build();
    ///
    /// assert_eq!(response.status_code(), 200);
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
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(200)
    ///     .build();
    ///
    /// assert_eq!(response.status_code(), 200);
    /// ```
    #[inline]
    pub fn status_code(&self) -> u16 {
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
/// use ic_http_certification::HttpResponse;
///
/// let response = HttpResponse::builder()
///     .with_status_code(200)
///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
///     .with_body(b"Hello, World!")
///     .with_upgrade(false)
///     .build();
///
/// assert_eq!(response.status_code(), 200);
/// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into())]);
/// assert_eq!(response.body(), b"Hello, World!");
/// assert_eq!(response.upgrade(), Some(false));
/// ```
#[derive(Debug, Clone, Default)]
pub struct HttpResponseBuilder<'a> {
    status_code: Option<u16>,
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
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(200)
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .with_body(b"Hello, World!")
    ///     .with_upgrade(false)
    ///     .build();
    ///
    /// assert_eq!(response.status_code(), 200);
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
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(200)
    ///     .build();
    ///
    /// assert_eq!(response.status_code(), 200);
    /// ```
    pub fn with_status_code(mut self, status_code: u16) -> Self {
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
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(200)
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .with_body(b"Hello, World!")
    ///     .with_upgrade(false)
    ///     .build();
    ///
    /// assert_eq!(response.status_code(), 200);
    /// assert_eq!(response.headers(), &[("Content-Type".into(), "text/plain".into())]);
    /// assert_eq!(response.body(), b"Hello, World!");
    /// assert_eq!(response.upgrade(), Some(false));
    /// ```
    pub fn build(self) -> HttpResponse<'a> {
        HttpResponse {
            status_code: self.status_code.unwrap_or(200),
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
    /// use ic_http_certification::{HttpResponse, HttpUpdateResponse};
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(200)
    ///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
    ///     .with_body(b"Hello, World!")
    ///     .build();
    ///
    /// let update_response = HttpUpdateResponse::from(response);
    ///
    /// assert_eq!(update_response.status_code(), 200);
    /// assert_eq!(update_response.headers(), &[("Content-Type".into(), "text/plain".into())]);
    /// assert_eq!(update_response.body(), b"Hello, World!");
    /// ```
    pub fn build_update(self) -> HttpUpdateResponse<'a> {
        HttpUpdateResponse {
            status_code: self.status_code.unwrap_or(200),
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
/// use ic_http_certification::{HttpResponse, HttpUpdateResponse};
///
/// let response = HttpResponse::builder()
///     .with_status_code(200)
///     .with_headers(vec![("Content-Type".into(), "text/plain".into())])
///     .with_body(b"Hello, World!")
///     .build();
///
/// let update_response = HttpUpdateResponse::from(response);
///
/// assert_eq!(update_response.status_code(), 200);
/// assert_eq!(update_response.headers(), &[("Content-Type".into(), "text/plain".into())]);
/// assert_eq!(update_response.body(), b"Hello, World!");
/// ```
#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct HttpUpdateResponse<'a> {
    /// HTTP response status code.
    status_code: u16,

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
    /// use ic_http_certification::HttpResponse;
    ///
    /// let response = HttpResponse::builder()
    ///     .with_status_code(200)
    ///     .build_update();
    ///
    /// assert_eq!(response.status_code(), 200);
    /// ```
    #[inline]
    pub fn status_code(&self) -> u16 {
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
