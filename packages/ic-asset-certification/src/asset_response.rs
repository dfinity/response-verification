use ic_http_certification::{HeaderField, HttpResponse};
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub(crate) struct AssetResponse<'a> {
    pub status_code: u16,
    pub body: Cow<'a, [u8]>,
    pub headers: Vec<HeaderField>,
}

impl<'a> AssetResponse<'a> {
    pub fn new<H>(
        status_code: u16,
        body: impl Into<Cow<'a, [u8]>>,
        headers: impl IntoIterator<Item = H>,
    ) -> Self
    where
        H: Into<HeaderField>,
    {
        AssetResponse {
            status_code,
            body: body.into(),
            headers: headers.into_iter().map(|e| e.into()).collect(),
        }
    }
}

impl<'a> From<AssetResponse<'a>> for HttpResponse<'a> {
    fn from(response: AssetResponse<'a>) -> Self {
        HttpResponse::builder()
            .with_status_code(response.status_code)
            .with_headers(response.headers)
            .with_body(response.body)
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    fn asset_response_with_borrowed_body() {
        let status_code = 200;
        let body = b"<html><body><h1>Hello World!</h1></body></html>".as_slice();
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        let response: AssetResponse<'_> = AssetResponse::new(status_code, body, headers.clone());

        assert_eq!(response.status_code, status_code);
        assert_eq!(response.body, body);
        assert_eq!(response.headers.len(), 1);
        assert_eq!(response.headers[0], headers[0].clone());
    }

    #[rstest]
    fn asset_response_with_owned_body() {
        let status_code = 200;
        let body = b"<html><body><h1>Hello World!</h1></body></html>".to_vec();
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        let response: AssetResponse<'_> =
            AssetResponse::new(status_code, body.clone(), headers.clone());

        assert_eq!(response.status_code, status_code);
        assert_eq!(response.body, body.as_slice());
        assert_eq!(response.headers.len(), 1);
        assert_eq!(response.headers[0], headers[0].clone());
    }

    #[rstest]
    fn asset_response_into_http_response() {
        let status_code = 200;
        let body = b"<html><body><h1>Hello World!</h1></body></html>".as_slice();
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        let response: AssetResponse<'_> = AssetResponse::new(status_code, body, headers.clone());
        let http_response: HttpResponse = response.into();

        assert_eq!(http_response.status_code(), status_code);
        assert_eq!(http_response.body(), body);
        assert_eq!(http_response.headers().len(), 1);
        assert_eq!(
            http_response.headers()[0],
            (headers[0].0.to_string(), headers[0].1.to_string())
        );
    }
}
