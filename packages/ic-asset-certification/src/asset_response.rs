use ic_http_certification::HttpResponse;

use crate::ResponseHeader;
use std::borrow::Cow;

#[derive(Debug, Clone)]
pub struct AssetResponse<'a> {
    status_code: u16,
    body: Cow<'a, [u8]>,
    headers: Vec<ResponseHeader<'a>>,
}

impl<'a> AssetResponse<'a> {
    pub fn new<B, H>(status_code: u16, body: B, headers: impl IntoIterator<Item = H>) -> Self
    where
        B: Into<Cow<'a, [u8]>>,
        H: Into<ResponseHeader<'a>>,
    {
        AssetResponse {
            status_code,
            body: body.into(),
            headers: headers.into_iter().map(|e| e.into()).collect(),
        }
    }

    pub fn add_header(&mut self, header: impl Into<ResponseHeader<'a>>) {
        self.headers.push(header.into());
    }

    pub fn status_code(&self) -> u16 {
        self.status_code
    }

    pub fn body(&self) -> &[u8] {
        self.body.as_ref()
    }

    pub fn headers(&self) -> &[ResponseHeader<'a>] {
        self.headers.as_ref()
    }
}

impl Into<HttpResponse> for AssetResponse<'_> {
    fn into(self) -> HttpResponse {
        HttpResponse {
            status_code: self.status_code(),
            headers: self.headers().iter().map(|e| e.clone().into()).collect(),
            body: self.body().to_vec(),
            upgrade: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;

    #[rstest]
    fn asset_response_with_borrowed_values() {
        let status_code = 200;
        let body = b"<html><body><h1>Hello World!</h1></body></html>".as_slice();
        let headers = [("Content-Type", "application/json")].as_slice();

        let response: AssetResponse<'_> = AssetResponse::new(status_code, body, headers);

        assert_eq!(response.status_code(), status_code);
        assert_eq!(response.body(), body);
        assert_eq!(response.headers.len(), 1);
        assert_eq!(response.headers[0], headers[0].into());
    }

    #[rstest]
    fn asset_response_with_owned_values() {
        let status_code = 200;
        let body = b"<html><body><h1>Hello World!</h1></body></html>".to_vec();
        let headers = vec![("Content-Type".to_string(), "application/json".to_string())];

        let response: AssetResponse<'_> =
            AssetResponse::new(status_code, body.clone(), headers.clone());

        assert_eq!(response.status_code(), status_code);
        assert_eq!(response.body(), body.as_slice());
        assert_eq!(response.headers.len(), 1);
        assert_eq!(response.headers[0], headers[0].clone().into());
    }
}
