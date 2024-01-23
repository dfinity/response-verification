use crate::{HeaderField, HttpCertificationError, HttpCertificationResult};
use candid::{CandidType, Deserialize};
use http::Uri;

/// A Candid-encodable representation of an HTTP request.
/// This struct is used by canisters that implement the HTTP interface required by the HTTP Gateway Protocol.
#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct HttpRequest {
    /// HTTP request method.
    pub method: String,
    /// Request URL.
    pub url: String,
    /// HTTP request headers.
    pub headers: Vec<HeaderField>,
    /// Request body as an array of bytes.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Returns the path of the request URL, without domain, query parameters or fragments.
    pub fn get_path(&self) -> HttpCertificationResult<String> {
        let uri = self
            .url
            .parse::<Uri>()
            .map_err(|_| HttpCertificationError::MalformedUrl(self.url.clone()))?;

        let decoded_path = urlencoding::decode(uri.path()).map(|path| path.into_owned())?;
        Ok(decoded_path)
    }

    /// Returns the query parameters of the request URL, if any, as a string.
    pub fn get_query(&self) -> HttpCertificationResult<Option<String>> {
        self.url
            .parse::<Uri>()
            .map(|uri| uri.query().map(|uri| uri.to_owned()))
            .map_err(|_| HttpCertificationError::MalformedUrl(self.url.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_get_uri() {
        let req = HttpRequest {
            method: "GET".to_string(),
            url: "https://canister.com/sample-asset.txt".to_string(),
            headers: vec![],
            body: vec![],
        };

        let path = req.get_path().unwrap();
        let query = req.get_query().unwrap();

        assert_eq!(path, "/sample-asset.txt");
        assert!(query.is_none());
    }

    #[test]
    fn request_get_encoded_uri() {
        let test_requests = [
            (
                HttpRequest {
                    method: "GET".to_string(),
                    url: "https://canister.com/%73ample-asset.txt".to_string(),
                    headers: vec![],
                    body: vec![],
                },
                "/sample-asset.txt",
                "",
            ),
            (
                HttpRequest {
                    method: "GET".to_string(),
                    url: "https://canister.com/path/123?foo=test%20component&bar=1".to_string(),
                    headers: vec![],
                    body: vec![],
                },
                "/path/123",
                "foo=test%20component&bar=1",
            ),
            (
                HttpRequest {
                    method: "GET".to_string(),
                    url: "https://canister.com/a%20file.txt".to_string(),
                    headers: vec![],
                    body: vec![],
                },
                "/a file.txt",
                "",
            ),
            (
                HttpRequest {
                    method: "GET".to_string(),
                    url: "https://canister.com/mujin0722/3888-zjfrd-tqaaa-aaaaf-qakia-cai/%E6%97%A0%E8%AE%BA%E7%BE%8E%E8%81%94%E5%82%A8%E6%98%AF%E5%90%A6%E5%8A%A0%E6%81%AFbtc%E4%BB%8D%E5%B0%86%E5%9B%9E%E5%88%B07%E4%B8%87%E5%88%80".to_string(),
                    headers: vec![],
                    body: vec![],
                },
                "/mujin0722/3888-zjfrd-tqaaa-aaaaf-qakia-cai/无论美联储是否加息btc仍将回到7万刀",
                "",
            ),
        ];

        for (req, expected_path, expected_query) in test_requests.iter() {
            let path = req.get_path().unwrap();
            let query = req.get_query().unwrap();

            assert_eq!(path, *expected_path);
            assert_eq!(query.unwrap_or_default(), *expected_query);
        }
    }
}
