#[derive(thiserror::Error, Debug)]
pub enum ResponseVerificationError {
    /// The provided URL was invalid
    #[error(r#"Invalid url: "{0}""#)]
    InvalidUrl(String),

    /// The parsed hash tree was invalid
    #[error(r#"Invalid hash tree: "{0}""#)]
    InvalidHashTree(String),

    /// The parsed certificate was invalid
    #[error(r#"Invalid certificate: "{0}""#)]
    InvalidCertificate(String),

    /// The cbor was invalid
    #[error(r#"Invalid cbor: "{0}""#)]
    InvalidCbor(String),

    /// The hash tree pruned data was not valid
    #[error(r#"Invalid pruned data: "{0}""#)]
    InvalidPrunedData(#[from] std::array::TryFromSliceError),
}

#[cfg(target_arch = "wasm32")]
impl Into<wasm_bindgen::JsValue> for ResponseVerificationError {
    fn into(self) -> wasm_bindgen::JsValue {
        let error = js_sys::Error::new(&self.to_string());
        
        wasm_bindgen::JsValue::from(error)
    }
}
