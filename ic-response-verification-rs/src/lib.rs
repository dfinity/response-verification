#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

pub mod certificate_header;
mod certificate_header_field;
mod logger;

use certificate_header::CertificateHeader;

#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = parseCertificateHeader))]
pub fn parse_certificate_header(header_value: String) -> CertificateHeader {
    CertificateHeader::from(header_value.as_str())
}
