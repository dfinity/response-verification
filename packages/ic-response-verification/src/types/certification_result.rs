use crate::types::Response;
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(typescript_custom_section)]
const CERTIFICATION_RESULT_TYPE: &'static str = r#"
interface CertificationResult {
  passed: boolean;
  response: Response;
}
"#;

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct CertificationResult {
    pub passed: bool,
    pub response: Option<Response>,
}
