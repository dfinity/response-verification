#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use serde::{Deserialize, Serialize};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(typescript_custom_section)]
const RESPONSE: &'static str = r#"
interface Response {
    headers: [string, string][];
}
"#;

/// Represents a Response from the IC
#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
    pub headers: Vec<(String, String)>,
}
