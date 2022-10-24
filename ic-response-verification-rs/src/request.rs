#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use serde::{Deserialize, Serialize};

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(typescript_custom_section)]
const REQUEST: &'static str = r#"
interface Request {
    headers: [string, string][];
}
"#;

/// Represents a Request from the IC
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub headers: Vec<(String, String)>,
}
