#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[cfg(target_arch = "wasm32")]
extern "C" {
    #[wasm_bindgen(js_namespace = console, js_name = log)]
    pub fn log_impl(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = warn)]
    pub fn warn_impl(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = trace)]
    pub fn trace_impl(s: &str);

    #[wasm_bindgen(js_namespace = console, js_name = trace)]
    pub fn error_impl(s: &str);
}

#[macro_export]
#[cfg(target_arch = "wasm32")]
macro_rules! log {
    ($($t:tt)*) => ($crate::logger::log_impl(&format_args!($($t)*).to_string()))
}

#[macro_export]
#[cfg(target_arch = "wasm32")]
macro_rules! warn {
    ($($t:tt)*) => ($crate::logger::warn_impl(&format_args!($($t)*).to_string()))
}

#[macro_export]
#[cfg(target_arch = "wasm32")]
macro_rules! trace {
    ($($t:tt)*) => ($crate::logger::trace_impl(&format_args!($($t)*).to_string()))
}

#[macro_export]
#[cfg(target_arch = "wasm32")]
macro_rules! error {
    ($($t:tt)*) => ($crate::logger::error_impl(&format_args!($($t)*).to_string()))
}

#[macro_export]
#[cfg(not(target_arch = "wasm32"))]
macro_rules! log {
    ($($arg:tt)*) => {{
        println!($($arg)*);
    }};
}

#[macro_export]
#[cfg(not(target_arch = "wasm32"))]
macro_rules! warn {
    ($($arg:tt)*) => {{
        println!($($arg)*);
    }};
}

#[macro_export]
#[cfg(not(target_arch = "wasm32"))]
macro_rules! trace {
    ($($arg:tt)*) => {{
        println!($($arg)*);
    }};
}

#[macro_export]
#[cfg(not(target_arch = "wasm32"))]
macro_rules! error {
    ($($arg:tt)*) => {{
        println!($($arg)*);
    }};
}
