#[cfg(target_arch = "wasm32")]
pub fn get_current_timestamp() -> u128 {
    js_sys::Date::now() as u128 * 1_000_000
}

#[cfg(not(target_arch = "wasm32"))]
pub fn get_current_timestamp() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
}
