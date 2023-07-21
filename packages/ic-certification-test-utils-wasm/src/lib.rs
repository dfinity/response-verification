use wasm_bindgen::prelude::*;

pub mod certificate_builder;

mod certificate;
mod encoding;
mod error;
mod signature;
mod tree;

#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Info);
}
