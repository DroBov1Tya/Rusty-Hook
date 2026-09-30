//! rusty_hook panel (Leptos CSR).

mod api;
mod dom;
mod fmt;
mod state;
mod ui;

use wasm_bindgen::prelude::wasm_bindgen;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(ui::App);
}
