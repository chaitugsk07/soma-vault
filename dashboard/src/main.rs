//! soma-vault admin portal (Leptos 0.8 CSR). Mounts the SPA entry point.

mod api;
mod app;
mod pages;
mod util;

fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
