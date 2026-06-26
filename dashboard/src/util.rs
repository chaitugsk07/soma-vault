//! Small browser utilities shared across pages.
use leptos::prelude::Set;

/// Format an ISO-8601 timestamp as a human-readable relative string.
/// The full ISO string belongs in a `title` tooltip on the wrapper element.
///
/// Example: "2026-06-26T01:17:09.586573Z" → "3 minutes ago"
pub fn relative_time(iso: &str) -> String {
    let then_ms = match parse_iso_to_ms(iso) {
        Some(v) => v,
        None => return iso.to_string(),
    };
    // js_sys::Date::now() → f64 milliseconds since epoch.
    let now_ms = js_sys::Date::now();
    let delta_secs = ((now_ms - then_ms) / 1000.0) as i64;

    if delta_secs < 60 {
        return "just now".to_string();
    }
    let mins = delta_secs / 60;
    if mins < 60 {
        return plural(mins, "minute");
    }
    let hours = mins / 60;
    if hours < 24 {
        return plural(hours, "hour");
    }
    let days = hours / 24;
    if days < 30 {
        return plural(days, "day");
    }
    let months = days / 30;
    if months < 12 {
        return plural(months, "month");
    }
    plural(months / 12, "year")
}

fn plural(n: i64, unit: &str) -> String {
    if n == 1 {
        format!("1 {} ago", unit)
    } else {
        format!("{} {}s ago", n, unit)
    }
}

/// Parse an ISO-8601 string into milliseconds since epoch via `js_sys::Date`.
fn parse_iso_to_ms(iso: &str) -> Option<f64> {
    let ms = js_sys::Date::parse(iso);
    if ms.is_nan() {
        None
    } else {
        Some(ms)
    }
}

/// Copy `text` to the clipboard. Sets `label` to "Copied!" for 2 seconds.
pub fn copy_to_clipboard(text: String, label: leptos::prelude::RwSignal<&'static str>) {
    leptos::task::spawn_local(async move {
        if let Some(window) = web_sys::window() {
            let promise = window.navigator().clipboard().write_text(&text);
            let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
        }
        label.set("Copied!");
        gloo_timers::future::TimeoutFuture::new(2_000).await;
        label.set("Copy");
    });
}
