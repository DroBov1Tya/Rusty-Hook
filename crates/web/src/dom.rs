//! Browser glue: location, clipboard, time, live stream.

use std::{cell::Cell, rc::Rc, time::Duration};

use leptos::prelude::*;
use shared::{EVENT_HIT, EVENT_RESYNC, RequestSummary};
use uuid::Uuid;
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use web_sys::{EventSource, MessageEvent};

use crate::state::Ctx;

const RECONNECT_DELAY: Duration = Duration::from_secs(3);

pub fn hook_url(id: Uuid) -> String {
    let origin = window().location().origin().unwrap_or_default();
    format!("{origin}/h/{id}")
}

pub fn hash_id() -> Option<Uuid> {
    let hash = window().location().hash().ok()?;
    Uuid::try_parse(hash.trim_start_matches('#')).ok()
}

pub fn set_hash(id: Option<Uuid>) {
    let value = id.map(|id| format!("#{id}")).unwrap_or_default();
    let _ = window().location().set_hash(&value);
}

pub fn confirm(message: &str) -> bool {
    window().confirm_with_message(message).unwrap_or(false)
}

pub fn decode(s: &str) -> String {
    js_sys::decode_uri_component(s).map(String::from).unwrap_or_else(|_| s.to_owned())
}

/// True when the user is typing; keyboard shortcuts stay out of the way.
pub fn typing() -> bool {
    document().active_element().is_some_and(|el| matches!(el.tag_name().as_str(), "INPUT" | "TEXTAREA" | "SELECT"))
}

fn date(ms: i64) -> js_sys::Date {
    // i64 ms fits f64 exactly for any realistic date.
    #[allow(clippy::cast_precision_loss)]
    js_sys::Date::new(&JsValue::from_f64(ms as f64))
}

pub fn time(ms: i64) -> String {
    String::from(date(ms).to_locale_time_string("en-GB"))
}

pub fn datetime(ms: i64) -> String {
    let d = date(ms);
    format!("{} {}", String::from(d.to_locale_date_string("en-CA", &JsValue::UNDEFINED)), time(ms))
}

pub fn copy(ctx: Ctx, text: String, what: &'static str) {
    leptos::task::spawn_local(async move {
        let promise = window().navigator().clipboard().write_text(&text);
        match wasm_bindgen_futures::JsFuture::from(promise).await {
            Ok(_) => ctx.notify(format!("{what} copied")),
            Err(_) => ctx.notify("Clipboard is blocked (needs https or localhost)".into()),
        }
    });
}

/// Live feed over SSE. Reconnects on drop and resyncs whatever was missed.
pub fn connect_stream(ctx: Ctx) {
    let Ok(es) = EventSource::new("/api/stream") else {
        ctx.live.set(false);
        return;
    };
    let reopened = Rc::new(Cell::new(false));

    let on_open = Closure::<dyn FnMut()>::new({
        let reopened = Rc::clone(&reopened);
        move || {
            ctx.live.set(true);
            if reopened.replace(true) {
                ctx.resync();
            }
        }
    });
    let on_hit = Closure::<dyn FnMut(MessageEvent)>::new(move |ev: MessageEvent| {
        let parsed = ev.data().as_string().and_then(|raw| serde_json::from_str::<RequestSummary>(&raw).ok());
        if let Some(summary) = parsed {
            ctx.on_hit(summary);
        }
    });
    let on_resync = Closure::<dyn FnMut()>::new(move || ctx.resync());
    let on_error = Closure::<dyn FnMut()>::new({
        let es = es.clone();
        move || {
            ctx.live.set(false);
            // CLOSED = browser gave up (e.g. 401); otherwise it retries by itself.
            if es.ready_state() == EventSource::CLOSED {
                ctx.check_session();
                schedule_reconnect(ctx);
            }
        }
    });

    es.set_onopen(Some(on_open.as_ref().unchecked_ref()));
    es.set_onerror(Some(on_error.as_ref().unchecked_ref()));
    let _ = es.add_event_listener_with_callback(EVENT_HIT, on_hit.as_ref().unchecked_ref());
    let _ = es.add_event_listener_with_callback(EVENT_RESYNC, on_resync.as_ref().unchecked_ref());

    // Listeners live as long as the page.
    on_open.forget();
    on_hit.forget();
    on_resync.forget();
    on_error.forget();
}

/// Waits while logged out, so a single stream survives re-login.
fn schedule_reconnect(ctx: Ctx) {
    set_timeout(move || if ctx.authed() { connect_stream(ctx) } else { schedule_reconnect(ctx) }, RECONNECT_DELAY);
}
