//! Full view of one captured request.

use leptos::prelude::*;
use serde_json::Value;
use shared::{Body, RequestDetail};

use super::ctx;
use crate::{dom, fmt};

/// Above this, skip highlighting: thousands of spans get sluggish.
const HIGHLIGHT_LIMIT: usize = 256 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Body,
    Headers,
    Query,
}

#[component]
pub fn Detail() -> impl IntoView {
    let ctx = ctx();
    move || match (ctx.selected_req.get(), ctx.detail.get()) {
        (None, _) => view! {
            <div class="placeholder muted">"Pick a request to inspect it"</div>
        }
        .into_any(),
        (Some(_), None) => view! {
            <div class="skeleton"><i></i><i></i><i></i></div>
        }
        .into_any(),
        (Some(_), Some(d)) => view! { <DetailView d /> }.into_any(),
    }
}

#[component]
fn DetailView(d: RequestDetail) -> impl IntoView {
    let ctx = ctx();
    let tab = RwSignal::new(Tab::Body);
    let s = d.summary.clone();
    let query = fmt::query_pairs(&s.query, dom::decode);
    let target = if s.query.is_empty() { s.path.clone() } else { format!("{}?{}", s.path, s.query) };
    let curl = fmt::curl(&d, &dom::hook_url(s.endpoint_id));
    let raw_body = match &d.body {
        Body::Text(t) | Body::Base64(t) => t.clone(),
    };
    let (n_headers, n_query) = (d.headers.len(), query.len());
    let id = s.id;

    let tab_btn = move |t: Tab, label: String| {
        view! {
            <button class="tab" class:active=move || tab.get() == t on:click=move |_| tab.set(t)>
                {label}
            </button>
        }
    };

    let body_view = body_view(&d);
    let headers_view = kv_table(d.headers.clone());
    let query_view = kv_table(query);

    view! {
        <div class="detail">
            <div class="detail-head">
                <span class=fmt::method_class(&s.method)>{s.method.clone()}</span>
                <code class="detail-path">{target}</code>
            </div>
            <div class="meta">
                <Meta k="Received" v=dom::datetime(s.received_ms) />
                <Meta k="From" v=s.ip.clone().unwrap_or_else(|| "-".into()) />
                <Meta k="Size" v=fmt::size(s.size) />
                <Meta k="Type" v=s.content_type.clone().unwrap_or_else(|| "-".into()) />
            </div>
            <div class="detail-actions">
                <button class="btn small" on:click=move |_| dom::copy(ctx, curl.clone(), "curl")>"Copy as curl"</button>
                <button class="btn small" on:click=move |_| dom::copy(ctx, raw_body.clone(), "Body")>"Copy body"</button>
                <div class="spacer"></div>
                <button class="btn small danger ghost" on:click=move |_| ctx.delete_request(id)>"Delete"</button>
            </div>
            <div class="tabs">
                {tab_btn(Tab::Body, "Body".into())}
                {tab_btn(Tab::Headers, format!("Headers {n_headers}"))}
                {tab_btn(Tab::Query, format!("Query {n_query}"))}
            </div>
            <div class="tab-body" class:hidden=move || tab.get() != Tab::Body>{body_view}</div>
            <div class="tab-body" class:hidden=move || tab.get() != Tab::Headers>{headers_view}</div>
            <div class="tab-body" class:hidden=move || tab.get() != Tab::Query>{query_view}</div>
        </div>
    }
}

#[component]
fn Meta(k: &'static str, v: String) -> impl IntoView {
    view! {
        <div class="meta-item">
            <span class="label">{k}</span>
            <span class="meta-v">{v}</span>
        </div>
    }
}

fn kv_table(pairs: Vec<(String, String)>) -> AnyView {
    if pairs.is_empty() {
        return view! { <div class="muted pad">"Nothing here"</div> }.into_any();
    }
    view! {
        <table class="kv">
            <tbody>
                {pairs.into_iter().map(|(k, v)| view! { <tr><th>{k}</th><td>{v}</td></tr> }).collect_view()}
            </tbody>
        </table>
    }
    .into_any()
}

fn body_view(d: &RequestDetail) -> AnyView {
    let content_type = d.summary.content_type.as_deref().unwrap_or_default().to_ascii_lowercase();
    match &d.body {
        Body::Text(text) if text.is_empty() => view! { <div class="muted pad">"Empty body"</div> }.into_any(),
        Body::Text(text) => {
            if let Some(json) = as_json(text) {
                let tokens = fmt::json_tokens(&json);
                return view! {
                    <pre class="code json">
                        {tokens.into_iter().map(|(t, s)| view! { <span class=t.class()>{s}</span> }).collect_view()}
                    </pre>
                }
                .into_any();
            }
            if content_type.starts_with("application/x-www-form-urlencoded") {
                return kv_table(fmt::query_pairs(text, dom::decode));
            }
            view! { <pre class="code">{text.clone()}</pre> }.into_any()
        }
        Body::Base64(b64) => view! {
            <div class="muted pad">"Binary body, shown as base64"</div>
            <pre class="code">{b64.clone()}</pre>
        }
        .into_any(),
    }
}

fn as_json(text: &str) -> Option<Value> {
    let t = text.trim_start();
    let looks_like = t.starts_with('{') || t.starts_with('[');
    (looks_like && text.len() <= HIGHLIGHT_LIMIT).then(|| serde_json::from_str(text).ok()).flatten()
}
