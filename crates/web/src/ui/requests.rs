//! Selected endpoint header and its live request list.

use leptos::prelude::*;
use shared::RequestSummary;

use super::ctx;
use crate::{dom, fmt};

#[component]
pub fn RequestList() -> impl IntoView {
    let ctx = ctx();
    let filter = RwSignal::new(String::new());

    let visible = move || {
        let needle = filter.get().to_lowercase();
        ctx.requests
            .with(|all| all.iter().filter(|r| needle.is_empty() || matches(r, &needle)).cloned().collect::<Vec<_>>())
    };
    let empty = move || ctx.requests.with(Vec::is_empty);

    view! {
        <EndpointBar />
        <div class="filter">
            <input
                type="search"
                placeholder="Filter: method, path, ip, type"
                prop:value=move || filter.get()
                on:input=move |ev| filter.set(event_target_value(&ev))
            />
        </div>
        <Show when=move || !empty() fallback=Waiting>
            <ul class="reqs">
                <For each=visible key=|r| r.id children=move |r| view! { <RequestRow r /> } />
            </ul>
            <Show when=move || ctx.has_more.get()>
                <button class="btn ghost more" on:click=move |_| ctx.load_more()>"Load older"</button>
            </Show>
        </Show>
    }
}

fn matches(r: &RequestSummary, needle: &str) -> bool {
    [Some(&r.method), Some(&r.path), Some(&r.query), r.ip.as_ref(), r.content_type.as_ref()]
        .into_iter()
        .flatten()
        .any(|field| field.to_lowercase().contains(needle))
}

#[component]
fn RequestRow(r: RequestSummary) -> impl IntoView {
    let ctx = ctx();
    let id = r.id;
    let target = if r.query.is_empty() { r.path.clone() } else { format!("{}?{}", r.path, r.query) };
    view! {
        <li class="req" class:active=move || ctx.selected_req.get() == Some(id) on:click=move |_| ctx.open_request(id)>
            <span class=fmt::method_class(&r.method)>{r.method.clone()}</span>
            <span class="req-path">{target}</span>
            <span class="req-meta">
                <span>{dom::time(r.received_ms)}</span>
                <span class="muted">{fmt::size(r.size)}</span>
            </span>
        </li>
    }
}

#[component]
fn EndpointBar() -> impl IntoView {
    let ctx = ctx();
    let endpoint = Memo::new(move |_| ctx.current_endpoint());

    move || {
        endpoint.get().map(|ep| {
            let id = ep.id;
            let url = dom::hook_url(id);
            let copy_url = url.clone();
            let title = if ep.name.is_empty() { "Untitled endpoint".to_owned() } else { ep.name.clone() };
            view! {
                <div class="bar card">
                    <div class="bar-title">
                        <h2>{title}</h2>
                        <span class="chip" title="Response sent to callers">
                            <b>{ep.response.status}</b>
                            {ep.response.content_type.clone()}
                        </span>
                    </div>
                    <div class="url">
                        <span class="url-any">"ANY"</span>
                        <code>{url}</code>
                        <button class="btn small" on:click=move |_| dom::copy(ctx, copy_url.clone(), "URL")>
                            "Copy"
                        </button>
                    </div>
                    <div class="bar-actions">
                        <button class="btn small" on:click=move |_| ctx.editing.set(true)>"Edit response"</button>
                        <button
                            class="btn small ghost"
                            on:click=move |_| {
                                if dom::confirm("Delete all captured requests?") {
                                    ctx.clear_requests(id);
                                }
                            }
                        >
                            "Clear"
                        </button>
                        <button
                            class="btn small danger"
                            on:click=move |_| {
                                if dom::confirm("Delete this endpoint and its requests?") {
                                    ctx.delete_endpoint(id);
                                }
                            }
                        >
                            "Delete"
                        </button>
                    </div>
                </div>
            }
        })
    }
}

#[component]
fn Waiting() -> impl IntoView {
    let ctx = ctx();
    let sample = move || {
        ctx.selected.get().map(|id| {
            format!(
                "curl -X POST '{}' \\\n  -H 'content-type: application/json' \\\n  -d '{{\"hello\":\"world\"}}'",
                dom::hook_url(id)
            )
        })
    };
    view! {
        <div class="waiting">
            <div class="radar"><i></i><i></i><i></i></div>
            <h3>"Waiting for the first request"</h3>
            <p class="muted">"Send anything to the URL above. It shows up here instantly."</p>
            <pre class="code sample">{sample}</pre>
            <button class="btn small" on:click=move |_| { if let Some(s) = sample() { dom::copy(ctx, s, "Command") } }>
                "Copy curl"
            </button>
        </div>
    }
}
