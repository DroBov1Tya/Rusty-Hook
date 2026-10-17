//! Main layout: top bar, endpoint sidebar, request list, detail.

use leptos::{ev, prelude::*};
use shared::Endpoint;

use super::{Logo, ctx, detail::Detail, editor::Editor, requests::RequestList};
use crate::{dom, fmt};

#[component]
pub fn Shell() -> impl IntoView {
    let ctx = ctx();
    ctx.load_endpoints();
    ctx.start_stream();

    let keys = window_event_listener(ev::keydown, move |e| {
        if e.ctrl_key() || e.meta_key() || e.alt_key() {
            return;
        }
        match e.key().as_str() {
            "Escape" => ctx.editing.set(false),
            _ if dom::typing() || ctx.editing.get_untracked() => {}
            "j" | "ArrowDown" => {
                e.prevent_default();
                ctx.step_request(1);
            }
            "k" | "ArrowUp" => {
                e.prevent_default();
                ctx.step_request(-1);
            }
            "n" => ctx.create_endpoint(),
            _ => {}
        }
    });
    on_cleanup(move || keys.remove());

    view! {
        <Topbar />
        <main class="grid">
            <Sidebar />
            <Show when=move || ctx.selected.get().is_some() fallback=Welcome>
                <section class="col col-list">
                    <RequestList />
                </section>
                <section class="col col-detail">
                    <Detail />
                </section>
            </Show>
        </main>
        <Show when=move || ctx.editing.get()>
            <Editor />
        </Show>
    }
}

#[component]
fn Topbar() -> impl IntoView {
    let ctx = ctx();
    let auth = move || ctx.session.get().is_some_and(|s| s.auth_required);
    view! {
        <header class="top">
            <div class="brand">
                <Logo />
                <span class="brand-name">"Rusty"<span class="accent">" Hook"</span></span>
            </div>
            <div class="spacer"></div>
            <div class="live" class:on=move || ctx.live.get() title="Live stream status">
                <i></i>
                {move || if ctx.live.get() { "live" } else { "offline" }}
            </div>
            <Show when=auth>
                <button class="btn ghost" on:click=move |_| ctx.logout()>"Log out"</button>
            </Show>
        </header>
    }
}

#[component]
fn Sidebar() -> impl IntoView {
    let ctx = ctx();
    view! {
        <aside class="col side">
            <div class="side-head">
                <span class="label">"Endpoints"</span>
                <button class="btn small primary" title="New endpoint (n)" on:click=move |_| ctx.create_endpoint()>
                    "+ New"
                </button>
            </div>
            <ul class="eps">
                <For
                    each=move || ctx.endpoints.get()
                    key=|e| (e.id, e.request_count, e.name.clone(), e.response.status)
                    children=move |ep| view! { <EndpointItem ep /> }
                />
            </ul>
            <div class="side-foot muted">
                <kbd>"j"</kbd>" "<kbd>"k"</kbd>" navigate  "<kbd>"n"</kbd>" new"
            </div>
        </aside>
    }
}

#[component]
fn EndpointItem(ep: Endpoint) -> impl IntoView {
    let ctx = ctx();
    let id = ep.id;
    let name = if ep.name.is_empty() { "Untitled".to_owned() } else { ep.name.clone() };
    view! {
        <li class="ep" class:active=move || ctx.selected.get() == Some(id) on:click=move |_| ctx.select(Some(id))>
            <div class="ep-row">
                <span class="ep-name">{name}</span>
                <span class="count">{ep.request_count}</span>
            </div>
            <div class="ep-row muted">
                <code>{fmt::short_id(&id)}</code>
                <span class="ep-status">{ep.response.status}</span>
            </div>
        </li>
    }
}

#[component]
fn Welcome() -> impl IntoView {
    let ctx = ctx();
    view! {
        <section class="col welcome">
            <div class="hero">
                <div class="orb"></div>
                <h1>"Catch every "<span class="accent">"webhook"</span>"."</h1>
                <p class="muted">
                    "Create an endpoint, point any service at it and watch requests land in real time."
                </p>
                <button class="btn primary big" on:click=move |_| ctx.create_endpoint()>"Create endpoint"</button>
            </div>
        </section>
    }
}
