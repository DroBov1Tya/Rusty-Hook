//! Views. Untrusted request data is rendered only as text nodes (auto-escaped).

mod detail;
mod editor;
mod requests;
mod shell;

use leptos::{ev, prelude::*};

use crate::{api, state::Ctx};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Loading,
    Login,
    Panel,
}

#[component]
pub fn App() -> impl IntoView {
    let ctx = Ctx::new();
    provide_context(ctx);
    ctx.check_session();

    let mode = Memo::new(move |_| match ctx.session.get() {
        None => Mode::Loading,
        Some(s) if s.auth_required && !s.authenticated => Mode::Login,
        Some(_) => Mode::Panel,
    });

    view! {
        <div class="app">
            {move || match mode.get() {
                Mode::Loading => view! { <div class="splash"><Logo /></div> }.into_any(),
                Mode::Login => view! { <Login /> }.into_any(),
                Mode::Panel => view! { <shell::Shell /> }.into_any(),
            }}
            <Toast />
        </div>
    }
}

pub fn ctx() -> Ctx {
    expect_context::<Ctx>()
}

#[component]
pub fn Logo() -> impl IntoView {
    view! {
        <svg class="logo" viewBox="0 0 32 32" aria-hidden="true">
            <defs>
                <linearGradient id="lg" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0" stop-color="#d4ff3a" />
                    <stop offset="1" stop-color="#7c5cff" />
                </linearGradient>
            </defs>
            <rect x="1" y="1" width="30" height="30" rx="9" fill="url(#lg)" />
            <path
                d="M19 7v10a5 5 0 1 1-10 0v-2"
                fill="none"
                stroke="#0b0b10"
                stroke-width="3"
                stroke-linecap="round"
            />
            <path d="M6.5 16.5 9 13l2.5 3.5" fill="none" stroke="#0b0b10" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" />
            <circle cx="19" cy="7" r="2.2" fill="#0b0b10" />
        </svg>
    }
}

#[component]
fn Login() -> impl IntoView {
    let ctx = ctx();
    let key = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(None::<String>);

    let submit = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        busy.set(true);
        error.set(None);
        leptos::task::spawn_local(async move {
            match api::login(key.get_untracked()).await {
                Ok(()) => ctx.check_session(),
                Err(err) if err.is_unauthorized() => error.set(Some("Wrong key".into())),
                Err(err) => error.set(Some(err.message)),
            }
            busy.set(false);
        });
    };

    view! {
        <div class="login">
            <form class="card login-card" on:submit=submit>
                <Logo />
                <h1>"rusty"<span class="accent">"_hook"</span></h1>
                <p class="muted">"Enter the admin key to open the panel."</p>
                <input
                    type="password"
                    autocomplete="current-password"
                    placeholder="Admin key"
                    autofocus
                    prop:value=move || key.get()
                    on:input=move |ev| key.set(event_target_value(&ev))
                />
                <button class="btn primary" type="submit" disabled=move || busy.get() || key.with(String::is_empty)>
                    {move || if busy.get() { "Checking..." } else { "Unlock" }}
                </button>
                <p class="err">{move || error.get()}</p>
            </form>
        </div>
    }
}

#[component]
fn Toast() -> impl IntoView {
    let ctx = ctx();
    view! {
        <div class="toast-wrap">
            {move || ctx.toast.get().map(|(id, msg)| view! { <div class="toast" data-id=id.to_string()>{msg}</div> })}
        </div>
    }
}
