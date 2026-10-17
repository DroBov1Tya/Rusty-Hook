//! Views. Untrusted request data is rendered only as text nodes (auto-escaped).

mod detail;
mod editor;
mod requests;
mod shell;

use leptos::{ev, prelude::*};

use crate::{api, dom, state::Ctx};

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
    let error = RwSignal::new(dom::take_sso_error().then(|| "SSO sign-in failed or account not allowed".to_owned()));
    let methods = ctx.session.get_untracked().map_or((false, false), |s| (s.key_login, s.sso_login));
    let (key_login, sso_login) = methods;

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
            <div class="card login-card">
                <Logo />
                <h1>"Rusty"<span class="accent">" Hook"</span></h1>
                <p class="muted">"Sign in to open the panel."</p>
                <Show when=move || sso_login>
                    // Full navigation: the IdP round trip happens outside the app.
                    <a class="btn primary" href="/api/oidc/login">"Sign in with SSO"</a>
                </Show>
                <Show when=move || key_login && sso_login>
                    <div class="divider muted">"or"</div>
                </Show>
                <Show when=move || key_login>
                    <form class="login-form" on:submit=submit>
                        <input
                            type="password"
                            autocomplete="current-password"
                            placeholder="Admin key"
                            autofocus=!sso_login
                            prop:value=move || key.get()
                            on:input=move |ev| key.set(event_target_value(&ev))
                        />
                        <button
                            class=if sso_login { "btn" } else { "btn primary" }
                            type="submit"
                            disabled=move || busy.get() || key.with(String::is_empty)
                        >
                            {move || if busy.get() { "Checking..." } else { "Unlock with key" }}
                        </button>
                    </form>
                </Show>
                <p class="err">{move || error.get()}</p>
            </div>
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
