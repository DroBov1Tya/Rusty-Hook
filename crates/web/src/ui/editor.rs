//! Drawer to edit endpoint name and the response it returns.

use leptos::{ev, prelude::*};
use shared::{MAX_DELAY_MS, ResponseSpec, UpdateEndpoint};

use super::ctx;

const STATUS_PRESETS: [u16; 6] = [200, 201, 204, 400, 404, 500];
const TYPE_PRESETS: [&str; 5] = [
    "text/plain; charset=utf-8",
    "application/json",
    "application/xml",
    "text/html; charset=utf-8",
    "application/x-www-form-urlencoded",
];

#[component]
pub fn Editor() -> impl IntoView {
    let ctx = ctx();
    let Some(ep) = ctx.current_endpoint() else {
        return ().into_any();
    };
    let id = ep.id;
    let name = RwSignal::new(ep.name);
    let status = RwSignal::new(ep.response.status.to_string());
    let content_type = RwSignal::new(ep.response.content_type);
    let body = RwSignal::new(ep.response.body);
    let delay = RwSignal::new(ep.response.delay_ms.to_string());
    let error = RwSignal::new(None::<String>);

    let save = move |ev: ev::SubmitEvent| {
        ev.prevent_default();
        let (Ok(status), Ok(delay_ms)) = (status.get().trim().parse(), delay.get().trim().parse()) else {
            error.set(Some("Status and delay must be numbers".into()));
            return;
        };
        let update = UpdateEndpoint {
            name: name.get(),
            response: ResponseSpec { status, content_type: content_type.get(), body: body.get(), delay_ms },
        };
        match update.validate() {
            Ok(()) => ctx.save_endpoint(id, update),
            Err(msg) => error.set(Some(msg.into())),
        }
    };

    view! {
        <div class="overlay" on:click=move |_| ctx.editing.set(false)></div>
        <form class="drawer card" on:submit=save>
            <div class="drawer-head">
                <h2>"Endpoint response"</h2>
                <button type="button" class="btn ghost small" on:click=move |_| ctx.editing.set(false)>"Esc"</button>
            </div>
            <label>
                <span class="label">"Name"</span>
                <input
                    maxlength="100"
                    placeholder="e.g. Stripe staging"
                    prop:value=move || name.get()
                    on:input=move |ev| name.set(event_target_value(&ev))
                />
            </label>
            <div class="row">
                <label>
                    <span class="label">"Status"</span>
                    <input
                        inputmode="numeric"
                        prop:value=move || status.get()
                        on:input=move |ev| status.set(event_target_value(&ev))
                    />
                </label>
                <label>
                    <span class="label">"Delay, ms (max " {MAX_DELAY_MS} ")"</span>
                    <input
                        inputmode="numeric"
                        prop:value=move || delay.get()
                        on:input=move |ev| delay.set(event_target_value(&ev))
                    />
                </label>
            </div>
            <div class="presets">
                {STATUS_PRESETS
                    .into_iter()
                    .map(|code| {
                        view! {
                            <button
                                type="button"
                                class="chip-btn"
                                class:active=move || status.get() == code.to_string()
                                on:click=move |_| status.set(code.to_string())
                            >
                                {code}
                            </button>
                        }
                    })
                    .collect_view()}
            </div>
            <label>
                <span class="label">"Content-Type"</span>
                <input
                    list="ct-presets"
                    prop:value=move || content_type.get()
                    on:input=move |ev| content_type.set(event_target_value(&ev))
                />
                <datalist id="ct-presets">
                    {TYPE_PRESETS.into_iter().map(|t| view! { <option value=t></option> }).collect_view()}
                </datalist>
            </label>
            <label class="grow">
                <span class="label">"Body"</span>
                <textarea
                    class="code"
                    spellcheck="false"
                    prop:value=move || body.get()
                    on:input=move |ev| body.set(event_target_value(&ev))
                ></textarea>
            </label>
            <p class="err">{move || error.get()}</p>
            <button class="btn primary" type="submit">"Save"</button>
        </form>
    }
    .into_any()
}
