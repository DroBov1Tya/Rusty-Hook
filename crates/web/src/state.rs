//! App-wide reactive state and the actions that change it.

use std::time::Duration;

use leptos::{prelude::*, task::spawn_local};
use shared::{Endpoint, RequestDetail, RequestSummary, SessionInfo, UpdateEndpoint};
use uuid::Uuid;

use crate::{
    api::{self, ApiError, PAGE_SIZE},
    dom,
};

const TOAST_TTL: Duration = Duration::from_millis(2600);
/// Live rows kept in memory; older ones stay reachable via "Load older".
const MAX_LIVE_ROWS: usize = 500;

#[derive(Clone, Copy)]
pub struct Ctx {
    pub session: RwSignal<Option<SessionInfo>>,
    pub endpoints: RwSignal<Vec<Endpoint>>,
    pub selected: RwSignal<Option<Uuid>>,
    pub requests: RwSignal<Vec<RequestSummary>>,
    pub has_more: RwSignal<bool>,
    pub selected_req: RwSignal<Option<i64>>,
    pub detail: RwSignal<Option<RequestDetail>>,
    pub live: RwSignal<bool>,
    pub editing: RwSignal<bool>,
    pub toast: RwSignal<Option<(u64, String)>>,
    stream_started: StoredValue<bool>,
}

impl Ctx {
    pub fn new() -> Self {
        Self {
            session: RwSignal::new(None),
            endpoints: RwSignal::new(Vec::new()),
            selected: RwSignal::new(None),
            requests: RwSignal::new(Vec::new()),
            has_more: RwSignal::new(false),
            selected_req: RwSignal::new(None),
            detail: RwSignal::new(None),
            live: RwSignal::new(false),
            editing: RwSignal::new(false),
            toast: RwSignal::new(None),
            stream_started: StoredValue::new(false),
        }
    }

    pub fn authed(self) -> bool {
        self.session.get_untracked().is_some_and(|s| s.authenticated)
    }

    pub fn notify(self, message: String) {
        // Date.now is unique enough to match a toast with its own timer.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let id = js_sys::Date::now() as u64;
        self.toast.set(Some((id, message)));
        set_timeout(
            move || {
                if self.toast.get_untracked().is_some_and(|(t, _)| t == id) {
                    self.toast.set(None);
                }
            },
            TOAST_TTL,
        );
    }

    /// Central error sink: 401 drops to login, everything else is a toast.
    pub fn fail(self, err: ApiError) {
        if err.is_unauthorized() {
            self.session.update(|s| {
                if let Some(s) = s {
                    s.authenticated = false;
                }
            });
        } else {
            self.notify(err.message);
        }
    }

    pub fn check_session(self) {
        spawn_local(async move {
            match api::session().await {
                Ok(s) => self.session.set(Some(s)),
                Err(err) => self.notify(format!("Server unreachable: {}", err.message)),
            }
        });
    }

    pub fn start_stream(self) {
        if !self.stream_started.get_value() {
            self.stream_started.set_value(true);
            dom::connect_stream(self);
        }
    }

    pub fn current_endpoint(self) -> Option<Endpoint> {
        let id = self.selected.get()?;
        self.endpoints.with(|eps| eps.iter().find(|e| e.id == id).cloned())
    }

    pub fn load_endpoints(self) {
        spawn_local(async move {
            match api::endpoints().await {
                Ok(eps) => {
                    let keep = self.selected.get_untracked().or_else(dom::hash_id);
                    let pick = keep.filter(|id| eps.iter().any(|e| e.id == *id)).or(eps.first().map(|e| e.id));
                    self.endpoints.set(eps);
                    if pick != self.selected.get_untracked() || self.requests.with_untracked(Vec::is_empty) {
                        self.select(pick);
                    }
                }
                Err(err) => self.fail(err),
            }
        });
    }

    pub fn select(self, id: Option<Uuid>) {
        self.selected.set(id);
        self.requests.set(Vec::new());
        self.has_more.set(false);
        self.selected_req.set(None);
        self.detail.set(None);
        self.editing.set(false);
        dom::set_hash(id);
        if id.is_some() {
            self.load_requests(None);
        }
    }

    pub fn load_requests(self, before: Option<i64>) {
        let Some(id) = self.selected.get_untracked() else { return };
        spawn_local(async move {
            match api::requests(id, before).await {
                // Ignore late answers for a no-longer-selected endpoint.
                Ok(_) if self.selected.get_untracked() != Some(id) => {}
                Ok(page) => {
                    self.has_more.set(page.len() >= PAGE_SIZE as usize);
                    let first = page.first().map(|r| r.id);
                    match before {
                        Some(_) => self.requests.update(|all| all.extend(page)),
                        None => self.requests.set(page),
                    }
                    if self.selected_req.get_untracked().is_none()
                        && let Some(first) = first
                    {
                        self.open_request(first);
                    }
                }
                Err(err) => self.fail(err),
            }
        });
    }

    pub fn load_more(self) {
        let last = self.requests.with_untracked(|r| r.last().map(|r| r.id));
        if let Some(last) = last {
            self.load_requests(Some(last));
        }
    }

    pub fn open_request(self, id: i64) {
        if self.selected_req.get_untracked() == Some(id) && self.detail.get_untracked().is_some() {
            return;
        }
        self.selected_req.set(Some(id));
        self.detail.set(None);
        spawn_local(async move {
            match api::request(id).await {
                Ok(_) if self.selected_req.get_untracked() != Some(id) => {}
                Ok(detail) => self.detail.set(Some(detail)),
                Err(err) => self.fail(err),
            }
        });
    }

    /// Move selection by `step` (j/k keys).
    pub fn step_request(self, step: isize) {
        let next = self.requests.with_untracked(|all| {
            let pos = self.selected_req.get_untracked().and_then(|id| all.iter().position(|r| r.id == id));
            let target = match pos {
                Some(p) => p.checked_add_signed(step)?,
                None => 0,
            };
            all.get(target).map(|r| r.id)
        });
        if let Some(id) = next {
            self.open_request(id);
        }
    }

    pub fn create_endpoint(self) {
        spawn_local(async move {
            match api::create_endpoint(String::new()).await {
                Ok(ep) => {
                    let id = ep.id;
                    self.endpoints.update(|eps| eps.insert(0, ep));
                    self.select(Some(id));
                    self.notify("Endpoint created".into());
                }
                Err(err) => self.fail(err),
            }
        });
    }

    pub fn save_endpoint(self, id: Uuid, update: UpdateEndpoint) {
        spawn_local(async move {
            match api::update_endpoint(id, &update).await {
                Ok(saved) => {
                    self.endpoints.update(|eps| {
                        if let Some(ep) = eps.iter_mut().find(|e| e.id == id) {
                            *ep = saved;
                        }
                    });
                    self.editing.set(false);
                    self.notify("Response saved".into());
                }
                Err(err) => self.fail(err),
            }
        });
    }

    pub fn delete_endpoint(self, id: Uuid) {
        spawn_local(async move {
            match api::delete_endpoint(id).await {
                Ok(()) => {
                    self.endpoints.update(|eps| eps.retain(|e| e.id != id));
                    let next = self.endpoints.with_untracked(|eps| eps.first().map(|e| e.id));
                    self.select(next);
                    self.notify("Endpoint deleted".into());
                }
                Err(err) => self.fail(err),
            }
        });
    }

    pub fn clear_requests(self, id: Uuid) {
        spawn_local(async move {
            match api::clear_requests(id).await {
                Ok(()) => {
                    self.set_count(id, |_| 0);
                    self.select(Some(id));
                }
                Err(err) => self.fail(err),
            }
        });
    }

    pub fn delete_request(self, id: i64) {
        spawn_local(async move {
            match api::delete_request(id).await {
                Ok(()) => {
                    if let Some(ep) = self.selected.get_untracked() {
                        self.set_count(ep, |c| (c - 1).max(0));
                    }
                    let next = self.requests.with_untracked(|all| {
                        let pos = all.iter().position(|r| r.id == id)?;
                        all.get(pos + 1).or_else(|| pos.checked_sub(1).and_then(|p| all.get(p))).map(|r| r.id)
                    });
                    self.requests.update(|all| all.retain(|r| r.id != id));
                    self.selected_req.set(None);
                    self.detail.set(None);
                    if let Some(next) = next {
                        self.open_request(next);
                    }
                }
                Err(err) => self.fail(err),
            }
        });
    }

    pub fn on_hit(self, hit: RequestSummary) {
        self.set_count(hit.endpoint_id, |c| c + 1);
        if self.selected.get_untracked() == Some(hit.endpoint_id) {
            let first = self.requests.with_untracked(Vec::is_empty);
            let id = hit.id;
            self.requests.update(|all| {
                all.insert(0, hit);
                if all.len() > MAX_LIVE_ROWS {
                    all.truncate(MAX_LIVE_ROWS);
                    self.has_more.set(true);
                }
            });
            if first {
                self.open_request(id);
            }
        }
    }

    pub fn resync(self) {
        self.load_endpoints();
        self.load_requests(None);
    }

    pub fn logout(self) {
        spawn_local(async move {
            let _ = api::logout().await;
            // Fresh page: drops stream and all in-memory state.
            let _ = window().location().reload();
        });
    }

    fn set_count(self, id: Uuid, f: impl Fn(i64) -> i64) {
        self.endpoints.update(|eps| {
            if let Some(ep) = eps.iter_mut().find(|e| e.id == id) {
                ep.request_count = f(ep.request_count);
            }
        });
    }
}
