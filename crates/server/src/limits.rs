//! Per-IP rate limits (GCRA via governor).

use std::{net::IpAddr, num::NonZeroU32};

use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};

const LOGIN_PER_MINUTE: NonZeroU32 = match NonZeroU32::new(10) {
    Some(n) => n,
    None => NonZeroU32::MIN,
};

pub struct Limits {
    pub login: DefaultKeyedRateLimiter<IpAddr>,
    pub hooks: DefaultKeyedRateLimiter<IpAddr>,
}

impl Limits {
    pub fn new(hooks_per_minute: NonZeroU32) -> Self {
        Self {
            login: RateLimiter::keyed(Quota::per_minute(LOGIN_PER_MINUTE)),
            hooks: RateLimiter::keyed(Quota::per_minute(hooks_per_minute)),
        }
    }

    /// Drop idle keys so the maps stay small.
    pub fn prune(&self) {
        self.login.retain_recent();
        self.hooks.retain_recent();
    }
}
