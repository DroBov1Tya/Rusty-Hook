//! API types shared by server and web. Validation lives here so both sides agree.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_NAME_LEN: usize = 100;
pub const MAX_CONTENT_TYPE_LEN: usize = 200;
pub const MAX_RESPONSE_BODY_LEN: usize = 64 * 1024;
pub const MAX_DELAY_MS: u32 = 10_000;
pub const MAX_PAGE_SIZE: u32 = 200;

/// What a hook endpoint answers to callers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseSpec {
    pub status: u16,
    pub content_type: String,
    pub body: String,
    pub delay_ms: u32,
}

impl Default for ResponseSpec {
    fn default() -> Self {
        Self { status: 200, content_type: "text/plain; charset=utf-8".into(), body: "ok".into(), delay_ms: 0 }
    }
}

impl ResponseSpec {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !(200..=599).contains(&self.status) {
            return Err("status must be 200-599");
        }
        if self.content_type.is_empty() || self.content_type.len() > MAX_CONTENT_TYPE_LEN {
            return Err("content_type must be 1-200 chars");
        }
        // Printable ASCII only: blocks header injection (CR/LF) by construction.
        if !self.content_type.bytes().all(|b| (0x20..0x7f).contains(&b)) {
            return Err("content_type must be printable ASCII");
        }
        if self.body.len() > MAX_RESPONSE_BODY_LEN {
            return Err("body must be at most 64 KiB");
        }
        if self.delay_ms > MAX_DELAY_MS {
            return Err("delay_ms must be at most 10000");
        }
        Ok(())
    }
}

pub fn validate_name(name: &str) -> Result<(), &'static str> {
    if name.chars().count() > MAX_NAME_LEN {
        return Err("name must be at most 100 chars");
    }
    if name.chars().any(char::is_control) {
        return Err("name must not contain control chars");
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Endpoint {
    pub id: Uuid,
    pub name: String,
    pub response: ResponseSpec,
    pub created_ms: i64,
    pub request_count: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewEndpoint {
    #[serde(default)]
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateEndpoint {
    pub name: String,
    pub response: ResponseSpec,
}

impl UpdateEndpoint {
    pub fn validate(&self) -> Result<(), &'static str> {
        validate_name(&self.name)?;
        self.response.validate()
    }
}

/// Light row for lists and live events.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RequestSummary {
    pub id: i64,
    pub endpoint_id: Uuid,
    pub method: String,
    pub path: String,
    pub query: String,
    pub content_type: Option<String>,
    pub ip: Option<String>,
    pub size: i32,
    pub received_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Body {
    Text(String),
    Base64(String),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RequestDetail {
    #[serde(flatten)]
    pub summary: RequestSummary,
    pub headers: Vec<(String, String)>,
    pub body: Body,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageQuery {
    pub before: Option<i64>,
    pub limit: Option<u32>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub auth_required: bool,
    pub authenticated: bool,
    pub max_body_bytes: usize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    pub key: String,
}

/// RFC 9457 problem details.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub kind: String,
    pub title: String,
    pub status: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// SSE event names.
pub const EVENT_HIT: &str = "hit";
pub const EVENT_RESYNC: &str = "resync";

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ResponseSpec {
        ResponseSpec::default()
    }

    #[test]
    fn default_spec_is_valid() {
        assert_eq!(spec().validate(), Ok(()));
    }

    #[test]
    fn status_bounds() {
        for (status, ok) in [(199, false), (200, true), (599, true), (600, false), (0, false)] {
            let s = ResponseSpec { status, ..spec() };
            assert_eq!(s.validate().is_ok(), ok, "status {status}");
        }
    }

    #[test]
    fn content_type_rejects_header_injection() {
        for ct in ["text/plain\r\nSet-Cookie: x=1", "a\nb", "", "\u{7f}", "caf\u{e9}"] {
            let s = ResponseSpec { content_type: ct.into(), ..spec() };
            assert!(s.validate().is_err(), "{ct:?}");
        }
        let long = ResponseSpec { content_type: "a".repeat(MAX_CONTENT_TYPE_LEN + 1), ..spec() };
        assert!(long.validate().is_err());
    }

    #[test]
    fn body_and_delay_limits() {
        let body = ResponseSpec { body: "x".repeat(MAX_RESPONSE_BODY_LEN), ..spec() };
        assert!(body.validate().is_ok());
        let body = ResponseSpec { body: "x".repeat(MAX_RESPONSE_BODY_LEN + 1), ..spec() };
        assert!(body.validate().is_err());
        let delay = ResponseSpec { delay_ms: MAX_DELAY_MS + 1, ..spec() };
        assert!(delay.validate().is_err());
    }

    #[test]
    fn name_rules() {
        assert!(validate_name("").is_ok());
        assert!(validate_name(&"x".repeat(MAX_NAME_LEN)).is_ok());
        assert!(validate_name(&"x".repeat(MAX_NAME_LEN + 1)).is_err());
        assert!(validate_name("a\u{0}b").is_err());
    }

    #[test]
    fn unknown_fields_rejected() {
        let raw = r#"{"name":"a","response":{"status":200,"content_type":"t","body":"","delay_ms":0},"admin":true}"#;
        assert!(serde_json::from_str::<UpdateEndpoint>(raw).is_err());
    }
}
