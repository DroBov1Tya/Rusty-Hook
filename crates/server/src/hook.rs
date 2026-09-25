//! Public hook receiver: ANY /h/{id}[/*]. Stores the request and replies with the endpoint spec.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use shared::RequestSummary;
use sqlx::{FromRow, types::Json};
use uuid::Uuid;

use crate::{auth::is_secret_cookie, state::AppState};

const MAX_METHOD_LEN: usize = 32;

#[derive(FromRow)]
struct Captured {
    resp_status: i16,
    resp_content_type: String,
    resp_body: String,
    resp_delay_ms: i32,
    id: i64,
    size: i32,
    received_ms: i64,
}

// One round trip: resolve endpoint and insert only if it exists.
const CAPTURE_SQL: &str = "
WITH e AS (
    SELECT id, resp_status, resp_content_type, resp_body, resp_delay_ms
    FROM endpoints WHERE id = $1
), ins AS (
    INSERT INTO requests (endpoint_id, method, path, query, content_type, headers, body, ip)
    SELECT id, $2, $3, $4, $5, $6, $7, $8 FROM e
    RETURNING id, size, (extract(epoch FROM received_at) * 1000)::int8 AS received_ms
)
SELECT e.resp_status, e.resp_content_type, e.resp_body, e.resp_delay_ms,
       ins.id, ins.size, ins.received_ms
FROM e, ins";

// Keep only the newest N rows of one endpoint. Uses (endpoint_id, id DESC).
const TRIM_SQL: &str = "
DELETE FROM requests
WHERE endpoint_id = $1 AND id <= (
    SELECT id FROM requests WHERE endpoint_id = $1
    ORDER BY id DESC OFFSET $2 LIMIT 1
)";

pub async fn capture(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some((endpoint_id, path)) = split_hook_path(uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if method.as_str().len() > MAX_METHOD_LEN {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let ip = client_ip(st.cfg.trust_forwarded, &headers, peer).to_string();
    let query = uri.query().unwrap_or_default().to_owned();
    let content_type = headers.get(header::CONTENT_TYPE).map(|v| lossy(v.as_bytes()));
    let pairs = stored_headers(&headers);

    let row = sqlx::query_as::<_, Captured>(CAPTURE_SQL)
        .bind(endpoint_id)
        .bind(method.as_str())
        .bind(&path)
        .bind(&query)
        .bind(&content_type)
        .bind(Json(&pairs))
        .bind(body.as_ref())
        .bind(&ip)
        .fetch_optional(&st.hook_db)
        .await;

    let row = match row {
        Ok(Some(row)) => row,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(err) => {
            tracing::error!(error = %err, "capture failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    // Receivers may be zero; that's fine.
    let _ = st.hub.send(RequestSummary {
        id: row.id,
        endpoint_id,
        method: method.as_str().to_owned(),
        path,
        query,
        content_type,
        ip: Some(ip),
        size: row.size,
        received_ms: row.received_ms,
    });
    spawn_trim(&st, endpoint_id);

    if row.resp_delay_ms > 0 {
        tokio::time::sleep(Duration::from_millis(row.resp_delay_ms.unsigned_abs().into())).await;
    }
    reply(row.resp_status, &row.resp_content_type, row.resp_body)
}

/// Middleware: per-IP rate limit, applied before the body is read.
pub async fn rate_limit(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = client_ip(st.cfg.trust_forwarded, req.headers(), peer);
    if st.limits.hooks.check_key(&ip).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, [(header::RETRY_AFTER, "60")]).into_response();
    }
    next.run(req).await
}

/// Real client IP. With TRUST_FORWARDED only the entry appended by our own proxy
/// (rightmost) is used: everything left of it is caller-controlled.
pub fn client_ip(trust_forwarded: bool, headers: &HeaderMap, peer: SocketAddr) -> IpAddr {
    let forwarded = || {
        let raw = headers.get_all("x-forwarded-for").iter().next_back()?.to_str().ok()?;
        raw.rsplit(',').next()?.trim().parse().ok()
    };
    match trust_forwarded {
        true => forwarded().unwrap_or(peer.ip()),
        false => peer.ip(),
    }
}

/// Headers as stored: panel/SSO session cookies are cut out so an admin who opens
/// a hook URL in the same browser doesn't leak their session into the DB.
fn stored_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .filter_map(|(k, v)| {
            let value = lossy(v.as_bytes());
            if *k != header::COOKIE {
                return Some((k.as_str().to_owned(), value));
            }
            let kept: Vec<&str> = value
                .split(';')
                .map(str::trim)
                .filter(|pair| !is_secret_cookie(pair.split_once('=').map_or(*pair, |(name, _)| name)))
                .collect();
            (!kept.is_empty()).then(|| (k.as_str().to_owned(), kept.join("; ")))
        })
        .collect()
}

/// "/h/<uuid>/a/b" -> (uuid, "/a/b"); "/h/<uuid>" -> (uuid, "/").
fn split_hook_path(full: &str) -> Option<(Uuid, String)> {
    let rest = full.strip_prefix("/h/")?;
    let (id, tail) = rest.split_once('/').unwrap_or((rest, ""));
    let id = Uuid::try_parse(id).ok()?;
    Some((id, format!("/{tail}")))
}

fn spawn_trim(st: &AppState, endpoint_id: Uuid) {
    let db = st.hook_db.clone();
    let keep = st.cfg.max_requests_per_endpoint;
    tokio::spawn(async move {
        if let Err(err) = sqlx::query(TRIM_SQL).bind(endpoint_id).bind(keep).execute(&db).await {
            tracing::warn!(error = %err, "trim failed");
        }
    });
}

fn reply(status: i16, content_type: &str, body: String) -> Response {
    let status = u16::try_from(status).ok().and_then(|s| StatusCode::from_u16(s).ok()).unwrap_or(StatusCode::OK);
    let content_type =
        HeaderValue::from_str(content_type).unwrap_or(HeaderValue::from_static("text/plain; charset=utf-8"));

    let mut res = Response::new(Body::from(body));
    *res.status_mut() = status;
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, content_type);
    // User-defined content on the panel origin: sandbox it so it can't script the panel.
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("sandbox"));
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    // Browsers may test hooks from any origin; no credentials are ever accepted here.
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    h.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("*"));
    h.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("*"));
    h.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("*"));
    res
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "6f1c1d3e-8a9b-4c2d-9e0f-112233445566";

    #[test]
    fn split_paths() {
        let id = Uuid::try_parse(ID).ok();
        assert_eq!(split_hook_path(&format!("/h/{ID}")).map(|p| p.1), Some("/".into()));
        assert_eq!(split_hook_path(&format!("/h/{ID}/")).map(|p| p.1), Some("/".into()));
        assert_eq!(split_hook_path(&format!("/h/{ID}/a/b")).map(|p| (Some(p.0), p.1)), Some((id, "/a/b".into())));
    }

    #[test]
    fn split_rejects_junk() {
        for p in ["/h/", "/h/nope", "/x/6f1c1d3e-8a9b-4c2d-9e0f-112233445566", "/h/../etc"] {
            assert!(split_hook_path(p).is_none(), "{p}");
        }
    }

    #[test]
    fn secret_cookies_are_not_stored() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, HeaderValue::from_static("a=1; rh_session=SECRET; _oauth2_proxy=X; b=2"));
        h.append(header::COOKIE, HeaderValue::from_static("__Host-rh_session=SECRET"));
        h.insert("x-sig", HeaderValue::from_static("abc"));
        let stored = stored_headers(&h);
        assert!(stored.iter().all(|(_, v)| !v.contains("SECRET") && !v.contains("_oauth2_proxy")));
        assert!(stored.contains(&("cookie".into(), "a=1; b=2".into())));
        assert!(stored.contains(&("x-sig".into(), "abc".into())));
        assert_eq!(stored.len(), 2);
    }

    #[test]
    fn forwarded_ip_uses_rightmost_entry() {
        let mut fwd = HeaderMap::new();
        fwd.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6, 10.0.0.7"));
        let peer = SocketAddr::from(([172, 18, 0, 3], 4000));
        assert_eq!(client_ip(true, &fwd, peer).to_string(), "10.0.0.7");
        assert_eq!(client_ip(false, &fwd, peer).to_string(), "172.18.0.3");
    }

    #[test]
    fn reply_is_sandboxed() {
        let res = reply(201, "text/html", "<script>x</script>".into());
        assert_eq!(res.status(), StatusCode::CREATED);
        assert_eq!(res.headers().get(header::CONTENT_SECURITY_POLICY).map(|v| v.as_bytes()), Some(&b"sandbox"[..]));
        assert_eq!(res.headers().get(header::X_CONTENT_TYPE_OPTIONS).map(|v| v.as_bytes()), Some(&b"nosniff"[..]));
    }

    #[test]
    fn reply_falls_back_on_bad_input() {
        let res = reply(-1, "bad\nvalue", String::new());
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers().get(header::CONTENT_TYPE).map(|v| v.as_bytes()),
            Some(&b"text/plain; charset=utf-8"[..])
        );
    }
}
