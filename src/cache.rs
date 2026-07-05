//! In-memory HTTP-semantics cache for GET requests.
//!
//! ESI's rules: never re-request a route before its `Expires` has elapsed,
//! and send `If-None-Match` with the previous `ETag` so the server can
//! answer 304 instead of re-sending the body. This cache implements both
//! automatically:
//!
//! - a GET whose cached entry is still fresh is answered from memory
//!   without touching the network;
//! - a stale entry's ETag is attached as `If-None-Match`, and a 304 reply
//!   is transparently resurrected into the cached 200 (with freshness
//!   bumped from the 304's own headers).
//!
//! The cache is memory-only and bounded; callers who want persistence own
//! their own storage (see the crate-level docs).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue, ETAG, EXPIRES, IF_NONE_MATCH};

/// Entries beyond this count trigger eviction of everything expired.
const MAX_ENTRIES: usize = 8192;

#[derive(Debug)]
pub(crate) struct HttpCache {
    entries: Mutex<HashMap<String, Entry>>,
}

#[derive(Debug, Clone)]
struct Entry {
    fresh_until: Option<Instant>,
    etag: Option<HeaderValue>,
    status: reqwest::StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

impl HttpCache {
    pub(crate) fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// If the URL has a fresh cached entry, return it as a synthesized
    /// response; otherwise attach the previous ETag (if any) to the request
    /// so the server may answer 304. Only meaningful for GETs.
    pub(crate) fn lookup(&self, request: &mut reqwest::Request) -> Option<reqwest::Response> {
        let key = request.url().to_string();
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(&key)?;
        if entry.fresh_until.is_some_and(|t| Instant::now() < t) {
            return Some(entry.to_response());
        }
        if let Some(etag) = &entry.etag {
            if !request.headers().contains_key(IF_NONE_MATCH) {
                request.headers_mut().insert(IF_NONE_MATCH, etag.clone());
            }
        }
        None
    }

    /// Handle a 304: bump the entry's freshness from the 304's headers and
    /// resurrect the cached body. Returns None if we have nothing cached
    /// (e.g. the caller supplied their own If-None-Match) — the 304 then
    /// passes through untouched.
    pub(crate) fn revalidated(
        &self,
        url: &reqwest::Url,
        headers_304: &HeaderMap,
    ) -> Option<reqwest::Response> {
        let mut entries = self.entries.lock().unwrap();
        let entry = entries.get_mut(url.as_str())?;
        entry.fresh_until = expires_from(headers_304).or(entry.fresh_until);
        if let Some(etag) = headers_304.get(ETAG) {
            entry.etag = Some(etag.clone());
        }
        Some(entry.to_response())
    }

    /// Store a successful response if it carries cache metadata. Consumes
    /// the response body and returns an equivalent response for the caller.
    pub(crate) async fn store(
        &self,
        response: reqwest::Response,
    ) -> reqwest::Result<reqwest::Response> {
        let status = response.status();
        let headers = response.headers().clone();
        let url = response.url().clone();
        let fresh_until = expires_from(&headers);
        let etag = headers.get(ETAG).cloned();
        if fresh_until.is_none() && etag.is_none() {
            return Ok(response);
        }
        let body = response.bytes().await?;
        let entry = Entry {
            fresh_until,
            etag,
            status,
            headers,
            body,
        };
        let synthesized = entry.to_response();
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= MAX_ENTRIES {
            let now = Instant::now();
            entries.retain(|_, e| e.fresh_until.is_some_and(|t| t > now));
        }
        entries.insert(url.to_string(), entry);
        Ok(synthesized)
    }
}

impl Entry {
    fn to_response(&self) -> reqwest::Response {
        let mut builder = http::Response::builder().status(self.status);
        if let Some(headers) = builder.headers_mut() {
            *headers = self.headers.clone();
        }
        let response = builder
            .body(self.body.clone())
            .expect("cached response must rebuild");
        reqwest::Response::from(response)
    }
}

/// Freshness lifetime from an `Expires` header, translated onto the
/// monotonic clock. ESI also sends `Date`; using it (rather than local
/// time) makes the arithmetic immune to client clock skew.
fn expires_from(headers: &HeaderMap) -> Option<Instant> {
    let parse_http_date = |v: &HeaderValue| {
        v.to_str()
            .ok()
            .and_then(|s| chrono::DateTime::parse_from_rfc2822(s).ok())
    };
    let expires = headers.get(EXPIRES).and_then(parse_http_date)?;
    let server_now = headers
        .get(reqwest::header::DATE)
        .and_then(parse_http_date)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| {
            chrono::DateTime::<chrono::Utc>::from(SystemTime::now())
        });
    let lifetime = (expires.with_timezone(&chrono::Utc) - server_now)
        .to_std()
        .ok()?;
    if lifetime.is_zero() {
        return None;
    }
    Some(Instant::now() + Duration::min(lifetime, Duration::from_secs(24 * 3600)))
}
