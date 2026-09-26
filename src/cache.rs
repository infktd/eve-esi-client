//! HTTP-semantics response cache for GET requests.
//!
//! ESI's rules: never re-request a route before its `Expires` has elapsed,
//! and send `If-None-Match` with the previous `ETag` so the server can
//! answer 304 instead of re-sending the body. The client implements both on
//! top of an [`EsiCache`]:
//!
//! - a GET whose cached entry is still fresh is answered from the cache
//!   without touching the network, marked `x-esi-client-cache: hit`;
//! - a stale entry's ETag is attached as `If-None-Match`, and a 304 reply
//!   is transparently resurrected into the cached 200 (with freshness and
//!   headers updated from the 304), marked `x-esi-client-cache: revalidated`.
//!
//! Cached responses never carry `X-ESI-Error-Limit-*` or `X-Ratelimit-*`
//! headers: those describe the budget at the moment a response was sent, and
//! replaying them would misreport the current one. Read the live budgets
//! from [`crate::EsiInner::error_budget`] and
//! [`crate::EsiInner::rate_budgets`] instead.
//!
//! [`MemoryCache`] is the default. Implement [`EsiCache`] to share a cache
//! between clients or persist it across restarts, and install it with
//! [`crate::ClientBuilder::cache`].

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, SystemTime};

pub use bytes::Bytes;
pub use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};

use reqwest::header::{
    CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, DATE, ETAG, EXPIRES,
    IF_NONE_MATCH, TRANSFER_ENCODING,
};

/// Header added to responses the client answered from its cache.
pub const CACHE_STATUS_HEADER: &str = "x-esi-client-cache";

/// Entries beyond this count make [`MemoryCache`] evict everything expired.
const MAX_ENTRIES: usize = 8192;

/// No response is considered fresh for longer than this, whatever its
/// `Expires` says.
const MAX_FRESHNESS: Duration = Duration::from_secs(24 * 3600);

/// Storage for cached ESI responses.
///
/// The client calls it only for GET requests. Implementations decide their
/// own storage and eviction; the client handles freshness and revalidation.
/// A cache must never make a request fail, so the methods are infallible:
/// treat a storage error in `get` as a miss and in `put`/`remove` as a no-op
/// (logging it however your application logs).
///
/// Implement it with [`macro@crate::async_trait`], which this crate re-exports:
///
/// ```
/// use eve_esi_client::cache::{CacheKey, CachedResponse, EsiCache};
///
/// struct NoCache;
///
/// #[eve_esi_client::async_trait]
/// impl EsiCache for NoCache {
///     async fn get(&self, _key: &CacheKey) -> Option<CachedResponse> {
///         None
///     }
///     async fn put(&self, _key: &CacheKey, _response: CachedResponse) {}
///     async fn remove(&self, _key: &CacheKey) {}
/// }
/// ```
#[async_trait::async_trait]
pub trait EsiCache: Send + Sync {
    /// The entry stored under `key`, fresh or stale. The client checks
    /// [`CachedResponse::expires_at`] itself.
    async fn get(&self, key: &CacheKey) -> Option<CachedResponse>;

    /// Store (or replace) the entry under `key`.
    async fn put(&self, key: &CacheKey, response: CachedResponse);

    /// Drop the entry under `key`. Called when a fresh response for the key
    /// carries no cache metadata, so the old entry must not be revalidated.
    async fn remove(&self, key: &CacheKey);
}

/// What a cached response is stored under.
///
/// Authenticated responses belong to the character whose token fetched
/// them: a corporation's assets, for example, depend on that character's
/// roles. So a cache shared between clients must key on both fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// The full request URL, including the query string.
    pub url: String,
    /// The `sub` claim of the request's bearer token, e.g.
    /// `CHARACTER:EVE:2112625428`, or `None` for an unauthenticated request.
    ///
    /// Requests whose bearer token has no readable `sub` claim are never
    /// cached. The principal is read from the request's `Authorization`
    /// header, so a token that only a `reqwest::Client`'s default headers add
    /// is invisible here: use [`crate::EsiInner::without_cache`] for those
    /// requests.
    pub principal: Option<String>,
}

/// A stored response.
///
/// The fields are public so a persistent [`EsiCache`] can rebuild one from
/// its stored parts. For a row holding the status as an integer, headers as
/// name/value pairs, the body as bytes and the expiry as Unix seconds:
///
/// ```
/// use std::time::{Duration, UNIX_EPOCH};
/// use eve_esi_client::cache::{CachedResponse, HeaderMap, HeaderName, HeaderValue, StatusCode};
///
/// # fn rebuild() -> Result<CachedResponse, Box<dyn std::error::Error>> {
/// # let (status, header_rows, body, etag, expires_at): (i16, Vec<(String, Vec<u8>)>, Vec<u8>, Option<String>, Option<i64>)
/// #     = (200, vec![("content-type".into(), b"application/json".to_vec())], b"[]".to_vec(), Some("\"abc\"".into()), Some(1_900_000_000));
/// let mut headers = HeaderMap::new();
/// for (name, value) in header_rows {
///     // `append`, not `insert`: a header may repeat.
///     headers.append(HeaderName::from_bytes(name.as_bytes())?, HeaderValue::from_bytes(&value)?);
/// }
/// let response = CachedResponse {
///     status: StatusCode::from_u16(status as u16)?,
///     headers,
///     body: body.into(),
///     etag: etag.map(HeaderValue::try_from).transpose()?,
///     expires_at: expires_at.map(|secs| UNIX_EPOCH + Duration::from_secs(secs as u64)),
/// };
/// # Ok(response)
/// # }
/// # rebuild().unwrap();
/// ```
///
/// To store one, the reverse: `status.as_u16()`, each `(name.as_str(),
/// value.as_bytes())` of `headers.iter()`, `&body[..]`, `etag`'s
/// `to_str()`, and `expires_at.duration_since(UNIX_EPOCH)`.
#[derive(Debug, Clone)]
pub struct CachedResponse {
    pub status: StatusCode,
    /// The response headers, without ESI's error- and rate-limit headers.
    pub headers: HeaderMap,
    pub body: Bytes,
    /// Sent as `If-None-Match` once the entry is stale.
    pub etag: Option<HeaderValue>,
    /// When the entry stops being fresh: the response's `Expires`, measured
    /// against its `Date` and capped at 24 hours. `None` means it is never
    /// fresh and is always revalidated with its ETag.
    pub expires_at: Option<SystemTime>,
}

impl CachedResponse {
    /// Whether the entry may be served without asking ESI at `now`.
    pub fn is_fresh_at(&self, now: SystemTime) -> bool {
        self.expires_at.is_some_and(|at| now < at)
    }

    /// Whether a successful response with these headers is worth storing:
    /// it is fresh for a while, or it can be revalidated.
    pub(crate) fn is_cacheable(headers: &HeaderMap) -> bool {
        headers.contains_key(ETAG) || expires_from(headers).is_some()
    }

    /// Builds an entry from a successful response's parts, or `None` if it
    /// isn't [cacheable](Self::is_cacheable).
    pub(crate) fn from_parts(
        status: StatusCode,
        mut headers: HeaderMap,
        body: Bytes,
    ) -> Option<Self> {
        let expires_at = expires_from(&headers);
        let etag = headers.get(ETAG).cloned();
        if expires_at.is_none() && etag.is_none() {
            return None;
        }
        strip_budget_headers(&mut headers);
        Some(Self {
            status,
            headers,
            body,
            etag,
            expires_at,
        })
    }

    /// Applies a 304 to a stale entry: freshness and ETag from the 304, and
    /// its headers replacing the stored ones (RFC 9111 §4.3.4), except those
    /// describing the stored body. Returns the headers to answer with, which
    /// include the 304's own (current) budget headers; the entry itself keeps
    /// none.
    pub(crate) fn revalidate(&mut self, headers_304: &HeaderMap) -> HeaderMap {
        self.expires_at = expires_from(headers_304).or(self.expires_at);
        if let Some(etag) = headers_304.get(ETAG) {
            self.etag = Some(etag.clone());
        }
        let mut merged = self.headers.clone();
        for name in headers_304.keys() {
            if [
                CONTENT_LENGTH,
                CONTENT_TYPE,
                CONTENT_ENCODING,
                CONTENT_RANGE,
                TRANSFER_ENCODING,
            ]
            .contains(name)
            {
                continue;
            }
            merged.remove(name);
            for value in headers_304.get_all(name) {
                merged.append(name.clone(), value.clone());
            }
        }
        self.headers = merged.clone();
        strip_budget_headers(&mut self.headers);
        merged
    }

    /// A response carrying the cached body, `headers`, and the cache marker.
    pub(crate) fn to_response(
        &self,
        mut headers: HeaderMap,
        marker: &'static str,
    ) -> reqwest::Response {
        headers.insert(CACHE_STATUS_HEADER, HeaderValue::from_static(marker));
        let mut response = http::Response::new(self.body.clone());
        *response.status_mut() = self.status;
        *response.headers_mut() = headers;
        reqwest::Response::from(response)
    }

    /// Served as a cache hit: the stored headers, minus any budget headers
    /// a custom cache may have kept.
    pub(crate) fn to_hit(&self) -> reqwest::Response {
        let mut headers = self.headers.clone();
        strip_budget_headers(&mut headers);
        self.to_response(headers, "hit")
    }

    /// Attaches the entry's ETag as `If-None-Match`, unless the caller set
    /// their own.
    pub(crate) fn condition(&self, request: &mut reqwest::Request) {
        if let Some(etag) = &self.etag {
            if !request.headers().contains_key(IF_NONE_MATCH) {
                request.headers_mut().insert(IF_NONE_MATCH, etag.clone());
            }
        }
    }
}

/// Removes ESI's error- and rate-limit headers, which are only true of the
/// moment a response was sent.
fn strip_budget_headers(headers: &mut HeaderMap) {
    let stale: Vec<HeaderName> = headers
        .keys()
        .filter(|name| {
            let name = name.as_str();
            name.starts_with("x-esi-error-limit-") || name.starts_with("x-ratelimit-")
        })
        .cloned()
        .collect();
    for name in stale {
        headers.remove(name);
    }
}

/// The default [`EsiCache`]: in memory, per process, bounded to a few
/// thousand entries (expired ones are evicted first).
#[derive(Debug, Default)]
pub struct MemoryCache {
    entries: Mutex<HashMap<CacheKey, CachedResponse>>,
}

impl MemoryCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<CacheKey, CachedResponse>> {
        // Every write replaces a whole entry, so a panic elsewhere can't
        // leave one half-updated; the map stays usable after poisoning.
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl EsiCache for MemoryCache {
    async fn get(&self, key: &CacheKey) -> Option<CachedResponse> {
        self.lock().get(key).cloned()
    }

    async fn put(&self, key: &CacheKey, response: CachedResponse) {
        let mut entries = self.lock();
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(key) {
            let now = SystemTime::now();
            entries.retain(|_, e| e.is_fresh_at(now));
        }
        entries.insert(key.clone(), response);
    }

    async fn remove(&self, key: &CacheKey) {
        self.lock().remove(key);
    }
}

/// The key a GET is cached under, or `None` if it mustn't be cached: its
/// bearer token has no readable `sub` claim, or it carries some other kind
/// of `Authorization`.
pub(crate) fn key_for(request: &reqwest::Request) -> Option<CacheKey> {
    let principal = match request.headers().get(reqwest::header::AUTHORIZATION) {
        None => None,
        Some(value) => {
            let token = value.to_str().ok()?.strip_prefix("Bearer ")?;
            Some(crate::auth::jwt_claim(token, "sub")?.as_str()?.to_string())
        }
    };
    Some(CacheKey {
        url: request.url().to_string(),
        principal,
    })
}

/// When a response stops being fresh, from its `Expires` header. The
/// lifetime is measured against ESI's own `Date` rather than local time, so
/// client clock skew doesn't shorten or stretch it, and capped at 24 hours.
fn expires_from(headers: &HeaderMap) -> Option<SystemTime> {
    let parse_http_date = |v: &HeaderValue| {
        v.to_str()
            .ok()
            .and_then(|s| chrono::DateTime::parse_from_rfc2822(s).ok())
    };
    let expires = headers.get(EXPIRES).and_then(parse_http_date)?;
    let server_now = headers
        .get(DATE)
        .and_then(parse_http_date)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|| chrono::DateTime::<chrono::Utc>::from(SystemTime::now()));
    let lifetime = (expires.with_timezone(&chrono::Utc) - server_now)
        .to_std()
        .ok()?;
    if lifetime.is_zero() {
        return None;
    }
    Some(SystemTime::now() + lifetime.min(MAX_FRESHNESS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn http_date(offset_secs: i64) -> HeaderValue {
        let at = chrono::Utc::now() + chrono::Duration::seconds(offset_secs);
        HeaderValue::from_str(&at.format("%a, %d %b %Y %H:%M:%S GMT").to_string()).unwrap()
    }

    #[test]
    fn freshness_is_clamped_to_a_day() {
        let mut headers = HeaderMap::new();
        headers.insert(DATE, http_date(0));
        headers.insert(EXPIRES, http_date(7 * 24 * 3600));
        let expires_at = expires_from(&headers).unwrap();
        let lifetime = expires_at.duration_since(SystemTime::now()).unwrap();
        assert!(lifetime <= MAX_FRESHNESS, "{lifetime:?}");
        assert!(
            lifetime > MAX_FRESHNESS - Duration::from_secs(60),
            "{lifetime:?}"
        );
    }

    #[test]
    fn stored_entries_drop_budget_headers() {
        let mut headers = HeaderMap::new();
        headers.insert(ETAG, HeaderValue::from_static("\"a\""));
        headers.insert("x-esi-error-limit-remain", HeaderValue::from_static("100"));
        headers.insert("x-ratelimit-remaining", HeaderValue::from_static("40"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let entry = CachedResponse::from_parts(StatusCode::OK, headers, Bytes::new()).unwrap();
        assert!(entry.headers.get("x-esi-error-limit-remain").is_none());
        assert!(entry.headers.get("x-ratelimit-remaining").is_none());
        assert!(entry.headers.get(CONTENT_TYPE).is_some());
    }

    #[test]
    fn uncacheable_responses_are_not_stored() {
        let mut expired = HeaderMap::new();
        expired.insert(DATE, http_date(0));
        expired.insert(EXPIRES, http_date(0));
        for headers in [HeaderMap::new(), expired] {
            assert!(!CachedResponse::is_cacheable(&headers));
            assert!(CachedResponse::from_parts(StatusCode::OK, headers, Bytes::new()).is_none());
        }
    }

    #[test]
    fn revalidation_takes_the_304s_headers_but_keeps_the_body_description() {
        let mut stored = HeaderMap::new();
        stored.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        stored.insert("x-pages", HeaderValue::from_static("1"));
        let mut entry = CachedResponse {
            status: StatusCode::OK,
            headers: stored,
            body: Bytes::from_static(b"[]"),
            etag: Some(HeaderValue::from_static("\"old\"")),
            expires_at: None,
        };
        let mut headers_304 = HeaderMap::new();
        headers_304.insert(ETAG, HeaderValue::from_static("\"new\""));
        headers_304.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        headers_304.insert("x-pages", HeaderValue::from_static("2"));
        headers_304.insert("x-esi-error-limit-remain", HeaderValue::from_static("77"));
        let answered = entry.revalidate(&headers_304);

        assert_eq!(answered["x-pages"], "2");
        assert_eq!(answered[CONTENT_TYPE], "application/json");
        assert_eq!(answered["x-esi-error-limit-remain"], "77");
        assert_eq!(entry.etag.as_ref().unwrap(), "\"new\"");
        assert_eq!(entry.headers["x-pages"], "2");
        assert!(entry.headers.get("x-esi-error-limit-remain").is_none());
    }

    #[tokio::test]
    async fn memory_cache_evicts_expired_entries_when_full() {
        let cache = MemoryCache::new();
        let entry = |expires_at| CachedResponse {
            status: StatusCode::OK,
            headers: HeaderMap::new(),
            body: Bytes::new(),
            etag: None,
            expires_at,
        };
        let key = |i: usize| CacheKey {
            url: format!("https://esi.test/{i}"),
            principal: None,
        };
        let fresh = Some(SystemTime::now() + Duration::from_secs(60));
        cache.put(&key(0), entry(fresh)).await;
        for i in 1..MAX_ENTRIES {
            cache.put(&key(i), entry(None)).await;
        }
        cache.put(&key(MAX_ENTRIES), entry(fresh)).await;
        assert_eq!(cache.lock().len(), 2);
        assert!(cache.get(&key(0)).await.is_some());
    }
}
