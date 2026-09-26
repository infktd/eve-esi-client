//! A caller-supplied `EsiCache` gets the same ESI caching rules as the
//! built-in one: fresh responses are served without a request, stale ones
//! revalidate, and entries are keyed by who fetched them. Responses served
//! from a cache are marked and never replay stale budget headers.
//!
//! The fixture is `GET /alliances` (a bare array of IDs) so CCP schema
//! changes can't invalidate it.

use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use chrono::{Duration as ChronoDuration, Utc};
use eve_esi_client::auth::{Authenticator, SsoClient, TokenSet};
use eve_esi_client::cache::{CacheKey, CachedResponse, EsiCache, MemoryCache};
use httpmock::prelude::*;

mod common;

const ALLIANCES_BODY: &str = "[99000001, 99000002, 99000003]";
const ALLIANCE_COUNT: usize = 3;
const CACHE_HEADER: &str = "x-esi-client-cache";

/// A [`MemoryCache`] that records every call, standing in for a shared or
/// persistent store.
#[derive(Default)]
struct RecordingCache {
    store: MemoryCache,
    calls: Mutex<Vec<(&'static str, CacheKey)>>,
}

impl RecordingCache {
    fn calls(&self, kind: &str) -> Vec<CacheKey> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| *k == kind)
            .map(|(_, key)| key.clone())
            .collect()
    }
}

#[eve_esi_client::async_trait]
impl EsiCache for RecordingCache {
    async fn get(&self, key: &CacheKey) -> Option<CachedResponse> {
        self.calls.lock().unwrap().push(("get", key.clone()));
        self.store.get(key).await
    }
    async fn put(&self, key: &CacheKey, response: CachedResponse) {
        self.calls.lock().unwrap().push(("put", key.clone()));
        self.store.put(key, response).await
    }
    async fn remove(&self, key: &CacheKey) {
        self.calls.lock().unwrap().push(("remove", key.clone()));
        self.store.remove(key).await
    }
}

fn builder_for(server: &MockServer, cache: &Arc<RecordingCache>) -> eve_esi_client::ClientBuilder {
    common::install_crypto_provider();
    eve_esi_client::Client::builder()
        .user_agent("eve-esi tests")
        .base_url(server.base_url())
        .cache(cache.clone())
}

fn http_date(offset_secs: i64) -> String {
    (Utc::now() + ChronoDuration::seconds(offset_secs))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// An unsigned JWT for `character_id`: enough for the client, which reads
/// the `sub` claim without verifying it.
fn access_token_for(character_id: u64) -> String {
    let encode = |json: String| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
    format!(
        "{}.{}.signature",
        encode(r#"{"alg":"none"}"#.to_string()),
        encode(format!(
            r#"{{"sub":"CHARACTER:EVE:{character_id}","name":"Pilot"}}"#
        )),
    )
}

fn authenticator(access_token: String) -> Authenticator {
    let sso = SsoClient::new("test-client", "http://localhost:8787/callback").unwrap();
    Authenticator::new(
        sso,
        TokenSet {
            access_token,
            refresh_token: None,
            // Never expires, so the test never tries to refresh.
            expires_at: None,
        },
    )
}

#[tokio::test]
async fn shared_cache_serves_a_restarted_client_without_stale_budgets() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("Date", http_date(0))
                .header("Expires", http_date(60))
                .header("X-ESI-Error-Limit-Remain", "100")
                .header("X-ESI-Error-Limit-Reset", "60")
                .header("X-Ratelimit-Group", "test-group")
                .header("X-Ratelimit-Limit", "150/15m")
                .header("X-Ratelimit-Remaining", "148")
                .header("X-Ratelimit-Used", "2")
                .body(ALLIANCES_BODY);
        })
        .await;
    let cache = Arc::new(RecordingCache::default());

    let first_client = builder_for(&server, &cache).build().unwrap();
    let fetched = first_client.get_alliances().send().await.unwrap();
    assert_eq!(fetched.len(), ALLIANCE_COUNT);
    // A response straight from ESI is untouched.
    assert!(fetched.headers().get(CACHE_HEADER).is_none());
    assert_eq!(fetched.headers()["x-esi-error-limit-remain"], "100");

    let puts = cache.calls("put");
    assert_eq!(puts.len(), 1);
    assert!(puts[0].url.ends_with("/alliances"), "{:?}", puts[0]);
    assert_eq!(puts[0].principal, None);
    let stored = cache.store.get(&puts[0]).await.unwrap();
    let lifetime = stored
        .expires_at
        .unwrap()
        .duration_since(SystemTime::now())
        .unwrap();
    assert!(lifetime <= Duration::from_secs(60) && lifetime > Duration::from_secs(55));
    assert!(stored.headers.get("x-esi-error-limit-remain").is_none());
    assert!(stored.headers.get("x-ratelimit-remaining").is_none());

    // A new client (as after a restart) shares the store.
    let restarted = builder_for(&server, &cache).build().unwrap();
    let hit = restarted.get_alliances().send().await.unwrap();
    assert_eq!(
        mock.calls_async().await,
        1,
        "must be served from the shared cache"
    );
    assert_eq!(hit.len(), ALLIANCE_COUNT);
    assert_eq!(hit.status(), 200);
    assert_eq!(hit.headers()[CACHE_HEADER], "hit");
    assert_eq!(hit.headers()["content-type"], "application/json");
    for stale in [
        "x-esi-error-limit-remain",
        "x-esi-error-limit-reset",
        "x-ratelimit-group",
        "x-ratelimit-remaining",
    ] {
        assert!(hit.headers().get(stale).is_none(), "{stale} replayed");
    }
    // Nothing reached ESI, so the restarted client has no budget to report.
    assert_eq!(restarted.error_budget(), None);
    assert_eq!(first_client.error_budget().unwrap().remain, 100);
}

#[tokio::test]
async fn revalidated_responses_are_marked_and_carry_the_304s_budgets() {
    let server = MockServer::start_async().await;
    let initial = server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("ETag", "\"abc123\"")
                .header("X-ESI-Error-Limit-Remain", "100")
                .header("X-ESI-Error-Limit-Reset", "60")
                .body(ALLIANCES_BODY);
        })
        .await;
    let cache = Arc::new(RecordingCache::default());
    let client = builder_for(&server, &cache).build().unwrap();
    client.get_alliances().send().await.unwrap();
    initial.delete_async().await;

    let revalidation = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/alliances")
                .header("If-None-Match", "\"abc123\"");
            then.status(304)
                .header("Date", http_date(0))
                .header("Expires", http_date(60))
                .header("ETag", "\"abc123\"")
                .header("X-ESI-Error-Limit-Remain", "55")
                .header("X-ESI-Error-Limit-Reset", "40");
        })
        .await;
    let revalidated = client.get_alliances().send().await.unwrap();
    assert_eq!(revalidation.calls_async().await, 1);
    assert_eq!(revalidated.len(), ALLIANCE_COUNT);
    assert_eq!(revalidated.status(), 200);
    assert_eq!(revalidated.headers()[CACHE_HEADER], "revalidated");
    assert_eq!(revalidated.headers()["x-esi-error-limit-remain"], "55");
    assert_eq!(revalidated.headers()["content-type"], "application/json");
    assert_eq!(client.error_budget().unwrap().remain, 55);

    let key = &cache.calls("put")[0];
    assert_eq!(cache.calls("put").len(), 2, "the refreshed entry is stored");
    let stored = cache.store.get(key).await.unwrap();
    assert!(stored.is_fresh_at(SystemTime::now()));
    assert!(stored.headers.get("x-esi-error-limit-remain").is_none());

    let hit = client.get_alliances().send().await.unwrap();
    assert_eq!(revalidation.calls_async().await, 1);
    assert_eq!(hit.headers()[CACHE_HEADER], "hit");
}

#[tokio::test]
async fn entry_is_removed_when_the_route_stops_sending_cache_metadata() {
    let server = MockServer::start_async().await;
    let initial = server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("ETag", "\"abc123\"")
                .body(ALLIANCES_BODY);
        })
        .await;
    let cache = Arc::new(RecordingCache::default());
    let client = builder_for(&server, &cache).build().unwrap();
    client.get_alliances().send().await.unwrap();
    initial.delete_async().await;

    server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .body(ALLIANCES_BODY);
        })
        .await;
    let fetched = client.get_alliances().send().await.unwrap();
    assert_eq!(fetched.len(), ALLIANCE_COUNT);
    let removed = cache.calls("remove");
    assert_eq!(removed.len(), 1);
    assert!(cache.store.get(&removed[0]).await.is_none());
}

#[tokio::test]
async fn authenticated_entries_are_keyed_by_character() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("Date", http_date(0))
                .header("Expires", http_date(60))
                .body(ALLIANCES_BODY);
        })
        .await;
    let cache = Arc::new(RecordingCache::default());
    let first = builder_for(&server, &cache)
        .authenticator(authenticator(access_token_for(1)))
        .build()
        .unwrap();
    let second = builder_for(&server, &cache)
        .authenticator(authenticator(access_token_for(2)))
        .build()
        .unwrap();

    first.get_alliances().send().await.unwrap();
    let hit = first.get_alliances().send().await.unwrap();
    assert_eq!(hit.headers()[CACHE_HEADER], "hit");
    assert_eq!(mock.calls_async().await, 1);

    let other = second.get_alliances().send().await.unwrap();
    assert_eq!(
        mock.calls_async().await,
        2,
        "another character must not share the entry"
    );
    assert!(other.headers().get(CACHE_HEADER).is_none());

    let principals: Vec<_> = cache
        .calls("put")
        .into_iter()
        .map(|key| key.principal)
        .collect();
    assert_eq!(
        principals,
        [
            Some("CHARACTER:EVE:1".to_string()),
            Some("CHARACTER:EVE:2".to_string())
        ]
    );
}

#[tokio::test]
async fn tokens_without_a_readable_subject_are_never_cached() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("Date", http_date(0))
                .header("Expires", http_date(60))
                .body(ALLIANCES_BODY);
        })
        .await;
    let cache = Arc::new(RecordingCache::default());
    let client = builder_for(&server, &cache)
        .authenticator(authenticator("opaque-token".to_string()))
        .build()
        .unwrap();

    client.get_alliances().send().await.unwrap();
    client.get_alliances().send().await.unwrap();
    assert_eq!(mock.calls_async().await, 2);
    assert!(
        cache.calls.lock().unwrap().is_empty(),
        "the cache must not be consulted"
    );
}

#[tokio::test]
async fn http_cache_false_disables_a_supplied_cache() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("Date", http_date(0))
                .header("Expires", http_date(60))
                .body(ALLIANCES_BODY);
        })
        .await;
    let cache = Arc::new(RecordingCache::default());
    let client = builder_for(&server, &cache)
        .http_cache(false)
        .build()
        .unwrap();

    client.get_alliances().send().await.unwrap();
    client.get_alliances().send().await.unwrap();
    assert_eq!(mock.calls_async().await, 2);
    assert!(cache.calls.lock().unwrap().is_empty());
}
