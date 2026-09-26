//! Client configuration downstream code relies on: a caller-supplied
//! reqwest client, readable error and rate budgets, and sharing backoff with
//! a cache-less copy of a client's state.
//!
//! The fixture is `GET /alliances` (a bare array of IDs) so CCP schema
//! changes can't invalidate it.

use std::time::Duration;

use chrono::{Duration as ChronoDuration, Utc};
use eve_esi_client::{Client, ClientInfo as _, EsiInner, COMPATIBILITY_DATE};
use httpmock::prelude::*;

mod common;

const ALLIANCES_BODY: &str = "[99000001, 99000002, 99000003]";

fn http_date(offset_secs: i64) -> String {
    (Utc::now() + ChronoDuration::seconds(offset_secs))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

fn builder_for(server: &MockServer) -> eve_esi_client::ClientBuilder {
    common::install_crypto_provider();
    Client::builder()
        .user_agent("eve-esi tests")
        .base_url(server.base_url())
}

#[tokio::test]
async fn supplied_http_client_still_sends_esi_headers() {
    common::install_crypto_provider();
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/alliances")
                .header("x-egress", "allow-listed")
                .header("user-agent", "eve-esi tests")
                .header("x-compatibility-date", COMPATIBILITY_DATE);
            then.status(200)
                .header("content-type", "application/json")
                .body(ALLIANCES_BODY);
        })
        .await;
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("x-egress", "allow-listed".parse().unwrap());
    let http = reqwest::Client::builder()
        .default_headers(headers)
        .user_agent("tether-egress/1.0")
        .build()
        .unwrap();
    let client = builder_for(&server).http_client(http).build().unwrap();

    client.get_alliances().send().await.unwrap();
    assert_eq!(mock.calls_async().await, 1);
}

#[tokio::test]
async fn default_http_client_sends_esi_headers() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/alliances")
                .header("user-agent", "eve-esi tests")
                .header("x-compatibility-date", COMPATIBILITY_DATE);
            then.status(200)
                .header("content-type", "application/json")
                .body(ALLIANCES_BODY);
        })
        .await;
    let client = builder_for(&server).build().unwrap();

    client.get_alliances().send().await.unwrap();
    assert_eq!(mock.calls_async().await, 1);
}

#[tokio::test]
async fn error_budget_is_readable() {
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("X-ESI-Error-Limit-Remain", "57")
                .header("X-ESI-Error-Limit-Reset", "30")
                .body(ALLIANCES_BODY);
        })
        .await;
    let client = builder_for(&server).http_cache(false).build().unwrap();
    assert_eq!(client.error_budget(), None, "nothing reported yet");

    client.get_alliances().send().await.unwrap();
    let budget = client.error_budget().unwrap();
    assert_eq!(budget.remain, 57);
    assert!(
        budget.resets_in <= Duration::from_secs(30) && budget.resets_in > Duration::from_secs(29),
        "{budget:?}"
    );
    assert_eq!(client.inner().error_budget().unwrap().remain, 57);
}

#[tokio::test]
async fn rate_budgets_are_readable_and_show_429_holds() {
    let server = MockServer::start_async().await;
    let ok = server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("X-Ratelimit-Group", "test-group")
                .header("X-Ratelimit-Limit", "150/15m")
                .header("X-Ratelimit-Remaining", "140")
                .header("X-Ratelimit-Used", "2")
                .body(ALLIANCES_BODY);
        })
        .await;
    let client = builder_for(&server).http_cache(false).build().unwrap();

    client.get_alliances().send().await.unwrap();
    let budgets = client.rate_budgets();
    let budget = budgets
        .iter()
        .find(|b| b.group == "test-group")
        .unwrap_or_else(|| panic!("no test-group in {budgets:?}"));
    assert_eq!(budget.max_tokens, 150);
    assert_eq!(budget.window, Duration::from_secs(15 * 60));
    assert_eq!(budget.remaining_estimate, 140);
    assert_eq!(budget.blocked_for, None);
    ok.delete_async().await;

    server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(429)
                .header("X-Ratelimit-Group", "test-group")
                .header("X-Ratelimit-Limit", "150/15m")
                .header("X-Ratelimit-Remaining", "0")
                .header("Retry-After", "30");
        })
        .await;
    client.get_alliances().send().await.unwrap_err();
    let budgets = client.inner().rate_budgets();
    let budget = budgets.iter().find(|b| b.group == "test-group").unwrap();
    assert_eq!(budget.remaining_estimate, 0);
    let blocked_for = budget.blocked_for.unwrap();
    assert!(
        blocked_for <= Duration::from_secs(30) && blocked_for > Duration::from_secs(29),
        "{blocked_for:?}"
    );
}

/// Token-bearing calls that must never be cached still share backoff with
/// the main client.
#[tokio::test]
async fn without_cache_shares_limiters_but_never_caches() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/alliances")
                .header("user-agent", "eve-esi tests");
            then.status(200)
                .header("content-type", "application/json")
                .header("Date", http_date(0))
                .header("Expires", http_date(60))
                .header("X-ESI-Error-Limit-Remain", "80")
                .header("X-ESI-Error-Limit-Reset", "60")
                .body(ALLIANCES_BODY);
        })
        .await;
    let client = builder_for(&server).build().unwrap();
    let uncached = Client::new_with_client(
        &server.base_url(),
        reqwest::Client::new(),
        client.inner().without_cache(),
    );

    uncached.get_alliances().send().await.unwrap();
    uncached.get_alliances().send().await.unwrap();
    assert_eq!(mock.calls_async().await, 2, "without_cache must not cache");
    assert_eq!(
        client.error_budget().unwrap().remain,
        80,
        "the error limiter must be shared"
    );

    client.get_alliances().send().await.unwrap();
    client.get_alliances().send().await.unwrap();
    assert_eq!(mock.calls_async().await, 3, "the original keeps its cache");
}

#[tokio::test]
async fn default_inner_with_new_with_client_still_works() {
    common::install_crypto_provider();
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
    let client = Client::new_with_client(
        &server.base_url(),
        reqwest::Client::new(),
        EsiInner::default(),
    );
    client.get_alliances().send().await.unwrap();
    client.get_alliances().send().await.unwrap();
    assert_eq!(
        mock.calls_async().await,
        2,
        "EsiInner::default() has no cache"
    );
}

#[test]
fn oauth2_types_are_reachable_without_depending_on_oauth2() {
    let verifier = eve_esi_client::auth::PkceCodeVerifier::new("v".repeat(43));
    let _: &eve_esi_client::oauth2::PkceCodeVerifier = &verifier;
    let state = eve_esi_client::auth::CsrfToken::new("state".to_string());
    assert_eq!(state.secret(), "state");
}
