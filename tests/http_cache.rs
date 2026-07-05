//! The wrapper must honor ESI's caching rules: never re-request a route
//! before its `Expires` elapses, and revalidate stale routes with
//! `If-None-Match`, resurrecting the cached body on 304.

use chrono::{Duration as ChronoDuration, Utc};
use httpmock::prelude::*;

const STATUS_BODY: &str =
    r#"{"players": 777, "server_version": "42", "start_time": "2026-07-05T11:00:00Z"}"#;

fn client_for(server: &MockServer) -> eve_esi::Client {
    eve_esi::Client::builder()
        .user_agent("eve-esi tests")
        .base_url(server.base_url())
        .build()
        .unwrap()
}

fn http_date(offset_secs: i64) -> String {
    (Utc::now() + ChronoDuration::seconds(offset_secs))
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

#[tokio::test]
async fn fresh_response_is_not_rerequested_before_expires() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/status");
            then.status(200)
                .header("content-type", "application/json")
                .header("Date", http_date(0))
                .header("Expires", http_date(60))
                .body(STATUS_BODY);
        })
        .await;
    let client = client_for(&server);

    let first = client.get_status().send().await.unwrap();
    let second = client.get_status().send().await.unwrap();

    assert_eq!(
        mock.hits_async().await,
        1,
        "second request within the Expires window must be served from cache"
    );
    assert_eq!(first.players, 777);
    assert_eq!(second.players, first.players);
}

#[tokio::test]
async fn stale_response_revalidates_with_etag_and_resurrects_304() {
    let server = MockServer::start_async().await;
    // Already-expired response carrying an ETag: cacheable for
    // revalidation, but stale immediately.
    let initial = server
        .mock_async(|when, then| {
            when.method(GET).path("/status");
            then.status(200)
                .header("content-type", "application/json")
                .header("Date", http_date(0))
                .header("Expires", http_date(0))
                .header("ETag", "\"abc123\"")
                .body(STATUS_BODY);
        })
        .await;
    let client = client_for(&server);

    let first = client.get_status().send().await.unwrap();
    assert_eq!(first.players, 777);
    initial.delete_async().await;

    // Now the server only answers 304 — and only if the client presents
    // the ETag it was given.
    let revalidation = server
        .mock_async(|when, then| {
            when.method(GET)
                .path("/status")
                .header("If-None-Match", "\"abc123\"");
            then.status(304)
                .header("Date", http_date(0))
                .header("Expires", http_date(60))
                .header("ETag", "\"abc123\"");
        })
        .await;

    let second = client.get_status().send().await.unwrap();
    assert_eq!(revalidation.hits_async().await, 1);
    assert_eq!(
        second.players, 777,
        "304 must transparently resurrect the cached body"
    );

    // The 304 carried a fresh Expires — a third call must not hit the
    // network at all.
    let third = client.get_status().send().await.unwrap();
    assert_eq!(revalidation.hits_async().await, 1);
    assert_eq!(third.players, 777);
}
