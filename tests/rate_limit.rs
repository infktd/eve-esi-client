//! The client must respect ESI's per-group rate limits end to end: back off
//! before a group's bucket runs dry, and hold a group after a 429 until
//! `Retry-After`.
//!
//! Mock responses use short windows ("2s") so the tests finish quickly; ESI
//! itself uses 15-minute windows. The fixture is `GET /alliances` (a bare
//! array of IDs) so CCP schema changes can't invalidate it.

use std::time::{Duration, Instant};

use httpmock::prelude::*;

const ALLIANCES_BODY: &str = "[99000001, 99000002, 99000003]";

fn client_for(server: &MockServer) -> eve_esi_client::Client {
    eve_esi_client::Client::builder()
        .user_agent("eve-esi tests")
        .base_url(server.base_url())
        // These tests are about rate limits, not caching.
        .http_cache(false)
        .build()
        .unwrap()
}

#[tokio::test]
async fn backs_off_before_a_group_runs_dry() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("X-Ratelimit-Group", "test-group")
                .header("X-Ratelimit-Limit", "10/2s")
                // 4 left is less than a worst-case response costs (5), so
                // the next request must wait for this one's 2 tokens to be
                // released when the 2-second window passes.
                .header("X-Ratelimit-Remaining", "4")
                .header("X-Ratelimit-Used", "2")
                .body(ALLIANCES_BODY);
        })
        .await;
    let client = client_for(&server);

    let start = Instant::now();
    client.get_alliances().send().await.unwrap();
    let first_done = start.elapsed();
    client.get_alliances().send().await.unwrap();
    let second_done = start.elapsed();

    assert_eq!(mock.calls_async().await, 2);
    assert!(
        first_done < Duration::from_secs(1),
        "first request must not be delayed (took {first_done:?})"
    );
    assert!(
        second_done >= Duration::from_secs(2),
        "second request must wait for tokens to be released (took {second_done:?})"
    );
    assert!(
        second_done < Duration::from_secs(5),
        "wait must end once enough tokens are released (took {second_done:?})"
    );
}

#[tokio::test]
async fn healthy_group_budget_adds_no_delay() {
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("X-Ratelimit-Group", "test-group")
                .header("X-Ratelimit-Limit", "600/15m")
                .header("X-Ratelimit-Remaining", "500")
                .header("X-Ratelimit-Used", "2")
                .body(ALLIANCES_BODY);
        })
        .await;
    let client = client_for(&server);

    let start = Instant::now();
    for _ in 0..5 {
        client.get_alliances().send().await.unwrap();
    }
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "requests with a healthy budget must not be throttled"
    );
}

#[tokio::test]
async fn holds_a_group_until_retry_after_following_a_429() {
    let server = MockServer::start_async().await;
    let limited = server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(429)
                .header("content-type", "application/json")
                .header("Retry-After", "2")
                .header("X-Ratelimit-Group", "test-group")
                .header("X-Ratelimit-Limit", "600/15m")
                .header("X-Ratelimit-Remaining", "0")
                .header("X-Ratelimit-Used", "5")
                .body(r#"{"error": "rate limited"}"#);
        })
        .await;
    let client = client_for(&server);

    let start = Instant::now();
    assert!(
        client.get_alliances().send().await.is_err(),
        "a 429 must surface to the caller"
    );
    limited.delete_async().await;

    let ok = server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("X-Ratelimit-Group", "test-group")
                .header("X-Ratelimit-Limit", "600/15m")
                .header("X-Ratelimit-Remaining", "590")
                .header("X-Ratelimit-Used", "2")
                .body(ALLIANCES_BODY);
        })
        .await;

    client.get_alliances().send().await.unwrap();
    let elapsed = start.elapsed();
    assert_eq!(ok.calls_async().await, 1);
    assert!(
        elapsed >= Duration::from_secs(2),
        "the next request must wait out Retry-After (took {elapsed:?})"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "the hold must lift once Retry-After has passed (took {elapsed:?})"
    );
}
