//! Phase 2 definition-of-done: a deliberately fast-polling client must back
//! off before crossing the error-limit threshold.
//!
//! Uses a mock ESI rather than the real one — intentionally burning CCP's
//! error budget to test backoff is exactly what the limiter exists to
//! prevent.
//!
//! The mock serves `GET /alliances`, whose response is a bare array of IDs.
//! These tests exercise the request pipeline, not any payload schema, so the
//! fixture must be a shape CCP can't break by renaming or requiring fields.

use std::time::{Duration, Instant};

use httpmock::prelude::*;

const ALLIANCES_BODY: &str = "[99000001, 99000002, 99000003]";

fn client_for(server: &MockServer) -> eve_esi_client::Client {
    eve_esi_client::Client::builder()
        .user_agent("eve-esi tests")
        .base_url(server.base_url())
        .build()
        .unwrap()
}

#[tokio::test]
async fn holds_requests_when_error_budget_reaches_threshold() {
    let server = MockServer::start_async().await;
    let mock = server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                // Remaining budget == default threshold (10): the next
                // request must wait out the 2-second reset window.
                .header("X-ESI-Error-Limit-Remain", "10")
                .header("X-ESI-Error-Limit-Reset", "2")
                .body(ALLIANCES_BODY);
        })
        .await;
    let client = client_for(&server);

    let start = Instant::now();
    client.get_alliances().send().await.unwrap();
    let first_done = start.elapsed();
    client.get_alliances().send().await.unwrap();
    let second_done = start.elapsed();

    assert_eq!(mock.calls_async().await, 2, "both requests must reach ESI");
    assert!(
        first_done < Duration::from_secs(1),
        "first request must not be delayed (took {first_done:?})"
    );
    assert!(
        second_done >= Duration::from_secs(2),
        "second request must wait out the error window (took {second_done:?})"
    );
}

#[tokio::test]
async fn healthy_error_budget_adds_no_delay() {
    let server = MockServer::start_async().await;
    server
        .mock_async(|when, then| {
            when.method(GET).path("/alliances");
            then.status(200)
                .header("content-type", "application/json")
                .header("X-ESI-Error-Limit-Remain", "100")
                .header("X-ESI-Error-Limit-Reset", "60")
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
