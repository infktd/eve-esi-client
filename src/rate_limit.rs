//! Bookkeeping for ESI's per-group rate limits.
//!
//! Most ESI routes belong to a rate-limit group with a token budget over a
//! floating window (for example `status`: 600 tokens per 15 minutes). Every
//! response spends tokens (2xx: 2, 3xx: 1, 4xx: 5, 5xx: 0), and each spend is
//! released back to the bucket once the window has passed. An empty bucket
//! earns HTTP 429 with `Retry-After`.
//!
//! Each operation's group and budget are known before its first request,
//! from the spec's `x-rate-limit` extension (baked in by build.rs), and each
//! bucket is kept current from the `X-Ratelimit-*` response headers. Before
//! sending, a request reserves the worst-case cost of any response; if the
//! bucket can't cover that, it waits until enough earlier spends are
//! released. A client's own traffic therefore never drives a bucket into 429,
//! even with concurrent requests. A 429 anyway (for example a bucket shared
//! with another process) holds the group until `Retry-After` has elapsed.
//!
//! Waits last as long as ESI requires, which for a drained bucket can be up
//! to the full window.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::StatusCode;

include!(concat!(env!("OUT_DIR"), "/rate_limits.rs"));
include!("../build_support/rate_limit_window.rs");

const GROUP: &str = "x-ratelimit-group";
const LIMIT: &str = "x-ratelimit-limit";
const REMAINING: &str = "x-ratelimit-remaining";
const USED: &str = "x-ratelimit-used";

/// The most tokens a single response can cost (a 4xx).
const MAX_REQUEST_COST: u32 = 5;

/// How long a 429 holds its group when it carries no usable `Retry-After`.
const DEFAULT_RETRY_AFTER: Duration = Duration::from_secs(60);

/// Longest single sleep while waiting, so a waiter promptly notices capacity
/// freed by a concurrent response.
const MAX_POLL: Duration = Duration::from_secs(1);

#[derive(Debug, Default)]
pub(crate) struct RateLimiter {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    buckets: HashMap<String, Bucket>,
    /// Groups reported by response headers for operations whose group
    /// differs from, or is missing in, the spec.
    learned: HashMap<&'static str, String>,
}

#[derive(Debug)]
struct Bucket {
    max_tokens: u32,
    window: Duration,
    /// The last server-reported remaining tokens and when it was observed.
    observed: Option<(u32, Instant)>,
    /// Tokens this client spent and when, in order. Each spend is released
    /// `window` after it happened.
    spends: VecDeque<(Instant, u32)>,
    /// Worst-case tokens reserved by requests sent but not yet answered.
    in_flight: u32,
    /// Set by a 429: nothing is sent to this group before this instant.
    blocked_until: Option<Instant>,
}

impl Bucket {
    fn new(max_tokens: u32, window: Duration) -> Self {
        Self {
            max_tokens,
            window,
            observed: None,
            spends: VecDeque::new(),
            in_flight: 0,
            blocked_until: None,
        }
    }

    /// Applies everything that has happened by `now`: lifted 429 holds, stale
    /// observations, and released spends.
    fn settle(&mut self, now: Instant) {
        if self.blocked_until.is_some_and(|until| now >= until) {
            // Retry-After is ESI saying a request will be accepted again, so
            // the zero-remaining observation that came with the 429 no longer
            // describes the bucket.
            self.blocked_until = None;
            self.observed = None;
        }
        if self
            .observed
            .is_some_and(|(_, at)| now >= at + self.window)
        {
            // Every token counted as spent at that observation has since been
            // released.
            self.observed = None;
        }
        while let Some(&(spent_at, tokens)) = self.spends.front() {
            if spent_at + self.window > now {
                break;
            }
            self.spends.pop_front();
            // Spends are recorded together with the observation taken from
            // the same response, so the observation already deducts them;
            // once released they are available again.
            if let Some((remaining, at)) = &mut self.observed {
                if spent_at <= *at {
                    *remaining = remaining.saturating_add(tokens).min(self.max_tokens);
                }
            }
        }
    }

    /// Tokens a new request could use right now. Call after `settle`.
    fn available(&self) -> u32 {
        let base = match self.observed {
            Some((remaining, _)) => remaining,
            // No current server figure: assume only our own spends count.
            None => self
                .max_tokens
                .saturating_sub(self.spends.iter().map(|&(_, t)| t).sum()),
        };
        base.saturating_sub(self.in_flight)
    }

    fn reservation_cost(&self) -> u32 {
        MAX_REQUEST_COST.min(self.max_tokens)
    }

    /// The earliest instant a request could reserve its worst-case cost,
    /// ignoring traffic we can't see. Call after `settle`.
    fn ready_at(&self, now: Instant) -> Instant {
        if let Some(until) = self.blocked_until {
            return until;
        }
        let needed = self.reservation_cost();
        let mut available = self.available();
        if available >= needed {
            return now;
        }
        for &(spent_at, tokens) in &self.spends {
            let deducted = match self.observed {
                Some((_, at)) => spent_at <= at,
                None => true,
            };
            if deducted {
                available = available.saturating_add(tokens);
                if available >= needed {
                    return spent_at + self.window;
                }
            }
        }
        match self.observed {
            // By then everything the server counted as spent is released.
            Some((_, at)) => at + self.window,
            // Only in-flight reservations stand in the way, and they clear as
            // their responses arrive.
            None => now + MAX_POLL,
        }
    }
}

/// Worst-case tokens held for one in-flight request. Dropping it returns
/// them, including when the request future is cancelled.
pub(crate) struct Reservation<'a> {
    limiter: &'a RateLimiter,
    group: Option<String>,
    tokens: u32,
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if let Some(group) = &self.group {
            if let Some(bucket) = self.limiter.lock().buckets.get_mut(group) {
                bucket.in_flight = bucket.in_flight.saturating_sub(self.tokens);
            }
        }
    }
}

impl RateLimiter {
    fn lock(&self) -> MutexGuard<'_, State> {
        // Bookkeeping stays usable even if a panic poisoned the lock.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Waits until the operation's rate-limit group can cover a worst-case
    /// response, then reserves that many tokens. Operations with no known
    /// group proceed immediately.
    pub(crate) async fn acquire(&self, operation_id: &'static str) -> Reservation<'_> {
        loop {
            let wait = {
                let mut state = self.lock();
                let Some((group, bucket)) = state.bucket_for(operation_id) else {
                    return Reservation {
                        limiter: self,
                        group: None,
                        tokens: 0,
                    };
                };
                let now = Instant::now();
                bucket.settle(now);
                let ready = bucket.ready_at(now);
                if ready <= now {
                    let tokens = bucket.reservation_cost();
                    bucket.in_flight += tokens;
                    return Reservation {
                        limiter: self,
                        group: Some(group),
                        tokens,
                    };
                }
                (ready - now).min(MAX_POLL)
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// Records the rate-limit headers of a response to `operation_id`.
    pub(crate) fn record(&self, operation_id: &'static str, status: StatusCode, headers: &HeaderMap) {
        let header = |name| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
        };
        let limit = header(LIMIT).and_then(parse_limit);
        let remaining = header(REMAINING).and_then(|v| v.parse::<u32>().ok());
        let used = header(USED).and_then(|v| v.parse::<u32>().ok());
        let rate_limited = status == StatusCode::TOO_MANY_REQUESTS;
        if limit.is_none() && remaining.is_none() && used.is_none() && !rate_limited {
            // Not a rate-limited route (or served without the headers).
            return;
        }

        let mut state = self.lock();
        let spec = spec_rate_limit(operation_id);
        let group = match header(GROUP).filter(|g| !g.is_empty()) {
            Some(reported) => {
                if spec.map(|(g, ..)| g) != Some(reported) {
                    state.learned.insert(operation_id, reported.to_string());
                }
                reported.to_string()
            }
            None => match state.learned.get(operation_id) {
                Some(learned) => learned.clone(),
                None => match spec {
                    Some((g, ..)) => g.to_string(),
                    None => return,
                },
            },
        };
        let bucket = match state.buckets.entry(group) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let Some((max_tokens, window)) = limit.or_else(|| {
                    spec.map(|(_, max, secs)| (max, Duration::from_secs(secs)))
                }) else {
                    return;
                };
                e.insert(Bucket::new(max_tokens, window))
            }
        };
        if let Some((max_tokens, window)) = limit {
            bucket.max_tokens = max_tokens;
            bucket.window = window;
        }

        let now = Instant::now();
        bucket.settle(now);
        if let Some(used) = used.filter(|&u| u > 0) {
            bucket.spends.push_back((now, used));
        }
        bucket.observed = remaining.map(|r| (r.min(bucket.max_tokens), now));
        if rate_limited {
            let retry_after = header(RETRY_AFTER.as_str())
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or(DEFAULT_RETRY_AFTER);
            let until = now + retry_after;
            bucket.blocked_until = Some(bucket.blocked_until.map_or(until, |t| t.max(until)));
        }
    }
}

impl State {
    /// The group and bucket governing an operation, creating the bucket from
    /// the spec's declaration on first use. Header-reported groups win over
    /// the spec's.
    fn bucket_for(&mut self, operation_id: &'static str) -> Option<(String, &mut Bucket)> {
        let spec = spec_rate_limit(operation_id);
        let group = match self.learned.get(operation_id) {
            Some(learned) => learned.clone(),
            None => spec?.0.to_string(),
        };
        let bucket = match self.buckets.entry(group.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                let (_, max_tokens, secs) = spec?;
                e.insert(Bucket::new(max_tokens, Duration::from_secs(secs)))
            }
        };
        Some((group, bucket))
    }
}

/// Parses `X-Ratelimit-Limit`, e.g. `150/15m`.
fn parse_limit(value: &str) -> Option<(u32, Duration)> {
    let (tokens, window) = value.split_once('/')?;
    let tokens = tokens.trim().parse().ok()?;
    let secs = parse_window_size(window)?;
    Some((tokens, Duration::from_secs(secs)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(60);

    #[test]
    fn parses_limit_header_and_window_sizes() {
        assert_eq!(parse_limit("150/15m"), Some((150, Duration::from_secs(900))));
        assert_eq!(parse_limit("3600/1h"), Some((3600, Duration::from_secs(3600))));
        assert_eq!(parse_window_size("30s"), Some(30));
        assert_eq!(parse_limit("150"), None);
        assert_eq!(parse_limit("x/15m"), None);
        assert_eq!(parse_window_size("15d"), None);
        assert_eq!(parse_window_size("0m"), None);
    }

    #[test]
    fn spec_declares_rate_limits() {
        // If extraction from the spec's x-rate-limit extension silently broke,
        // the gate would never engage before a route's first response.
        assert!(SPEC_RATE_LIMITED_OPERATIONS > 0);
    }

    #[test]
    fn concurrent_reservations_cannot_overdraw_a_fresh_bucket() {
        let now = Instant::now();
        let mut bucket = Bucket::new(10, WINDOW);
        bucket.settle(now);
        assert_eq!(bucket.ready_at(now), now);
        bucket.in_flight += bucket.reservation_cost();
        assert_eq!(bucket.ready_at(now), now);
        bucket.in_flight += bucket.reservation_cost();
        // Both reservations could cost 5 each; a third must wait.
        assert!(bucket.ready_at(now) > now);
    }

    #[test]
    fn low_bucket_waits_for_its_spends_to_be_released() {
        let t0 = Instant::now();
        let mut bucket = Bucket::new(10, WINDOW);
        // Server: 1 token left after this client spent 4 at t0.
        bucket.spends.push_back((t0, 4));
        bucket.observed = Some((1, t0));
        bucket.settle(t0);
        assert_eq!(bucket.ready_at(t0), t0 + WINDOW);

        let later = t0 + WINDOW;
        bucket.settle(later);
        assert!(bucket.available() >= MAX_REQUEST_COST);
        assert_eq!(bucket.ready_at(later), later);
    }

    #[test]
    fn earliest_sufficient_release_is_chosen() {
        let t0 = Instant::now();
        let mut bucket = Bucket::new(100, WINDOW);
        bucket.spends.push_back((t0, 2));
        bucket.spends.push_back((t0 + Duration::from_secs(10), 2));
        bucket.observed = Some((1, t0 + Duration::from_secs(10)));
        let now = t0 + Duration::from_secs(20);
        bucket.settle(now);
        // 1 + 2 (released at t0+60s) = 3, + 2 (released at t0+70s) = 5.
        assert_eq!(bucket.ready_at(now), t0 + Duration::from_secs(70));
    }

    #[test]
    fn stale_observation_is_dropped() {
        let t0 = Instant::now();
        let mut bucket = Bucket::new(10, WINDOW);
        bucket.observed = Some((0, t0));
        bucket.settle(t0 + WINDOW);
        assert_eq!(bucket.observed, None);
        assert_eq!(bucket.available(), 10);
    }

    #[test]
    fn rate_limited_group_is_held_until_retry_after() {
        let t0 = Instant::now();
        let mut bucket = Bucket::new(10, WINDOW);
        bucket.observed = Some((0, t0));
        bucket.blocked_until = Some(t0 + Duration::from_secs(5));
        bucket.settle(t0);
        assert_eq!(bucket.ready_at(t0), t0 + Duration::from_secs(5));

        let lifted = t0 + Duration::from_secs(5);
        bucket.settle(lifted);
        assert_eq!(bucket.blocked_until, None);
        assert_eq!(bucket.ready_at(lifted), lifted);
    }

    #[test]
    fn dropping_a_reservation_returns_its_tokens() {
        let limiter = RateLimiter::default();
        limiter
            .lock()
            .buckets
            .insert("g".to_string(), Bucket::new(10, WINDOW));
        limiter.lock().buckets.get_mut("g").unwrap().in_flight = 5;
        drop(Reservation {
            limiter: &limiter,
            group: Some("g".to_string()),
            tokens: 5,
        });
        assert_eq!(limiter.lock().buckets["g"].in_flight, 0);
    }
}
