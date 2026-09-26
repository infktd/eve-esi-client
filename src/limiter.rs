//! Bookkeeping for ESI's error-rate limit.
//!
//! ESI reports the error budget on every response via
//! `X-ESI-Error-Limit-Remain` (errors left in the current window) and
//! `X-ESI-Error-Limit-Reset` (seconds until the window resets). Exceeding
//! the budget earns HTTP 420s and, if ignored, an IP ban. The limiter
//! records these headers from every response and, once the remaining budget
//! drops to a configurable threshold, holds new requests until the window
//! has reset.

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub(crate) const ERROR_LIMIT_REMAIN: &str = "x-esi-error-limit-remain";
pub(crate) const ERROR_LIMIT_RESET: &str = "x-esi-error-limit-reset";

#[derive(Debug)]
pub(crate) struct ErrorLimiter {
    threshold: u32,
    state: Mutex<Option<Window>>,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    remain: u32,
    reset_at: Instant,
}

impl Default for ErrorLimiter {
    fn default() -> Self {
        Self::new(10)
    }
}

impl ErrorLimiter {
    pub(crate) fn new(threshold: u32) -> Self {
        Self {
            threshold,
            state: Mutex::new(None),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Option<Window>> {
        // The state is a single Copy value, always written whole, so it is
        // valid even if a panic poisoned the lock.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The error budget last reported by ESI, or `None` if nothing has been
    /// reported yet or the reported window has since reset.
    pub(crate) fn budget(&self) -> Option<crate::ErrorBudget> {
        let window = (*self.lock())?;
        let resets_in = window.reset_at.checked_duration_since(Instant::now())?;
        if resets_in.is_zero() {
            return None;
        }
        Some(crate::ErrorBudget {
            remain: window.remain,
            resets_in,
        })
    }

    /// Blocks (asynchronously) while the remaining error budget is at or
    /// below the threshold, until the current error window has reset.
    pub(crate) async fn acquire(&self) {
        let wait = {
            let state = self.lock();
            match *state {
                Some(w) if w.remain <= self.threshold => {
                    w.reset_at.checked_duration_since(Instant::now())
                }
                _ => None,
            }
        };
        if let Some(wait) = wait {
            // A little padding so we don't race the server's own clock.
            tokio::time::sleep(wait + Duration::from_millis(500)).await;
            let mut state = self.lock();
            if let Some(w) = *state {
                if Instant::now() >= w.reset_at {
                    *state = None;
                }
            }
        }
    }

    /// Records the error-limit headers from a response.
    pub(crate) fn record(&self, headers: &reqwest::header::HeaderMap) {
        let parse = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u32>().ok())
        };
        let (Some(remain), Some(reset)) =
            (parse(ERROR_LIMIT_REMAIN), parse(ERROR_LIMIT_RESET))
        else {
            return;
        };
        let mut state = self.lock();
        *state = Some(Window {
            remain,
            reset_at: Instant::now() + Duration::from_secs(u64::from(reset)),
        });
    }
}
