//! The request pipeline for every generated method.
//!
//! Progenitor's generated `Client` routes each call through
//! [`ClientHooks::pre`] → [`ClientHooks::exec`]. Overriding the trait for
//! `Client` (auto-ref specialization over the generated no-op impl on
//! `&Client`) lets this one impl apply auth, rate-limit and error-limit
//! backoff, and HTTP caching to the entire endpoint surface.
//!
//! Limits are gated after the cache lookup: a response served from the
//! cache never touches the network, so it neither waits nor spends tokens.

use progenitor_client::{ClientHooks, ClientInfo as _, Error, OperationInfo};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::{Method, StatusCode};

use crate::Client;

impl ClientHooks<crate::EsiInner> for Client {
    async fn pre<E>(
        &self,
        request: &mut reqwest::Request,
        _info: &OperationInfo,
    ) -> Result<(), Error<E>> {
        if let Some(auth) = &self.inner().auth {
            let token = auth
                .access_token()
                .await
                .map_err(|e| Error::Custom(e.to_string()))?;
            let mut value = HeaderValue::try_from(format!("Bearer {token}"))
                .map_err(|e| Error::Custom(e.to_string()))?;
            value.set_sensitive(true);
            request.headers_mut().insert(AUTHORIZATION, value);
        }
        Ok(())
    }

    async fn exec(
        &self,
        mut request: reqwest::Request,
        info: &OperationInfo,
    ) -> reqwest::Result<reqwest::Response> {
        let cache = match request.method() {
            &Method::GET => self.inner().cache.as_deref(),
            _ => None,
        };
        if let Some(cache) = cache {
            if let Some(hit) = cache.lookup(&mut request) {
                return Ok(hit);
            }
        }
        // Error-limit first: waiting on it while holding rate-limit tokens
        // would starve other requests to the same group.
        self.inner().limiter.acquire().await;
        let reservation = self.inner().rate_limiter.acquire(info.operation_id).await;
        let url = request.url().clone();
        let result = self.client().execute(request).await;
        if let Ok(response) = &result {
            self.inner().limiter.record(response.headers());
            self.inner()
                .rate_limiter
                .record(info.operation_id, response.status(), response.headers());
        }
        // Release the worst-case reservation only after the actual spend is
        // recorded, so capacity is never briefly double-counted.
        drop(reservation);
        let response = result?;
        if let Some(cache) = cache {
            if response.status() == StatusCode::NOT_MODIFIED {
                if let Some(hit) = cache.revalidated(&url, response.headers()) {
                    return Ok(hit);
                }
            } else if response.status().is_success() {
                return cache.store(response).await;
            }
        }
        Ok(response)
    }
}
