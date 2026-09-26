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

use std::time::SystemTime;

use bytes::Bytes;
use progenitor_client::{ClientHooks, ClientInfo as _, Error, OperationInfo};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use reqwest::{Method, StatusCode};

use crate::cache::{self, CachedResponse};
use crate::Client;

impl ClientHooks<crate::EsiInner> for Client {
    async fn pre<E>(
        &self,
        request: &mut reqwest::Request,
        _info: &OperationInfo,
    ) -> Result<(), Error<E>> {
        // User-Agent and X-Compatibility-Date, set per request so they also
        // reach ESI through a caller-supplied reqwest::Client.
        for (name, value) in &self.inner().default_headers {
            if !request.headers().contains_key(name) {
                request.headers_mut().insert(name, value.clone());
            }
        }
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
        let cache = match (request.method(), &self.inner().cache) {
            (&Method::GET, Some(cache)) => cache::key_for(&request).map(|key| (cache, key)),
            _ => None,
        };
        let mut stale = None;
        if let Some((cache, key)) = &cache {
            if let Some(entry) = cache.get(key).await {
                if entry.is_fresh_at(SystemTime::now()) {
                    return Ok(entry.to_hit());
                }
                entry.condition(&mut request);
                stale = Some(entry);
            }
        }
        // Error-limit first: waiting on it while holding rate-limit tokens
        // would starve other requests to the same group.
        self.inner().limiter.acquire().await;
        let reservation = self.inner().rate_limiter.acquire(info.operation_id).await;
        let result = self.client().execute(request).await;
        if let Ok(response) = &result {
            self.inner().limiter.record(response.headers());
            self.inner().rate_limiter.record(
                info.operation_id,
                response.status(),
                response.headers(),
            );
        }
        // Release the worst-case reservation only after the actual spend is
        // recorded, so capacity is never briefly double-counted.
        drop(reservation);
        let response = result?;
        let Some((cache, key)) = cache else {
            return Ok(response);
        };
        if response.status() == StatusCode::NOT_MODIFIED {
            // With nothing cached (e.g. the caller supplied their own
            // If-None-Match) the 304 passes through untouched.
            if let Some(mut entry) = stale {
                let headers = entry.revalidate(response.headers());
                let revalidated = entry.to_response(headers, "revalidated");
                cache.put(&key, entry).await;
                return Ok(revalidated);
            }
        } else if response.status().is_success() {
            if !CachedResponse::is_cacheable(response.headers()) {
                // The old entry's ETag no longer describes this route.
                if stale.is_some() {
                    cache.remove(&key).await;
                }
                return Ok(response);
            }
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes().await?;
            // The caller gets the response as ESI sent it, budget headers
            // included; only the stored copy drops them.
            let replay = replay(status, headers.clone(), body.clone());
            if let Some(entry) = CachedResponse::from_parts(status, headers, body) {
                cache.put(&key, entry).await;
            }
            return Ok(replay);
        }
        Ok(response)
    }
}

fn replay(
    status: StatusCode,
    headers: reqwest::header::HeaderMap,
    body: Bytes,
) -> reqwest::Response {
    let mut response = http::Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    reqwest::Response::from(response)
}
