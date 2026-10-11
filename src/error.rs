//! Reading ESI's error responses.
//!
//! Every ESI operation fails with [`crate::Error<types::Error>`]. A response
//! with an error status (4xx/5xx) arrives as
//! [`crate::Error::ErrorResponse`], whose value is ESI's error body:
//!
//! ```no_run
//! use eve_esi_client::ErrorExt as _;
//! # async fn run(client: eve_esi_client::Client) {
//! match client.get_characters_character_id_fleet().character_id(1).send().await {
//!     Ok(fleet) => println!("in fleet {}", fleet.fleet_id),
//!     Err(e) if e.status() == Some(reqwest::StatusCode::NOT_FOUND) => println!("not in a fleet"),
//!     Err(e) => println!("{:?}: {:?}", e.status(), e.esi_message()),
//! }
//! # }
//! ```
//!
//! ESI's own errors are JSON (`{"error": "..."}`), but not every error
//! response is: a proxy in front of ESI can answer with an HTML page, and
//! some errors have an empty body. The client rewrites such bodies into
//! ESI's shape, `{"error": <the body as text, or the status's reason>,
//! "status": <code>}`, so they too arrive as `ErrorResponse` with their
//! status (and count as retryable where the status is), instead of as an
//! [`crate::Error::InvalidResponsePayload`] that has lost it.

use bytes::Bytes;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE};
use reqwest::StatusCode;

use crate::types;

/// Longest error-body text kept when rewriting a non-JSON error body.
const MAX_ERROR_TEXT: usize = 2048;

/// Accessors for ESI's error responses on [`crate::Error`].
///
/// The status itself is [`crate::Error::status`].
pub trait ErrorExt {
    /// ESI's error message: the `error` field of an error response (for a
    /// non-JSON error body, its text). `None` for failures that never got an
    /// error response, such as a network error or a token that couldn't be
    /// obtained ([`crate::Error::Custom`]).
    fn esi_message(&self) -> Option<&str>;

    /// The error response's body, as ESI's error type, if there was one.
    fn esi_error(&self) -> Option<&types::Error>;
}

impl ErrorExt for crate::Error<types::Error> {
    fn esi_message(&self) -> Option<&str> {
        self.esi_error().map(|e| e.error.as_str())
    }

    fn esi_error(&self) -> Option<&types::Error> {
        match self {
            crate::Error::ErrorResponse(value) => Some(&**value),
            _ => None,
        }
    }
}

/// Whether `body` already has ESI's error shape: a JSON object with a
/// string `error`.
fn is_esi_error_body(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").map(serde_json::Value::is_string))
        .unwrap_or(false)
}

/// For an error status whose body isn't ESI's error JSON, the replacement
/// body and headers; `None` to pass the response on unchanged.
pub(crate) fn normalize_error_body(
    status: StatusCode,
    headers: &HeaderMap,
    body: &Bytes,
) -> Option<(HeaderMap, Bytes)> {
    if !(status.is_client_error() || status.is_server_error()) || is_esi_error_body(body) {
        return None;
    }
    let text = String::from_utf8_lossy(body);
    let text = text.trim();
    let message = if text.is_empty() {
        status
            .canonical_reason()
            .map(str::to_string)
            .unwrap_or_else(|| format!("HTTP {}", status.as_u16()))
    } else {
        let mut end = text.len().min(MAX_ERROR_TEXT);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text[..end].to_string()
    };
    let body = serde_json::json!({ "error": message, "status": status.as_u16() });
    let mut headers = headers.clone();
    headers.remove(CONTENT_LENGTH);
    headers.remove(CONTENT_ENCODING);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    Some((headers, Bytes::from(body.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esi_error_bodies_pass_through() {
        let body = Bytes::from_static(br#"{"error":"Character not in fleet"}"#);
        assert!(normalize_error_body(StatusCode::NOT_FOUND, &HeaderMap::new(), &body).is_none());
        let ok = Bytes::from_static(b"<html>");
        assert!(normalize_error_body(StatusCode::OK, &HeaderMap::new(), &ok).is_none());
    }

    #[test]
    fn other_error_bodies_are_rewritten() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html"));
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("12"));
        headers.insert("x-esi-error-limit-remain", HeaderValue::from_static("99"));
        let (new_headers, body) = normalize_error_body(
            StatusCode::BAD_GATEWAY,
            &headers,
            &Bytes::from_static(b" <html>502</html> "),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"error": "<html>502</html>", "status": 502})
        );
        assert_eq!(new_headers[CONTENT_TYPE], "application/json");
        assert!(new_headers.get(CONTENT_LENGTH).is_none());
        assert_eq!(new_headers["x-esi-error-limit-remain"], "99");

        for body in [&b""[..], b"{\"error\": {\"nested\": 1}}", b"[1]"] {
            let (_, out) = normalize_error_body(
                StatusCode::FORBIDDEN,
                &HeaderMap::new(),
                &Bytes::copy_from_slice(body),
            )
            .unwrap();
            let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
            assert_eq!(json["status"], 403);
            assert!(json["error"].is_string());
        }
        let (_, empty) =
            normalize_error_body(StatusCode::FORBIDDEN, &HeaderMap::new(), &Bytes::new()).unwrap();
        assert!(String::from_utf8_lossy(&empty).contains("\"Forbidden\""));
    }

    #[test]
    fn long_bodies_are_truncated_on_a_char_boundary() {
        let text = "é".repeat(MAX_ERROR_TEXT);
        let (_, out) = normalize_error_body(
            StatusCode::SERVICE_UNAVAILABLE,
            &HeaderMap::new(),
            &Bytes::from(text),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert!(json["error"].as_str().unwrap().len() <= MAX_ERROR_TEXT);
    }
}
