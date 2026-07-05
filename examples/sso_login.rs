//! Full EVE SSO round-trip: PKCE authorization, token exchange, and an
//! authenticated ESI call.
//!
//! Register an application at <https://developers.eveonline.com/> with
//! callback URL `http://localhost:8787/callback` and the
//! `esi-location.read_location.v1` scope, then run:
//!
//! ```text
//! cargo run --example sso_login -- <client_id>
//! ```

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;

use eve_esi_client::auth::{Authenticator, SsoClient};

const REDIRECT_URI: &str = "http://localhost:8787/callback";
const SCOPE: &str = "esi-location.read_location.v1";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client_id = std::env::args()
        .nth(1)
        .ok_or("usage: cargo run --example sso_login -- <client_id>")?;

    let sso = SsoClient::new(client_id, REDIRECT_URI)?;
    let pending = sso.authorize([SCOPE]);
    println!("Open this URL in your browser and log in:\n\n{}\n", pending.url);

    // Catch the redirect. One request is all we need.
    let listener = TcpListener::bind("127.0.0.1:8787")?;
    let (code, state) = {
        let (mut stream, _) = listener.accept()?;
        let request_line = {
            let mut line = String::new();
            BufReader::new(&stream).read_line(&mut line)?;
            line
        };
        // GET /callback?code=...&state=... HTTP/1.1
        let query = request_line
            .split_whitespace()
            .nth(1)
            .and_then(|path| path.split_once('?'))
            .map(|(_, q)| q)
            .ok_or("callback carried no query string")?;
        let mut code = None;
        let mut state = None;
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("code", v)) => code = Some(v.to_string()),
                Some(("state", v)) => state = Some(v.to_string()),
                _ => {}
            }
        }
        stream.write_all(
            b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\nLogged in - you can close this tab.",
        )?;
        (
            code.ok_or("callback carried no authorization code")?,
            state.ok_or("callback carried no state")?,
        )
    };

    if state != *pending.csrf_state.secret() {
        return Err("CSRF state mismatch - aborting".into());
    }

    let tokens = sso.exchange(code, pending.pkce_verifier).await?;
    let character_id = tokens.character_id().ok_or("token carries no character id")?;
    println!(
        "Logged in as {} (character {character_id}), token expires {:?}, refresh token: {}",
        tokens.character_name().unwrap_or_default(),
        tokens.expires_at,
        if tokens.refresh_token.is_some() { "yes" } else { "no" },
    );

    let client = eve_esi_client::Client::builder()
        .user_agent("eve-esi sso example (jay.nejati@outlook.com)")
        .authenticator(Authenticator::new(sso, tokens))
        .build()?;
    let location = client
        .get_characters_character_id_location()
        .character_id(eve_esi_client::types::CharacterId(character_id as i64))
        .send()
        .await?;
    println!("Current solar system: {}", location.solar_system_id);

    Ok(())
}
