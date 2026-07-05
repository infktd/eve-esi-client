//! Repo maintenance tasks, invoked as `cargo run -p xtask -- <command>`.

use std::io::Read;

// CCP publishes the same spec surface in several formats; use their native
// OpenAPI 3.0 conversion because progenitor consumes 3.0.x only — this keeps
// the 3.1-to-3.0 downconversion on CCP's side of the fence instead of ours.
// (3.1 lives at /meta/openapi.json, YAML variants also exist.)
const SPEC_URL: &str = "https://esi.evetech.net/meta/openapi-3.0.json";
const SPEC_PATH: &str = "spec/esi-latest.json";

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("fetch-spec") => fetch_spec(args.get(1).map(String::as_str)),
        _ => {
            eprintln!("usage: cargo run -p xtask -- fetch-spec [compatibility-date]");
            std::process::exit(2);
        }
    }
}

/// Fetch ESI's published OpenAPI spec and write it to `spec/esi-latest.json`,
/// pretty-printed with key order preserved so that spec updates produce
/// small, human-readable git diffs.
///
/// The spec surface is selected by ESI's compatibility-date versioning: the
/// server resolves the requested date down to the newest published
/// compatibility date that is not after it. Defaults to today (UTC), i.e.
/// "the newest spec there is" — the resolved date is recorded by the server
/// in the spec's own `info.version` field.
fn fetch_spec(compatibility_date: Option<&str>) {
    let date = compatibility_date
        .map(String::from)
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());
    let url = format!("{SPEC_URL}?compatibility_date={date}");
    eprintln!("fetching {url}");

    let response = ureq::get(&url).call().expect("failed to fetch spec");
    let mut body = String::new();
    response
        .into_reader()
        .read_to_string(&mut body)
        .expect("failed to read spec response body");

    let spec: serde_json::Value =
        serde_json::from_str(&body).expect("spec response is not valid JSON");

    let openapi = spec.get("openapi").and_then(|v| v.as_str()).unwrap_or("?");
    let version = spec
        .pointer("/info/version")
        .and_then(|v| v.as_str())
        .unwrap_or("?");
    let paths = spec
        .get("paths")
        .and_then(|v| v.as_object())
        .map(|m| m.len())
        .unwrap_or(0);
    eprintln!("openapi {openapi}, resolved compatibility date {version}, {paths} paths");

    let mut out = serde_json::to_string_pretty(&spec).expect("failed to serialize spec");
    out.push('\n');
    std::fs::write(SPEC_PATH, out).expect("failed to write spec file");
    eprintln!("wrote {SPEC_PATH}");
}
