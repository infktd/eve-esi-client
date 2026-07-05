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
        Some("spec-diff") => match (args.get(1), args.get(2)) {
            (Some(old), Some(new)) => spec_diff(old, new),
            _ => {
                eprintln!("usage: cargo run -p xtask -- spec-diff <old.json> <new.json>");
                std::process::exit(2);
            }
        },
        _ => {
            eprintln!(
                "usage: cargo run -p xtask -- fetch-spec [compatibility-date]\n\
                        cargo run -p xtask -- spec-diff <old.json> <new.json>"
            );
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

/// Compare two spec files and print a Markdown change report to stdout,
/// classifying each change as additive or breaking to guide the reviewer's
/// semver decision. Used by the spec-check workflow to annotate its PRs.
fn spec_diff(old_path: &str, new_path: &str) {
    let load = |p: &str| -> serde_json::Value {
        serde_json::from_str(&std::fs::read_to_string(p).expect("failed to read spec"))
            .expect("spec is not valid JSON")
    };
    let old = load(old_path);
    let new = load(new_path);

    let mut changes: Vec<Change> = Vec::new();
    diff_versions(&old, &new, &mut changes);
    diff_paths(&old, &new, &mut changes);
    diff_schemas(&old, &new, &mut changes);

    let verdict = changes.iter().map(|c| c.kind).max().unwrap_or(Kind::Info);
    println!("## Spec change report\n");
    println!(
        "**Overall: {}**\n",
        match verdict {
            Kind::Info => "no API surface changes detected",
            Kind::Additive => "looks additive (minor version bump)",
            Kind::Review => "has changes needing review",
            Kind::Breaking => "potentially BREAKING (major version bump)",
        }
    );
    if changes.is_empty() {
        println!("No differences in routes, operations, or schemas.");
        return;
    }
    for kind in [Kind::Breaking, Kind::Review, Kind::Additive, Kind::Info] {
        let section: Vec<&Change> = changes.iter().filter(|c| c.kind == kind).collect();
        if section.is_empty() {
            continue;
        }
        println!(
            "### {}\n",
            match kind {
                Kind::Breaking => "Breaking",
                Kind::Review => "Needs review",
                Kind::Additive => "Additive",
                Kind::Info => "Info",
            }
        );
        for change in section {
            println!("- {}", change.what);
        }
        println!();
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Info,
    Additive,
    Review,
    Breaking,
}

struct Change {
    kind: Kind,
    what: String,
}

fn keys(v: &serde_json::Value, pointer: &str) -> Vec<String> {
    v.pointer(pointer)
        .and_then(serde_json::Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn diff_versions(old: &serde_json::Value, new: &serde_json::Value, changes: &mut Vec<Change>) {
    let version = |v: &serde_json::Value| {
        v.pointer("/info/version")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?")
            .to_string()
    };
    let (o, n) = (version(old), version(new));
    if o != n {
        changes.push(Change {
            kind: Kind::Info,
            what: format!("compatibility date: `{o}` -> `{n}`"),
        });
    }
}

fn diff_paths(old: &serde_json::Value, new: &serde_json::Value, changes: &mut Vec<Change>) {
    const METHODS: [&str; 8] = [
        "get", "put", "post", "delete", "patch", "head", "options", "trace",
    ];
    let old_paths = keys(old, "/paths");
    let new_paths = keys(new, "/paths");

    for path in &new_paths {
        if !old_paths.contains(path) {
            changes.push(Change {
                kind: Kind::Additive,
                what: format!("new route `{path}`"),
            });
        }
    }
    for path in &old_paths {
        if !new_paths.contains(path) {
            changes.push(Change {
                kind: Kind::Breaking,
                what: format!("route removed: `{path}`"),
            });
        }
    }

    for path in new_paths.iter().filter(|p| old_paths.contains(p)) {
        let pointer = format!("/paths/{}", path.replace('~', "~0").replace('/', "~1"));
        for method in METHODS {
            let o = old.pointer(&format!("{pointer}/{method}"));
            let n = new.pointer(&format!("{pointer}/{method}"));
            let label = format!("`{} {path}`", method.to_uppercase());
            match (o, n) {
                (None, Some(_)) => changes.push(Change {
                    kind: Kind::Additive,
                    what: format!("new operation {label}"),
                }),
                (Some(_), None) => changes.push(Change {
                    kind: Kind::Breaking,
                    what: format!("operation removed: {label}"),
                }),
                (Some(o), Some(n)) if o != n => diff_operation(o, n, &label, changes),
                _ => {}
            }
        }
    }
}

fn diff_operation(
    old: &serde_json::Value,
    new: &serde_json::Value,
    label: &str,
    changes: &mut Vec<Change>,
) {
    let params = |v: &serde_json::Value| -> Vec<(String, bool)> {
        v.get("parameters")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|p| {
                        (
                            p.get("name")
                                .or_else(|| p.get("$ref"))
                                .and_then(serde_json::Value::as_str)
                                .unwrap_or("?")
                                .to_string(),
                            p.get("required")
                                .and_then(serde_json::Value::as_bool)
                                .unwrap_or(false),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let (old_params, new_params) = (params(old), params(new));
    for (name, required) in &new_params {
        if !old_params.iter().any(|(n, _)| n == name) {
            changes.push(Change {
                kind: if *required { Kind::Breaking } else { Kind::Additive },
                what: format!(
                    "{label}: new {} parameter `{name}`",
                    if *required { "required" } else { "optional" }
                ),
            });
        }
    }
    for (name, _) in &old_params {
        if !new_params.iter().any(|(n, _)| n == name) {
            changes.push(Change {
                kind: Kind::Breaking,
                what: format!("{label}: parameter removed: `{name}`"),
            });
        }
    }
    if old.get("responses") != new.get("responses")
        || old.get("requestBody") != new.get("requestBody")
    {
        changes.push(Change {
            kind: Kind::Review,
            what: format!("{label}: request/response definition changed"),
        });
    }
}

fn diff_schemas(old: &serde_json::Value, new: &serde_json::Value, changes: &mut Vec<Change>) {
    let old_schemas = keys(old, "/components/schemas");
    let new_schemas = keys(new, "/components/schemas");

    for name in &new_schemas {
        if !old_schemas.contains(name) {
            changes.push(Change {
                kind: Kind::Additive,
                what: format!("new schema `{name}`"),
            });
        }
    }
    for name in &old_schemas {
        if !new_schemas.contains(name) {
            changes.push(Change {
                kind: Kind::Breaking,
                what: format!("schema removed: `{name}`"),
            });
        }
    }

    for name in new_schemas.iter().filter(|s| old_schemas.contains(s)) {
        let pointer = format!("/components/schemas/{name}");
        let (Some(o), Some(n)) = (old.pointer(&pointer), new.pointer(&pointer)) else {
            continue;
        };
        if o == n {
            continue;
        }
        let props = |v: &serde_json::Value| keys(v, "/properties");
        let required = |v: &serde_json::Value| -> Vec<String> {
            v.get("required")
                .and_then(serde_json::Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default()
        };
        let (old_props, new_props) = (props(o), props(n));
        let mut noted = false;
        for prop in &new_props {
            if !old_props.contains(prop) {
                let req = required(n).contains(prop);
                changes.push(Change {
                    kind: if req { Kind::Review } else { Kind::Additive },
                    what: format!(
                        "schema `{name}`: new {} field `{prop}`",
                        if req { "required" } else { "optional" }
                    ),
                });
                noted = true;
            }
        }
        for prop in &old_props {
            if !new_props.contains(prop) {
                changes.push(Change {
                    kind: Kind::Breaking,
                    what: format!("schema `{name}`: field removed: `{prop}`"),
                });
                noted = true;
            }
        }
        for prop in new_props.iter().filter(|p| old_props.contains(*p)) {
            let sub = format!("{pointer}/properties/{prop}");
            if old.pointer(&sub) != new.pointer(&sub) {
                let type_of = |v: &serde_json::Value| {
                    v.pointer(&format!("{sub}/type"))
                        .cloned()
                        .unwrap_or_default()
                };
                changes.push(Change {
                    kind: if type_of(old) != type_of(new) {
                        Kind::Breaking
                    } else {
                        Kind::Review
                    },
                    what: format!("schema `{name}`: field `{prop}` definition changed"),
                });
                noted = true;
            }
        }
        if !noted {
            changes.push(Change {
                kind: Kind::Review,
                what: format!("schema `{name}` changed (not at field level)"),
            });
        }
    }
}
