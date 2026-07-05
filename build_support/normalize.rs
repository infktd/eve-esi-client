// Spec normalizations applied in memory before progenitor codegen.
// Each rule is documented in spec/README.md. This file is `include!`d by
// both build.rs and tests/golden_codegen.rs so the golden-file test
// exercises exactly the pipeline the build uses.

const SPEC_HTTP_METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
];

fn for_each_operation(spec: &mut serde_json::Value, mut f: impl FnMut(&mut serde_json::Value)) {
    let Some(paths) = spec
        .get_mut("paths")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    for path_item in paths.values_mut() {
        for method in SPEC_HTTP_METHODS {
            if let Some(op) = path_item.get_mut(method) {
                f(op);
            }
        }
    }
}

/// ESI declares every operation as `200` (typed payload) + `default` (the
/// `Error` envelope). Progenitor counts `default` toward the *success*
/// response group and asserts on two distinct success types, so rewrite
/// `default` into explicit `4XX`/`5XX` error ranges — which is what ESI's
/// `default` means — whenever an explicit 2xx response exists.
///
/// Additionally, progenitor supports only one success shape per operation.
/// Two contract endpoints declare a typed `200` plus an empty `204`
/// ("no longer available"); drop the bodiless secondary codes — at runtime
/// they surface as `Error::UnexpectedResponse`, which callers can match on.
fn normalize_responses(spec: &mut serde_json::Value) {
    for_each_operation(spec, |op| {
        let Some(responses) = op
            .get_mut("responses")
            .and_then(serde_json::Value::as_object_mut)
        else {
            return;
        };
        let two_xx: Vec<String> = responses
            .keys()
            .filter(|k| k.starts_with('2'))
            .cloned()
            .collect();
        if two_xx.len() > 1 {
            for code in two_xx.iter().filter(|c| c.as_str() != "200") {
                println!("cargo:warning=dropping secondary success response {code}");
                responses.remove(code);
            }
        }
        if two_xx.is_empty() {
            return;
        }
        let Some(default) = responses.remove("default") else {
            return;
        };
        for range in ["4XX", "5XX"] {
            if !responses.contains_key(range) {
                responses.insert(range.to_string(), default.clone());
            }
        }
    });
}

/// Every ESI operation requires an `X-Compatibility-Date` header whose only
/// legal value is the date this spec was resolved at (it's an enum with a
/// single variant). Making all 200+ generated methods take that argument
/// would be noise with exactly one correct answer, so strip the parameter
/// here and let the crate inject the header on every request instead (see
/// `Client::builder` in lib.rs). Returns the date for embedding as
/// `COMPATIBILITY_DATE`.
fn strip_compatibility_date_param(spec: &mut serde_json::Value) -> String {
    let date = spec
        .pointer("/components/parameters/CompatibilityDate/schema/enum/0")
        .and_then(serde_json::Value::as_str)
        .expect("spec no longer pins X-Compatibility-Date to a single value")
        .to_string();
    for_each_operation(spec, |op| {
        let Some(params) = op
            .get_mut("parameters")
            .and_then(serde_json::Value::as_array_mut)
        else {
            return;
        };
        params.retain(|p| {
            p.pointer("/$ref").and_then(serde_json::Value::as_str)
                != Some("#/components/parameters/CompatibilityDate")
        });
    });
    date
}
