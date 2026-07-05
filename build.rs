//! Generates the ESI client from `spec/esi-latest.json` at compile time.
//!
//! The committed spec is exactly what CCP publishes (pretty-printed); the
//! normalizations below happen in memory only. Each one is documented in
//! `spec/README.md`.

use serde_json::Value;

const SPEC_PATH: &str = "spec/esi-latest.json";

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "patch", "head", "options", "trace",
];

fn for_each_operation(spec: &mut Value, mut f: impl FnMut(&mut Value)) {
    let Some(paths) = spec.get_mut("paths").and_then(Value::as_object_mut) else {
        return;
    };
    for path_item in paths.values_mut() {
        for method in METHODS {
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
fn normalize_responses(spec: &mut Value) {
    for_each_operation(spec, |op| {
        let Some(responses) = op.get_mut("responses").and_then(Value::as_object_mut) else {
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
/// `Client::builder` in lib.rs). The date itself is extracted from the spec
/// and baked in as `COMPATIBILITY_DATE`.
fn strip_compatibility_date_param(spec: &mut Value) -> String {
    let date = spec
        .pointer("/components/parameters/CompatibilityDate/schema/enum/0")
        .and_then(Value::as_str)
        .expect("spec no longer pins X-Compatibility-Date to a single value")
        .to_string();
    for_each_operation(spec, |op| {
        let Some(params) = op.get_mut("parameters").and_then(Value::as_array_mut) else {
            return;
        };
        params.retain(|p| {
            p.pointer("/$ref").and_then(Value::as_str)
                != Some("#/components/parameters/CompatibilityDate")
        });
    });
    date
}

fn main() {
    println!("cargo:rerun-if-changed={SPEC_PATH}");
    println!("cargo:rerun-if-changed=build.rs");

    let file = std::fs::File::open(SPEC_PATH).expect("failed to open spec file");
    let mut raw: Value = serde_json::from_reader(file).expect("spec is not valid JSON");

    normalize_responses(&mut raw);
    let compatibility_date = strip_compatibility_date_param(&mut raw);
    let base_url = raw
        .pointer("/servers/0/url")
        .and_then(Value::as_str)
        .expect("spec declares no server URL")
        .to_string();

    let spec: openapiv3::OpenAPI =
        serde_json::from_value(raw).expect("spec failed to parse as OpenAPI 3.0");

    let mut settings = progenitor::GenerationSettings::default();
    settings.with_interface(progenitor::InterfaceStyle::Builder);
    let mut generator = progenitor::Generator::new(&settings);
    let tokens = generator
        .generate_tokens(&spec)
        .expect("progenitor failed to generate client");
    let ast = syn::parse2(tokens).expect("failed to parse generated tokens");
    let mut content = prettyplease::unparse(&ast);

    content.push_str(&format!(
        "\n/// The ESI compatibility date this client was generated against.\n\
         ///\n\
         /// Sent automatically as the `X-Compatibility-Date` header on every\n\
         /// request made through [`Client`].\n\
         pub const COMPATIBILITY_DATE: &str = \"{compatibility_date}\";\n\
         \n\
         /// ESI's base URL, from the spec's `servers` entry.\n\
         pub const BASE_URL: &str = \"{base_url}\";\n"
    ));

    let mut out_file = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    out_file.push("codegen.rs");
    std::fs::write(out_file, content).expect("failed to write generated code");
}
