//! Generates the ESI client from `spec/esi-latest.json` at compile time.
//!
//! The committed spec is exactly what CCP publishes (pretty-printed); the
//! normalizations in `build_support/normalize.rs` happen in memory only and
//! are documented in `spec/README.md`.

use serde_json::Value;

include!("build_support/normalize.rs");

const SPEC_PATH: &str = "spec/esi-latest.json";

fn main() {
    println!("cargo:rerun-if-changed={SPEC_PATH}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build_support/normalize.rs");

    let file = std::fs::File::open(SPEC_PATH).expect("failed to open spec file");
    let mut raw: Value = serde_json::from_reader(file).expect("spec is not valid JSON");

    normalize_responses(&mut raw);
    let compatibility_date = strip_compatibility_date_param(&mut raw);
    let base_url = raw
        .pointer("/servers/0/url")
        .and_then(Value::as_str)
        .expect("spec declares no server URL")
        .to_string();
    let sso_authorize_url = raw
        .pointer("/components/securitySchemes/OAuth2/flows/authorizationCode/authorizationUrl")
        .and_then(Value::as_str)
        .expect("spec declares no OAuth2 authorization URL")
        .to_string();
    let sso_token_url = raw
        .pointer("/components/securitySchemes/OAuth2/flows/authorizationCode/tokenUrl")
        .and_then(Value::as_str)
        .expect("spec declares no OAuth2 token URL")
        .to_string();

    let spec: openapiv3::OpenAPI =
        serde_json::from_value(raw).expect("spec failed to parse as OpenAPI 3.0");

    let mut settings = progenitor::GenerationSettings::default();
    settings.with_interface(progenitor::InterfaceStyle::Builder);
    settings.with_inner_type("crate::EsiInner".parse().unwrap());
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
         pub const BASE_URL: &str = \"{base_url}\";\n\
         \n\
         /// EVE SSO authorization endpoint, from the spec's OAuth2 security scheme.\n\
         pub const SSO_AUTHORIZE_URL: &str = \"{sso_authorize_url}\";\n\
         \n\
         /// EVE SSO token endpoint, from the spec's OAuth2 security scheme.\n\
         pub const SSO_TOKEN_URL: &str = \"{sso_token_url}\";\n"
    ));

    let mut out_file = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    out_file.push("codegen.rs");
    std::fs::write(out_file, content).expect("failed to write generated code");
}
