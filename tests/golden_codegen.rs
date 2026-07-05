//! Golden-file codegen test: run the exact build.rs pipeline (same
//! normalization code, via include!) against a pinned historical spec
//! snapshot and require a generated method for every operation in it.
//!
//! This catches regressions in the crate's own codegen pipeline — a
//! progenitor upgrade or a normalization edit that silently drops
//! endpoints — independent of whether CCP has changed anything.

include!("../build_support/normalize.rs");

const GOLDEN_SPEC: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/golden/esi-spec-2026-06-09.json"
);

fn pascal_to_snake(id: &str) -> String {
    let mut out = String::with_capacity(id.len() + 8);
    for (i, c) in id.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

#[test]
fn every_operation_in_the_pinned_spec_generates_a_method() {
    let raw = std::fs::read_to_string(GOLDEN_SPEC).expect("golden spec must be readable");
    let mut spec_json: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

    normalize_responses(&mut spec_json);
    let compatibility_date = strip_compatibility_date_param(&mut spec_json);
    assert_eq!(compatibility_date, "2026-06-09");

    // Collect expected method names before handing the spec to progenitor.
    let mut expected: Vec<String> = Vec::new();
    for_each_operation(&mut spec_json, |op| {
        let id = op
            .get("operationId")
            .and_then(serde_json::Value::as_str)
            .expect("every operation has an operationId");
        expected.push(pascal_to_snake(id));
    });
    assert_eq!(
        expected.len(),
        218,
        "pinned spec must contain exactly its known operation count"
    );

    let spec: openapiv3::OpenAPI =
        serde_json::from_value(spec_json).expect("normalized spec must parse as OpenAPI 3.0");
    let mut settings = progenitor::GenerationSettings::default();
    settings.with_interface(progenitor::InterfaceStyle::Builder);
    settings.with_inner_type("crate::EsiInner".parse().unwrap());
    let tokens = progenitor::Generator::new(&settings)
        .generate_tokens(&spec)
        .expect("progenitor must generate the pinned spec");
    let text = tokens.to_string();

    let missing: Vec<&String> = expected
        .iter()
        .filter(|m| !text.contains(&format!("fn {m} ")))
        .collect();
    assert!(
        missing.is_empty(),
        "generated client is missing methods for: {missing:?}"
    );
}
