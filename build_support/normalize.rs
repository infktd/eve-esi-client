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

/// ESI models tagged unions as a `oneOf` of single-property objects —
/// `{"faction": {..}}` | `{"alliance": {..}}` | `{"unclaimed": true}` — but
/// never marks the lone property `required`. Typify turns a non-required
/// property into `Option` + `serde(default)`, so every branch accepts every
/// object and the resulting enum deserializes every value as its *first*
/// variant, silently dropping the payload.
///
/// For every `oneOf`/`anyOf` anywhere in the spec (components, inline
/// schemas, array `items`, `additionalProperties`), mark the property of each
/// single-property object branch as required. The property name *is* the
/// discriminant, and with it required typify emits an externally tagged enum
/// (`Alliance(SovereigntySystemsAlliance)`) that serde discriminates on the
/// key itself.
///
/// Branches this rule can't safely fix are left untouched and returned so
/// build.rs can surface them as `cargo:warning`s instead of mis-parsing in
/// silence: multi-property object branches (which property discriminates
/// would be a guess), and `$ref` branches to an under-constrained object
/// (patching a shared component would change it everywhere it's used).
fn require_union_discriminants(spec: &mut serde_json::Value) -> Vec<String> {
    let mut branches = Vec::new();
    collect_union_branches(spec, String::new(), &mut branches);

    let mut unresolved = Vec::new();
    for pointer in branches {
        let Some(branch) = spec.pointer(&pointer) else {
            continue;
        };
        if let Some(target) = branch.get("$ref").and_then(serde_json::Value::as_str) {
            let target = target.to_string();
            let resolved = target
                .strip_prefix('#')
                .and_then(|p| spec.pointer(p))
                .and_then(underconstrained_object_properties);
            if resolved.is_some() {
                unresolved.push(format!(
                    "{pointer}: union branch refers to {target}, an object with no `required` \
                     list; its variant can't be discriminated and will mis-parse"
                ));
            }
            continue;
        }
        match underconstrained_object_properties(branch).as_deref() {
            None => {}
            Some([only]) => {
                let required = serde_json::Value::Array(vec![only.clone().into()]);
                spec.pointer_mut(&pointer)
                    .and_then(serde_json::Value::as_object_mut)
                    .expect("branch pointer was just resolved to an object")
                    .insert("required".to_string(), required);
            }
            Some(props) => unresolved.push(format!(
                "{pointer}: union branch has properties {props:?} and no `required` list; \
                 its variant can't be discriminated and will mis-parse"
            )),
        }
    }
    unresolved
}

/// JSON pointers of every `oneOf`/`anyOf` branch at or below `value`.
fn collect_union_branches(value: &serde_json::Value, pointer: String, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_pointer =
                    format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                if matches!(key.as_str(), "oneOf" | "anyOf") {
                    if let Some(branches) = child.as_array() {
                        out.extend((0..branches.len()).map(|i| format!("{child_pointer}/{i}")));
                    }
                }
                collect_union_branches(child, child_pointer, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                collect_union_branches(child, format!("{pointer}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// Property names of an object schema that declares properties but no
/// (or an empty) `required` list; `None` for anything else.
fn underconstrained_object_properties(schema: &serde_json::Value) -> Option<Vec<String>> {
    let is_object = match schema.get("type") {
        Some(ty) => ty == "object",
        None => schema.get("properties").is_some(),
    };
    let has_required = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|r| !r.is_empty());
    let properties = schema.get("properties")?.as_object()?;
    (is_object && !has_required && !properties.is_empty())
        .then(|| properties.keys().cloned().collect())
}
