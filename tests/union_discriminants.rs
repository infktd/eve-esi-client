//! ESI's `oneOf` unions are objects keyed by variant name
//! (`{"alliance": {..}}`), with the key never marked `required` in CCP's
//! spec. Left alone, typify generated untagged enums whose every variant
//! accepted every value, so everything parsed as the first variant. These
//! tests pin the normalization that fixes it (`require_union_discriminants`)
//! and the generated types it produces.
//!
//! Unlike the pipeline tests, the deserialization fixtures here are coupled
//! to ESI payload schemas on purpose — they are shaped like real responses,
//! because what's under test is how real responses parse.

include!("../build_support/normalize.rs");

use eve_esi_client::types::{
    CorporationsProjectsDetailConfiguration,
    CorporationsProjectsDetailConfigurationcapturefwcomplexLocationsItem as LocationsItem,
    SovereigntySystems, SovereigntySystemsSolarsystemClaim as Claim,
};

const BUNDLED_SPEC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/spec/esi-latest.json");

/// One claim of each kind, verbatim from live `GET /sovereignty/systems`.
const SOVEREIGNTY_BODY: &str = r#"{"solar_systems": [
  {"solar_system_id": 30000001, "claim": {"faction": {"faction_id": 500007}}},
  {"solar_system_id": 30000208, "claim": {"alliance": {
    "alliance_id": 99003581, "corporation_id": 98599770,
    "claimed_since": "2020-10-08T00:38:16Z",
    "sovereignty_hub": {"id": 1034510825648, "vulnerability_window":
      {"start": "2026-09-22T09:30:00Z", "end": "2026-09-22T12:30:00Z"}},
    "is_capital_system": false,
    "development": {"activity_defense_multiplier": 6.0,
      "military_level": 5, "industrial_level": 5, "strategic_level": 5}}}},
  {"solar_system_id": 30000326, "claim": {"unclaimed": true}}
]}"#;

#[test]
fn sovereignty_claims_land_in_their_own_variants() {
    let body: SovereigntySystems = serde_json::from_str(SOVEREIGNTY_BODY).unwrap();
    let [faction, alliance, unclaimed] = body.solar_systems.as_slice() else {
        panic!("expected three systems, got {}", body.solar_systems.len());
    };

    assert_eq!(*faction.solar_system_id, 30000001);
    match &faction.claim {
        Claim::Faction(f) => assert_eq!(*f.faction_id, 500007),
        other => panic!("faction claim parsed as {other:?}"),
    }

    assert_eq!(*alliance.solar_system_id, 30000208);
    match &alliance.claim {
        Claim::Alliance(a) => {
            assert_eq!(*a.alliance_id, 99003581);
            assert_eq!(*a.corporation_id, 98599770);
            assert_eq!(*a.sovereignty_hub.id, 1034510825648);
        }
        other => panic!("alliance claim parsed as {other:?}"),
    }

    assert_eq!(*unclaimed.solar_system_id, 30000326);
    assert!(
        matches!(unclaimed.claim, Claim::Unclaimed(true)),
        "unclaimed claim parsed as {:?}",
        unclaimed.claim
    );
}

#[test]
fn project_location_items_discriminate_on_their_key() {
    let region: LocationsItem = serde_json::from_str(r#"{"region_id": 10000060}"#).unwrap();
    assert!(
        matches!(region, LocationsItem::RegionId(ref id) if **id == 10000060),
        "region_id parsed as {region:?}"
    );

    let system: LocationsItem = serde_json::from_str(r#"{"solar_system_id": 30002187}"#).unwrap();
    assert!(
        matches!(system, LocationsItem::SolarSystemId(ref id) if **id == 30002187),
        "solar_system_id parsed as {system:?}"
    );

    // Previously an all-optional first variant swallowed anything at all.
    assert!(serde_json::from_str::<LocationsItem>(r#"{"planet_id": 40000001}"#).is_err());

    // The same fix applies at every depth: the 17-way project configuration
    // union wrapping a list of these items.
    let config: CorporationsProjectsDetailConfiguration = serde_json::from_str(
        r#"{"capture_fw_complex": {"locations": [{"constellation_id": 20000001}]}}"#,
    )
    .unwrap();
    let CorporationsProjectsDetailConfiguration::CaptureFwComplex(capture) = config else {
        panic!("capture_fw_complex parsed as {config:?}");
    };
    assert!(matches!(
        capture.locations.as_slice(),
        [LocationsItem::ConstellationId(id)] if **id == 20000001
    ));
}

/// Every `oneOf`/`anyOf` branch in `spec`, found independently of the
/// normalizer's own walker: (JSON pointer, branch schema).
fn union_branches<'a>(
    value: &'a serde_json::Value,
    pointer: &str,
    out: &mut Vec<(String, &'a serde_json::Value)>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let child_pointer =
                    format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                if key == "oneOf" || key == "anyOf" {
                    for (i, branch) in child.as_array().into_iter().flatten().enumerate() {
                        out.push((format!("{child_pointer}/{i}"), branch));
                    }
                }
                union_branches(child, &child_pointer, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                union_branches(child, &format!("{pointer}/{i}"), out);
            }
        }
        _ => {}
    }
}

fn is_undiscriminated_object(schema: &serde_json::Value) -> bool {
    let is_object = schema
        .get("type")
        .map_or(schema.get("properties").is_some(), |t| t == "object");
    let has_properties = schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|p| !p.is_empty());
    let has_required = schema
        .get("required")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|r| !r.is_empty());
    is_object && has_properties && !has_required
}

#[test]
fn bundled_spec_has_no_silently_undiscriminated_union_branches() {
    let raw = std::fs::read_to_string(BUNDLED_SPEC).expect("bundled spec must be readable");
    let mut spec: serde_json::Value = serde_json::from_str(&raw).expect("valid JSON");

    // Same order as build.rs.
    normalize_responses(&mut spec);
    let warnings = require_union_discriminants(&mut spec);
    strip_compatibility_date_param(&mut spec);

    let mut branches = Vec::new();
    union_branches(&spec, "", &mut branches);
    assert!(!branches.is_empty(), "bundled spec should contain unions");

    for (pointer, branch) in &branches {
        let target = match branch.get("$ref").and_then(serde_json::Value::as_str) {
            Some(r) => spec
                .pointer(r.trim_start_matches('#'))
                .expect("$ref resolves"),
            None => branch,
        };
        if is_undiscriminated_object(target) {
            assert!(
                warnings
                    .iter()
                    .any(|w| w.starts_with(&format!("{pointer}:"))),
                "{pointer} is an object branch with no `required` list and no warning; \
                 it will silently mis-parse as the union's first variant"
            );
        }
    }

    let claim = spec
        .pointer("/components/schemas/SovereigntySystemsSolarsystem/properties/claim/oneOf")
        .and_then(serde_json::Value::as_array)
        .unwrap();
    let required: Vec<&serde_json::Value> = claim.iter().map(|b| &b["required"]).collect();
    assert_eq!(
        required,
        [
            &serde_json::json!(["faction"]),
            &serde_json::json!(["alliance"]),
            &serde_json::json!(["unclaimed"])
        ]
    );
}

#[test]
fn branches_that_cannot_be_fixed_safely_are_reported_not_guessed() {
    let mut spec = serde_json::json!({"components": {"schemas": {
        "Loose": {"type": "object", "properties": {"a": {"type": "integer"}}},
        "Union": {"oneOf": [
            {"type": "object", "properties": {"single": {"type": "integer"}}},
            {"type": "object", "properties": {"x": {"type": "integer"}, "y": {"type": "integer"}}},
            {"$ref": "#/components/schemas/Loose"},
            {"type": "object", "properties": {"kept": {"type": "integer"}}, "required": ["kept"]},
            {"type": "string"}
        ]},
        "Nested": {"type": "object", "additionalProperties": {"type": "array", "items": {
            "anyOf": [{"type": "object", "properties": {"deep/key": {"type": "boolean"}}}]
        }}}
    }}});
    let before = spec.clone();

    let warnings = require_union_discriminants(&mut spec);

    let union = &spec["components"]["schemas"]["Union"]["oneOf"];
    assert_eq!(union[0]["required"], serde_json::json!(["single"]));
    assert_eq!(
        union[1], before["components"]["schemas"]["Union"]["oneOf"][1],
        "multi-property branch must not be guessed at"
    );
    assert_eq!(
        spec["components"]["schemas"]["Loose"], before["components"]["schemas"]["Loose"],
        "shared $ref target must not be patched"
    );
    assert_eq!(union[3]["required"], serde_json::json!(["kept"]));
    assert_eq!(union[4], serde_json::json!({"type": "string"}));
    assert_eq!(
        spec.pointer("/components/schemas/Nested/additionalProperties/items/anyOf/0/required"),
        Some(&serde_json::json!(["deep/key"]))
    );

    assert_eq!(warnings.len(), 2, "{warnings:#?}");
    assert!(
        warnings[0].starts_with("/components/schemas/Union/oneOf/1:"),
        "{}",
        warnings[0]
    );
    assert!(
        warnings[1].starts_with("/components/schemas/Union/oneOf/2:"),
        "{}",
        warnings[1]
    );
    assert!(
        warnings[1].contains("#/components/schemas/Loose"),
        "{}",
        warnings[1]
    );
}
