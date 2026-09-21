# Changelog

Changes to the crate itself. Routine spec refreshes are released
automatically and listed on the
[GitHub releases page](https://github.com/infktd/eve-esi-client/releases).

## 0.4.0

### Breaking: untagged `oneOf` enums now discriminate correctly

Untagged `oneOf` enums now discriminate correctly; previously every value
parsed as the first variant.

ESI models tagged unions as a `oneOf` of single-key objects —
`{"faction": {..}}`, `{"alliance": {..}}`, `{"unclaimed": true}` — without
marking the key `required`. The generated enums were `#[serde(untagged)]` with
an optional field per variant, so the first variant matched every value with
its field set to `None`. For example, every system in
`GET /sovereignty/systems` parsed as a faction claim with no faction, and all
alliance sovereignty was lost.

The spec normalization now marks each branch's key as required, so these
become externally tagged enums that serde discriminates on the key:

```rust
// 0.3.x: every claim parsed as `Faction { faction: None }`
pub enum SovereigntySystemsSolarsystemClaim {
    Faction { faction: Option<SovereigntySystemsFaction> },
    Alliance { alliance: Option<SovereigntySystemsAlliance> },
    Unclaimed { unclaimed: Option<bool> },
}

// 0.4.0
pub enum SovereigntySystemsSolarsystemClaim {
    Faction(SovereigntySystemsFaction),
    Alliance(SovereigntySystemsAlliance),
    Unclaimed(bool),
}
```

Migrating: match `Claim::Alliance(alliance)` instead of
`Claim::Alliance { alliance: Some(alliance) }`. Each variant also gets a
`From` impl for its payload type when that type is unique within the enum. An
object whose key names no known variant (for example, one CCP adds later) is
now a deserialization error instead of a silent, empty first variant.

All 39 union enums in the spec change this way:

- `SovereigntySystemsSolarsystemClaim`
- `CharactersCosmeticsSkinrComponentsItemRuns`
- `CharactersParagonHubSkinrItemPrice`, `CharactersParagonHubSkinrItemTarget`
- `ParagonHubSkinrInternalItemPrice`
- `CosmeticsSkinrLayoutslotConfiguration`
- `CorporationsStructuresSovereigntyHubsDetailTransportConfiguration`,
  `CorporationsStructuresSovereigntyHubsDetailTransportState`
  (`Transit(Option<bool>)`, because `transit` is nullable)
- `FreelanceJobsDetailConfigurationParametersValue`
- `CorporationsProjectsDetailConfiguration` (17 variants)
- The `CorporationsProjectsDetailConfiguration*` list-item unions for each
  project kind: `*LocationsItem` (×12), `*IdentitiesItem` (×6),
  `*ShipsItem` (×6), `*ItemsItem` (×2), `*DockingLocationsItem` (×2),
  `*MaterialsItem` (×1)

No structs or client methods changed.
