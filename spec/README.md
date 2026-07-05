# ESI spec — source of truth for codegen

`esi-latest.json` is CCP's published OpenAPI document for ESI (tranquility),
fetched verbatim and pretty-printed (key order preserved) so spec updates
produce small, human-readable git diffs. Refresh it with:

```
cargo run -p xtask -- fetch-spec [compatibility-date]
```

## Provenance

- **Source URL:** `https://esi.evetech.net/meta/openapi.json?compatibility_date=<date>`
- **Versioning:** ESI uses compatibility-date versioning. The server resolves
  the requested date down to the newest published compatibility date not
  after it, and records the resolved date in the spec's `info.version`.
  `fetch-spec` requests today's date by default, i.e. the newest surface.
- **Format:** OpenAPI **3.1.0** as published.

Do NOT use the legacy `https://esi.evetech.net/latest/swagger.json` route:
it is Swagger 2.0, deprecated, and already behind the OpenAPI route
(180 paths vs 203 as of compatibility date 2026-06-09).

## Progenitor compatibility (verified 2026-07-05, progenitor 0.14.0)

Progenitor consumes OpenAPI **3.0.x** (via the `openapiv3` crate), so
`build.rs` must apply a small in-memory normalization before codegen.
The committed file stays byte-identical to what CCP publishes (modulo
pretty-printing); nothing normalized is ever committed.

Rules, each empirically required as of the date above:

1. **Nullable type arrays** — `"type": [T, "null"]` → `"type": T,
   "nullable": true`. (2 occurrences; the only JSON-Schema-2020-12 typing
   construct the spec uses.)
2. **Schema `examples` arrays** — 3.1 schema-level `"examples": [x, ...]` →
   3.0 `"example": x` (first entry). Media-type `examples` maps are objects,
   not arrays, and are untouched.
3. **`default` responses** — every ESI operation declares a typed `200` plus
   a `default` response carrying the `Error` envelope. Progenitor counts
   `default` toward the *success* response group and panics on two distinct
   success types. Where an explicit 2xx exists, rewrite `default` into
   explicit `4XX` and `5XX` range responses (same `Error` schema) — which is
   what ESI's `default` means.
4. **Secondary 2xx responses** — `GET /contracts/public/bids/{contract_id}`
   and `GET /contracts/public/items/{contract_id}` declare `200` (typed) plus
   an empty `204` ("contract no longer available"). Progenitor supports one
   success shape per operation, so the `204` is dropped; at runtime a 204
   surfaces as `Error::UnexpectedResponse`, which callers can match on.
5. **Version string** — `"openapi": "3.1.0"` → `"3.0.3"` after the above.

With these applied, progenitor 0.14.0 generates a client covering all
203 paths (218 methods) that compiles cleanly (reqwest 0.13,
progenitor-client 0.14).
