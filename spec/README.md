# ESI spec — source of truth for codegen

`esi-latest.json` is CCP's published OpenAPI document for ESI (tranquility),
fetched verbatim and pretty-printed (key order preserved) so spec updates
produce small, human-readable git diffs. Refresh it with:

```
cargo run -p xtask -- fetch-spec [compatibility-date]
```

## Provenance

- **Source URL:** `https://esi.evetech.net/meta/openapi-3.0.json?compatibility_date=<date>`
- **Format:** OpenAPI **3.0.3**. CCP publishes the same surface in four
  formats (`openapi.json`/`openapi.yaml` are 3.1; `openapi-3.0.json`/
  `openapi-3.0.yaml` are 3.0). We consume CCP's own 3.0 conversion because
  progenitor targets OpenAPI 3.0.x — this keeps the 3.1→3.0 downconversion
  on CCP's side instead of maintaining one here. (Verified identical
  surface: same resolved compatibility date, same 203 paths as the 3.1
  document.)
- **Versioning:** ESI uses compatibility-date versioning. The server
  resolves the requested date down to the newest published compatibility
  date not after it, and records the resolved date in the spec's
  `info.version`. `fetch-spec` requests today's date by default, i.e. the
  newest surface.

Do NOT use the legacy `https://esi.evetech.net/latest/swagger.json` route:
it is Swagger 2.0, deprecated, and already behind the OpenAPI routes
(180 paths vs 203 as of compatibility date 2026-06-09).

## Progenitor compatibility (verified 2026-07-05, progenitor 0.14.0)

Two ESI response conventions hit unsupported cases in progenitor, so
`build.rs` applies a small in-memory normalization before codegen. The
committed file stays exactly what CCP publishes (modulo pretty-printing);
nothing normalized is ever committed.

1. **`default` responses** — every ESI operation declares a typed `200` plus
   a `default` response carrying the `Error` envelope. Progenitor counts
   `default` toward the *success* response group and panics on two distinct
   success types. Where an explicit 2xx exists, rewrite `default` into
   explicit `4XX` and `5XX` range responses (same `Error` schema) — which is
   what ESI's `default` means.
2. **Secondary 2xx responses** — `GET /contracts/public/bids/{contract_id}`
   and `GET /contracts/public/items/{contract_id}` declare `200` (typed) plus
   an empty `204` ("contract no longer available"). Progenitor supports one
   success shape per operation, so the `204` is dropped; at runtime a 204
   surfaces as `Error::UnexpectedResponse`, which callers can match on.

With these applied, progenitor 0.14.0 generates a client covering all
203 paths (218 methods) that compiles cleanly (reqwest 0.13,
progenitor-client 0.14).

(Historical note: the 3.1 document also works if fed through three extra
downconvert rules — nullable `type` arrays, schema-level `examples` arrays,
version-string rewrite — but consuming CCP's 3.0 document makes those
unnecessary.)
