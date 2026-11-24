# Report schemas and compatibility

AttackMap's JSON outputs are a versioned contract. Each carries a
`schema_version`, and each has a JSON Schema (draft 2020-12) in `schemas/`:

| Output | Schema | Version source |
|---|---|---|
| `attackmap-report.json` | `schemas/attackmap-report.schema.json` (generated from the models) | `attackmap.schemas.REPORT_SCHEMA_VERSION` |
| `defensive-review.json` | `schemas/defensive-review.schema.json` | `attackmap.review_json.SCHEMA_VERSION` |
| `review-context-pack.json` | `schemas/review-context-pack.schema.json` | `attackmap.context_pack.SCHEMA_VERSION` |

SARIF output follows SARIF 2.1.0. AttackMap's own keys in SARIF `properties`
bags mirror fields of the report schema and follow its version.

## The guarantee

Semantic versioning applies to each schema on its own:

- **Patch**: documentation or constraint wording; the shape is unchanged.
- **Minor**: additions only, such as a new optional property, a new enum
  value or a new definition. A consumer written for `X.Y` keeps working on
  every later `X.*`, provided it ignores unknown properties.
- **Major**: anything else, for example removing or renaming a property,
  narrowing a type, or removing an enum value.

`schemas/frozen/<name>/<version>.json` holds the schema each version shipped,
and it never changes. `tests/test_schema_contract.py` enforces three rules:

1. `attackmap-report.schema.json` is exactly what the models generate.
2. Each schema equals the snapshot of its current version, so a changed schema
   needs a version bump.
3. Each schema has no breaking change against any snapshot with the same major
   version (`attackmap.schemas.breaking_changes`).

## Changing a schema

1. Change the models (or the hand-written schema), then run
   `python scripts/schemas.py write` to regenerate the report schema.
2. Bump the version constant: minor for additions, major for anything else.
3. Run `python scripts/schemas.py freeze` to snapshot the new version, and
   commit the snapshot.
4. Add a CHANGELOG line naming the schema and its new version.
