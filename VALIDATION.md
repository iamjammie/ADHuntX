# Data validation

ADHuntX validates every externally-supplied dataset on import, following the same house standard
used across the Hunt suite (FluxHunt, PhotonWire, HostHunt, hunt-sage): **recognise the format up
front, type-guard every structure before use, reject junk with a descriptive error, and degrade
gracefully on partial data with data-quality warnings** rather than crashing or silently dropping.

## Where it applies

- **Load Data → Import collector JSON** — the main assessment dataset (`validateDataset`).
- **Password Audit → Import audit results** — the optional offline password-quality dataset.

Sample data and saved assessments flow through the same `validateDataset` path.

## What is checked

| Check | Behaviour |
|-------|-----------|
| File size | Rejected over 80 MB (assessment) / 8 MB (audit) with a clear message — scope the collection with `-SearchBase` / `-MaxObjects`. |
| JSON parse | `JSON.parse` wrapped in try/catch; parse errors are shown to the user, not thrown to the console. |
| Top-level shape | Must be a JSON object. `null`, arrays, and scalars are rejected. |
| Format marker | Recognises `adhuntx_schema` 1/2, a raw collector dataset (`domain`/`users`/`groups`/`computers`), or an ADHuntX report export. An unknown `adhuntx_schema` imports best-effort with a warning; a file with no recognised data is rejected. |
| `domain` | Must be an object; a non-object `domain` is ignored (reset to `{}`) with a warning — this guards the `password_policy` / `trusts` access paths. |
| Entity arrays (`users`, `groups`, `computers`, `acls`, `gpos`, `findings`, `attack_paths`) | A non-array is reset to empty with a warning; non-object elements are dropped and counted in a warning. |
| `adcs` and its `templates` / `certificate_authorities` | Coerced to object / arrays with a warning if malformed. |
| `domain.domain_controllers` / `trusts` / `fine_grained_password_policies` / `sites` | Coerced to arrays with a warning if malformed. |
| Object-count sanity cap | Over 300,000 objects loads with a warning that analysis may be slow (tables already cap rendered rows). |

## Errors vs warnings

- **Hard errors reject the import** (not a JSON object, no recognised data, too large) and are shown
  in the Load Data panel and as a toast. Nothing is analysed.
- **Soft issues degrade gracefully**: the data is coerced to a safe shape and each issue is recorded
  as a data-quality warning. Warnings are merged into the assessment's `limitations`, so they surface
  in the dashboard banner and in the report — the same channel the collector uses to record gaps.

This mirrors the suite's convention of explicit guard clauses with descriptive messages, a
`warnings[]` channel for recoverable problems, and type guards (`isinstance` / `typeof` /
`Array.isArray`) before every structural access.

## Password-audit import format

```json
{ "svc_sql": { "weak": true, "reused": false }, "jadmin": { "weak": false, "reused": true } }
```

Keys are sAMAccountNames (case-insensitive); each value must be an object. Non-object values are
skipped and counted. No passwords or hashes are handled — this annotates accounts from an
authorized, offline quality result only.
