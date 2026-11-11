# Contributing to ADHuntX

Thanks for your interest in improving ADHuntX. It is a single-file, fully offline Active Directory
assessment tool, and a few constraints keep it that way — please read these before opening a PR.

## Golden rules

1. **Zero network, zero dependencies.** The shipped `ADHuntX.html` must make no network requests and
   load no external scripts, stylesheets, fonts, or data. Everything is inlined (including the charts
   and the logo as inline SVG, and the collector as an embedded, downloadable blob). A PR that adds a
   CDN script or a runtime fetch will not be merged.
2. **Keep the engine DOM-free.** All analysis lives between the `=== ENGINE START ===` / `=== ENGINE
   END ===` markers with no DOM access, so it can be unit-tested in Node. UI code lives below it.
3. **Parsers and imports must be defensive.** Any externally-supplied data is untrusted. Import paths
   go through `validateDataset`: recognise the format, type-guard every structure, reject junk with a
   descriptive message, and degrade gracefully on partial data with data-quality warnings rather than
   throwing. See [VALIDATION.md](VALIDATION.md).
4. **Read-only and defensive.** ADHuntX never writes to Active Directory and performs no exploitation,
   credential dumping, or password attacks. The collector issues LDAP **search** operations only and
   retrieves no secrets. PRs that add offensive capability will not be merged.
5. **Privacy first.** Never add anything that transmits, phones home, or persists an assessment
   outside the user's browser.
6. **Findings need evidence.** A detection must attach concrete evidence and an evidentiary status
   (confirmed / potential / not observable), and must never fabricate a finding from missing data.

## Project layout

```
ADHuntX.html          the whole analyzer: engine (DOM-free, between the ENGINE markers) + UI + inline
                      charts/logo + the embedded, downloadable collector
ADHuntX-Collect.ps1   read-only PowerShell collector (ADSI; no RSAT required)
docs/                 collector guide and documentation
VALIDATION.md         the import-validation standard
SECURITY.md           safety model and scope
```

## Testing

- The engine can be extracted and exercised in Node (parse out the script, eval the region between
  the ENGINE markers, call `analyse(sampleData())`).
- UI and import validation can be driven headlessly with Playwright. New rules should fire against the
  synthetic `sampleData()` dataset, and new import handling should be exercised against malformed and
  hostile inputs.

By contributing you agree your work is licensed under the project's MIT License.
