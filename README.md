<div align="center">

# ADHuntX

**Discover. Hunt. Expose. Secure.**

A single-file, fully offline Active Directory security assessment and attack-path analyzer.

`Version 2.0` · Runtime: any modern browser · Dependencies: **none** · Network calls: **zero**

[Documentation](docs/) · [Download `ADHuntX.html`](ADHuntX.html) · [Collector guide](docs/COLLECTOR_GUIDE.md)

</div>

---

ADHuntX imports a read-only snapshot of an Active Directory domain, analyses it **entirely in your
browser**, and turns it into evidence-based findings, privilege-escalation attack paths, risk
scoring, a password-hygiene audit, compliance mapping, and a shareable report. Nothing is ever
uploaded — the data is parsed locally and the application makes **no network requests of any kind**.

The whole analyzer is one HTML file. Save `ADHuntX.html`, double-click it, and work — no install, no
server, no internet connection. That makes it safe for sensitive directory data and usable in
air-gapped environments. A small read-only PowerShell collector (downloadable from inside the app)
gathers the data on a domain-joined machine.

<!-- suite-nav:start -->
> **Part of the [iamjammie Hunt suite](https://iamjammie.github.io/FluxHunt/suite.html)** — open-source, offline-first security tooling and knowledge.
>
> 🧠 [Hunt-Sage](https://github.com/iamjammie/hunt-sage) (knowledge) · 🌊 [FluxHunt](https://github.com/iamjammie/FluxHunt) (wire) · 🖥️ [HostHunt](https://github.com/iamjammie/HostHunt) (box) · 📡 [HostVigil](https://github.com/iamjammie/HostVigil) (fleet) · 🔐 **ADHuntX** (directory) · 🎯 [Sentinel Matrix](https://github.com/iamjammie/Sentinel-Matrix) (detection coverage) · 🧬 [TTP NEXUS](https://github.com/iamjammie/TTP-Nexus) (frameworks) · 🛡️ [ThreatIntFlux](https://github.com/iamjammie/ThreatIntFlux) (threat intel) · 🔦 [Photonwire](https://github.com/iamjammie/PhotonWire) (air gap) · 🛰️ [SPECTRA](https://github.com/iamjammie/SPECTRA---Space-Cyber-Framework) (space)
>
> [Suite hub](https://iamjammie.github.io/FluxHunt/suite.html) · [All projects](https://github.com/iamjammie)
<!-- suite-nav:end -->

> ⚠️ **Authorized, read-only use only.** ADHuntX is an assessment and analysis platform, **not** an
> exploitation tool: no credential dumping, password attacks, exploitation, or directory
> modification. Use it only on directories you are explicitly authorized to assess.

## What it does

Comparable in spirit to the config-health scoring of **PingCastle** / **Purple Knight** and the
attack-path graph of **BloodHound**, in one portable offline file:

- **Dashboard** — risk gauge, an auto-generated executive summary with an attack-surface inference,
  severity charts, and the top paths and critical findings.
- **Posture & Frameworks** — PingCastle-style pillar scores (Privileged Accounts / Stale Objects /
  Trusts / Anomalies), a blast-radius metric, and MITRE ATT&CK / NIST CSF / CIS coverage.
- **35 assessment rules** across Identity, AD configuration & ACLs, Domain Controllers, and AD CS —
  each finding with severity, evidence, confidence, an evidentiary status, and mitigation. ACL/DACL
  analysis covers GenericAll/Write, WriteDACL/Owner, ForceChangePassword, AllExtendedRights,
  **DCSync**, **AddKeyCredentialLink (shadow credentials)**, ownership, **GPO-edit abuse**, and
  **GPP cpassword in SYSVOL**.
- **Attack paths** — a directed privilege graph with Dijkstra path discovery to Domain/Enterprise
  Admins, DCs, and the domain object, with interactive relationship / target / risk filters.
- **Password Audit** — policy and fine-grained-policy audit, per-account hygiene, and
  privileged / service-account password risk (no hashes are ever collected).
- **Compliance** — ATT&CK / NIST CSF / CIS control-area coverage (indicative, not a certification).
- **Compare** — diff two saved assessments: new / resolved / persistent findings, risk and pillar
  deltas, and new / removed privileged accounts and paths.
- **Domain** — forest / domain / FSMO / DCs / sites / DNS, trusts, and GPOs.
- **Remediation & Action Plan** — a prioritized, effort/impact-graded, checkable to-do list whose
  progress is saved locally.
- **Reports** — pictorial HTML / print-to-PDF / JSON / CSV with charts and progress bars.

## Quick start

1. Download **`ADHuntX.html`** and open it in any modern browser.
2. Click **Load Sample** to explore a realistic, intentionally-misconfigured synthetic domain — no
   files or setup required.
3. To assess a real domain, go to **Load Data → step 03**, download the collector, and run it.

## Collect from a live domain (read-only)

A browser cannot query LDAP directly, so a small PowerShell collector gathers the data:

```powershell
powershell -ExecutionPolicy Bypass -File .\ADHuntX-Collect.ps1 -Output adhuntx-data.json
```

It performs LDAP **search** operations and read-only configuration inspection only — no writes, no
exploitation, no secrets — using ADSI, so **RSAT is not required**. Then import the JSON it produces
(**Load Data → Import collector JSON**). See the **[collector guide](docs/COLLECTOR_GUIDE.md)** for
scoping, modules, and permissions.

## Supported inputs

- The ADHuntX collector JSON (`adhuntx_schema` 1 or 2).
- An ADHuntX report export (JSON) — reloads an earlier assessment.
- Any JSON matching the documented schema (see **[VALIDATION.md](VALIDATION.md)**). Imports are
  validated on load: unrecognised files are rejected with a clear message, and malformed entries are
  coerced or dropped with data-quality warnings rather than crashing the app.

## Privacy and honest limitations

- Everything runs client-side; imported data and saved assessments stay in your browser (IndexedDB).
  The app makes no network requests.
- Findings and attack paths are **potential** exposure derived from configuration — they require
  human validation and never assert confirmed compromise.
- Framework / control mapping is indicative for prioritisation, not a formal compliance
  certification.
- The collector cannot gather live logon **sessions** or local-admin-via-RPC (BloodHound's
  `HasSession`); it does no password cracking and reads no real-time DC health. These are out of
  scope by design.

## Responsible use

ADHuntX is read-only and defensive. Run the collector and the analyzer only against directories you
are explicitly authorized to assess; collection activity (LDAP searches) may be logged by the
directory. See **[SECURITY.md](SECURITY.md)**.

## License

MIT — see [LICENSE](LICENSE).
