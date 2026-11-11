# ADHuntX Security & Safety Model

ADHuntX is a **defensive, read-only** Active Directory assessment tool for
**authorized** audits, threat hunting, and training.

## What it does

- Reads directory objects and configuration over LDAP (collector) and analyses
  them offline in the browser (HTML app).
- Identifies misconfigurations and privilege-escalation exposure with evidence.
- Produces findings, attack paths, remediation guidance, and reports.

## What it never does

- No writes or modifications to Active Directory.
- No exploitation, privilege escalation, or lateral movement.
- No password spraying, brute force, or credential dumping.
- No Kerberoasting / AS-REP *requesting* or cracking (it only flags *exposure*).
- No retrieval of passwords or password hashes.
- No automatic remediation — remediation is presented as reviewed guidance,
  including illustrative PowerShell the operator runs deliberately.

## Data handling

- The HTML app runs entirely client-side. Imported data and saved assessments
  stay in your browser (IndexedDB); nothing is transmitted anywhere.
- The collector writes a local JSON file. It never contains plaintext passwords
  or hashes. LAPS is reported as *presence only*, never the password value.
- Errors and gaps are recorded as data-quality warnings rather than hidden.

## Findings are potential, not confirmed

Findings and attack paths represent **potential** exposure derived from
configuration. They require human validation and do not assert confirmed
compromise or guaranteed exploitability.

## Authorization

Use only on directories you are explicitly authorized to assess. The operator
is responsible for having permission. Collection activity (LDAP searches) may
be logged by the directory; coordinate with the environment owner.

## Reporting issues

If a detection is wrong (false positive/negative) or a collector module fails,
capture the finding/rule ID and the relevant (sanitized) evidence so the logic
can be corrected.
