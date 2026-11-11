# ADHuntX Collector Guide

`ADHuntX-Collect.ps1` gathers a read-only JSON snapshot of a domain for offline
analysis in `ADHuntX.html`. It uses ADSI (System.DirectoryServices), so **RSAT
is not required**, and works on Windows PowerShell 5.1 and PowerShell 7.

## Quick start

From a domain-joined machine, in the folder with the script:

```powershell
powershell -ExecutionPolicy Bypass -File .\ADHuntX-Collect.ps1
```

This writes `adhuntx-data.json`. Import it into ADHuntX.html (Load Data →
Import collector JSON).

## Common invocations

```powershell
# Target a specific DC and output file
.\ADHuntX-Collect.ps1 -Server dc01.corp.local -Output corp.json

# Scope to an OU subtree
.\ADHuntX-Collect.ps1 -SearchBase "OU=Corp,DC=corp,DC=local"

# Choose modules
.\ADHuntX-Collect.ps1 -Modules users,groups,computers,acl,gpo,trusts,adcs

# Full detail (adds SYSVOL GPP cpassword scan + extra attributes)
.\ADHuntX-Collect.ps1 -DetailedCollection

# Cap object count for a quick sample on a huge domain
.\ADHuntX-Collect.ps1 -MaxObjects 5000
```

## Parameters

| Parameter | Default | Meaning |
|-----------|---------|---------|
| `-Output` | `adhuntx-data.json` | Output JSON path. |
| `-Domain` | current | Domain FQDN (display only; collection uses the bound DC). |
| `-Server` | nearest DC | Specific domain controller to query. |
| `-SearchBase` | domain root | Limit collection to a DN subtree. |
| `-Modules` | all | Subset of: `domain users groups computers dc acl gpo trusts fgpp adcs dns passwordpolicy`. |
| `-IncludeDisabled` | on | Include disabled accounts. |
| `-IncludeComputers` | on | Collect computer objects + LAPS indicators. |
| `-IncludeGPO` | on | Collect GPOs, links, edit rights. |
| `-IncludeACL` | on | Parse security descriptors (the DACL unlock). |
| `-IncludeADCS` | on | Collect CAs and certificate templates. |
| `-IncludeDNS` | on | Collect AD-integrated DNS zone names. |
| `-IncludePasswordPolicy` | on | Collect default + fine-grained password policy. |
| `-MaxObjects` | 0 (none) | Per-search size cap. |
| `-DetailedCollection` | off | SYSVOL cpassword scan + extra attributes. |
| `-PageSize` | 500 | LDAP paging size. |

## What it collects

Domain/forest metadata, DCs, sites; users, groups (+ membership), computers;
**DACLs** (GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword,
AllExtendedRights, **DCSync** on the domain head, **AddKeyCredentialLink**,
AddMember, ownership — recording only non-default principals to cut noise);
GPOs with links, **who-can-edit**, and optional **GPP cpassword** detection;
trusts with SID-filtering and selective-authentication flags; fine-grained
password policies; **LAPS** deployment indicators (presence only); Machine-
AccountQuota; AD CS CAs and templates; DNS zone names.

## Permissions

Most collection works as a normal domain user. Reading `ntSecurityDescriptor`
(DACLs) is allowed for authenticated users by default, so ACL collection
usually works unprivileged. SYSVOL cpassword scanning needs read access to the
SYSVOL share (normal). DNS zone enumeration may require DNS-reader rights.

## What it never does

No writes to the directory. No password or hash retrieval. No exploitation,
password spraying, Kerberoast/AS-REP requesting, or remediation. If a section
can't be read, it is recorded as a data-quality warning in the JSON (and shown
in the app) rather than silently skipped or fabricated.

## Output

A single JSON file (`adhuntx_schema: 2`) containing a `collector` metadata
block, `domain`, `users`, `groups`, `computers`, `acls`, `gpos`, `adcs`, `dns`,
`laps_observed`, `counts`, and `limitations`. Load it into ADHuntX.html.

## Validation note

This collector is new in v2 and should be smoke-tested in a lab domain before
use on production: run it, confirm the JSON imports cleanly, and spot-check a
few findings (e.g. a known DA member, a known delegated permission) against
ground truth. Report mismatches so detection logic can be tuned.
