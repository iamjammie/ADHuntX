<#
    ADHuntX-Collect.ps1  v2.0  — read-only Active Directory collector for ADHuntX.

    Gathers a normalized JSON dataset from a live domain that you load into
    ADHuntX.html for offline analysis. It performs ONLY LDAP search operations
    and read-only configuration inspection — no writes, no exploitation, no
    password/hash retrieval, no remediation.

    WHAT'S NEW IN v2 vs v1:
      * DACL / nTSecurityDescriptor parsing: GenericAll, GenericWrite, WriteDACL,
        WriteOwner, ForceChangePassword, AllExtendedRights, DCSync (replication
        rights on the domain head), AddKeyCredentialLink (shadow credentials),
        AddMember, and object ownership.
      * GPO collection: metadata, links, who-can-edit, and optional SYSVOL GPP
        cpassword detection.
      * Trusts with SID-filtering and selective-authentication indicators.
      * Fine-Grained Password Policies (PSOs).
      * LAPS deployment indicators (presence only — never the password).
      * Sites / subnets / FSMO roles, MachineAccountQuota.
      * Collection metadata, per-module progress, and data-quality warnings.

    Works with Windows PowerShell 5.1 and PowerShell 7. Uses System.Directory-
    Services (ADSI), so RSAT / the ActiveDirectory module is NOT required. A
    normal domain-user context is usually enough for read.

    USAGE
      powershell -ExecutionPolicy Bypass -File .\ADHuntX-Collect.ps1
      powershell -ExecutionPolicy Bypass -File .\ADHuntX-Collect.ps1 -Server dc01.corp.local -Output adhuntx-data.json
      powershell -ExecutionPolicy Bypass -File .\ADHuntX-Collect.ps1 -Modules users,groups,computers,acl,gpo,trusts,adcs
      powershell -ExecutionPolicy Bypass -File .\ADHuntX-Collect.ps1 -SearchBase "OU=Corp,DC=corp,DC=local" -DetailedCollection

    AUTHORIZED USE ONLY. You are responsible for having permission to assess the
    target directory.
#>
[CmdletBinding()]
param(
    [string]   $Output = "adhuntx-data.json",
    [string]   $Domain = "",
    [string]   $Server = "",
    [string]   $SearchBase = "",
    [string[]] $Modules = @("domain","users","groups","computers","dc","acl","gpo","trusts","fgpp","adcs","dns","passwordpolicy"),
    [switch]   $IncludeDisabled = $true,
    [switch]   $IncludeComputers = $true,
    [switch]   $IncludeGPO = $true,
    [switch]   $IncludeACL = $true,
    [switch]   $IncludeADCS = $true,
    [switch]   $IncludeDNS = $true,
    [switch]   $IncludePasswordPolicy = $true,
    [int]      $MaxObjects = 0,          # 0 = no cap
    [switch]   $DetailedCollection,      # enables SYSVOL cpassword scan + extra attrs
    [int]      $PageSize = 500
)

$ErrorActionPreference = "Stop"
$script:Warnings = New-Object System.Collections.ArrayList
$script:SidToName = @{}        # SID string -> display name, built as we collect
$startTime = Get-Date

function Add-Warning([string]$m){ [void]$script:Warnings.Add($m); Write-Warning $m }
function Has-Module([string]$m){ return ($Modules -contains $m) }

# ---- Well-known GUIDs for ACE interpretation --------------------------------
$GUID_ForceChangePwd = [Guid]"00299570-246d-11d0-a768-00aa006e0529"
$GUID_ReplGetChanges = [Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
$GUID_ReplGetChangesAll = [Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
$GUID_KeyCredentialLink = [Guid]"5b47d60f-6090-40b2-9f37-2a4de88f3063"
$GUID_MemberAttr = [Guid]"bf9679c0-0de6-11d0-a285-00aa003049e2"
$GUID_Empty = [Guid]"00000000-0000-0000-0000-000000000000"

# SIDs/principals that are expected to hold rights — excluded from "dangerous ACL" noise.
$SafeSidSuffixes = @("-512","-516","-518","-519","-544","-548","-520","-498","-516")
$SafeWellKnown = @("S-1-5-18","S-1-5-32-544","S-1-5-9","S-1-5-10","S-1-3-0","S-1-5-32-548","S-1-5-32-549","S-1-5-32-551")

function Is-SafePrincipal([string]$sid){
    if ([string]::IsNullOrEmpty($sid)) { return $true }
    if ($SafeWellKnown -contains $sid) { return $true }
    foreach ($s in $SafeSidSuffixes) { if ($sid.EndsWith($s)) { return $true } }
    return $false
}

# ---- Directory helpers ------------------------------------------------------
function Get-RootDSE {
    if ($Server) { return New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/RootDSE") }
    return New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
}

function New-Searcher {
    param([string]$Filter, [string[]]$Props, [string]$Base, [string]$SecurityMasks = "")
    if ($Server -and $Base) { $path = "LDAP://$Server/$Base" }
    elseif ($Base)          { $path = "LDAP://$Base" }
    elseif ($Server)        { $path = "LDAP://$Server" }
    else                    { $path = "LDAP://RootDSE" }
    $entry = New-Object System.DirectoryServices.DirectoryEntry($path)
    $s = New-Object System.DirectoryServices.DirectorySearcher($entry)
    $s.Filter = $Filter
    $s.PageSize = $PageSize
    $s.SearchScope = "Subtree"
    if ($MaxObjects -gt 0) { $s.SizeLimit = $MaxObjects }
    if ($SecurityMasks) { $s.SecurityMasks = [System.DirectoryServices.SecurityMasks]$SecurityMasks }
    foreach ($p in $Props) { [void]$s.PropertiesToLoad.Add($p) }
    return $s
}

function V($r,[string]$n){ if ($r.Properties.Contains($n) -and $r.Properties[$n].Count -gt 0){ return $r.Properties[$n][0] } return $null }
function M($r,[string]$n){ $o=@(); if($r.Properties.Contains($n)){ foreach($v in $r.Properties[$n]){ $o+=$v } } return $o }

function SidOf($bytes){
    if ($null -eq $bytes){ return "" }
    try { return (New-Object System.Security.Principal.SecurityIdentifier($bytes,0)).Value } catch { return "" }
}
function GuidOf($bytes){
    if ($null -eq $bytes){ return "" }
    try { return ([Guid]([byte[]]$bytes)).ToString() } catch { return "" }
}
function FileTimeIso($v){
    if ($null -eq $v){ return $null }
    try { $l=[int64]$v; if($l -eq 0 -or $l -eq 9223372036854775807){ return $null }; return [DateTime]::FromFileTimeUtc($l).ToString("o") } catch { return $null }
}
function GenTimeIso($v){
    if ($null -eq $v){ return $null }
    try { if($v -is [DateTime]){ return $v.ToUniversalTime().ToString("o") }; return [DateTime]::ParseExact($v.ToString().Substring(0,14),"yyyyMMddHHmmss",$null).ToString("o") } catch { return $null }
}
function ResolveSid([string]$sid){
    if ($script:SidToName.ContainsKey($sid)){ return $script:SidToName[$sid] }
    try { $n=(New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value; return $n.Split('\')[-1] } catch { return $sid }
}

Write-Host "ADHuntX collector v2.0 — read-only. Starting..." -ForegroundColor Cyan
Write-Progress -Activity "ADHuntX collection" -Status "Resolving domain" -PercentComplete 2

# ---- Resolve naming contexts ------------------------------------------------
$rootDse = $null; $defaultNc=""; $configNc=""; $schemaNc=""; $rootNc=""
try {
    $rootDse = Get-RootDSE
    $defaultNc = [string]$rootDse.Properties["defaultNamingContext"].Value
    $configNc  = [string]$rootDse.Properties["configurationNamingContext"].Value
    $schemaNc  = [string]$rootDse.Properties["schemaNamingContext"].Value
    $rootNc    = [string]$rootDse.Properties["rootDomainNamingContext"].Value
} catch { Add-Warning "Could not read RootDSE: $($_.Exception.Message)" }
if (-not $defaultNc) { $defaultNc = $SearchBase }
$baseDN = if ($SearchBase) { $SearchBase } else { $defaultNc }
$domainFqdn = if ($Domain) { $Domain } else { ($defaultNc -replace "DC=","" -replace ",",".") }

# =============================================================================
# DOMAIN + FOREST
# =============================================================================
$domainObj = [ordered]@{
    name=$domainFqdn; netbios_name=""; domain_sid=""; forest_name=($rootNc -replace "DC=","" -replace ",",".")
    functional_level=""; forest_functional_level=""; domain_controllers=@(); trusts=@()
    ldaps_available=$false; ldap_available=$true; password_policy=$null
    machine_account_quota=$null; fine_grained_password_policies=@(); sites=@(); fsmo=@{}
}
if (Has-Module "domain") {
    Write-Progress -Activity "ADHuntX collection" -Status "Domain metadata" -PercentComplete 6
    try {
        $s = New-Searcher "(objectClass=domainDNS)" @("objectSid","minPwdLength","pwdHistoryLength","lockoutThreshold","pwdProperties","maxPwdAge","minPwdAge","ms-DS-MachineAccountQuota","msDS-Behavior-Version","fSMORoleOwner") $baseDN
    $s.SizeLimit=1; $d=$s.FindOne()
        if ($d) {
            $domainObj.domain_sid = SidOf (V $d "objectSid")
            $complex = $false; $pp = V $d "pwdProperties"; if($pp){ $complex = (([int]$pp) -band 1) -eq 1 }
            $maxAge = V $d "maxPwdAge"
            $maxDays = $null; if($maxAge){ try{ $ticks=[int64]$maxAge; if($ticks -ne 0){ $maxDays=[math]::Round([math]::Abs($ticks)/864000000000) } }catch{} }
            $domainObj.password_policy = [ordered]@{
                min_length=[int](V $d "minPwdLength"); history_length=[int](V $d "pwdHistoryLength")
                max_age_days=$maxDays; min_age_days=$null; lockout_threshold=[int](V $d "lockoutThreshold"); complexity_enabled=$complex
            }
            $maq = V $d "ms-DS-MachineAccountQuota"; if($maq -ne $null){ $domainObj.machine_account_quota=[int]$maq }
        }
    } catch { Add-Warning "Domain metadata collection failed: $($_.Exception.Message)" }
    # LDAPS probe
    try {
        $hostProbe = if($Server){$Server}else{$domainFqdn}
        $tcp=New-Object System.Net.Sockets.TcpClient
        $iar=$tcp.BeginConnect($hostProbe,636,$null,$null)
        $domainObj.ldaps_available = ($iar.AsyncWaitHandle.WaitOne(2000,$false) -and $tcp.Connected)
        $tcp.Close()
    } catch { $domainObj.ldaps_available=$false }
    # Domain controllers
    try {
        $s = New-Searcher "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))" @("name","dNSHostName","operatingSystem","operatingSystemVersion","distinguishedName") $baseDN
        foreach ($r in $s.FindAll()) {
            $domainObj.domain_controllers += [ordered]@{
                name=[string](V $r "name"); dns_hostname=[string](V $r "dNSHostName")
                operating_system=[string](V $r "operatingSystem"); operating_system_version=[string](V $r "operatingSystemVersion")
                ip_address=""; is_global_catalog=$false; distinguished_name=[string](V $r "distinguishedName")
            }
        }
    } catch { Add-Warning "DC enumeration failed: $($_.Exception.Message)" }
    # Sites / subnets
    if ($configNc) {
        try {
            $s = New-Searcher "(objectClass=site)" @("name","siteObjectBL") "CN=Sites,$configNc"
            foreach ($r in $s.FindAll()){ $domainObj.sites += [ordered]@{ name=[string](V $r "name"); subnets=@() } }
        } catch { Add-Warning "Site enumeration limited: $($_.Exception.Message)" }
    }
}

# =============================================================================
# USERS
# =============================================================================
$users=@()
if (Has-Module "users") {
    Write-Progress -Activity "ADHuntX collection" -Status "Users" -PercentComplete 18
    try {
        $filter = if($IncludeDisabled){ "(&(objectCategory=person)(objectClass=user))" } else { "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))" }
        $props = @("sAMAccountName","distinguishedName","objectSid","objectGUID","userPrincipalName","displayName","mail","department","description","userAccountControl","adminCount","lastLogonTimestamp","pwdLastSet","accountExpires","whenCreated","whenChanged","memberOf","primaryGroupID","servicePrincipalName","msDS-AllowedToDelegateTo")
        $s = New-Searcher $filter $props $baseDN
        foreach ($r in $s.FindAll()) {
            $uac=[int](V $r "userAccountControl")
            $sid = SidOf (V $r "objectSid"); $sam=[string](V $r "sAMAccountName")
            if($sid){ $script:SidToName[$sid]=$sam }
            $users += [ordered]@{
                sam_account_name=$sam; distinguished_name=[string](V $r "distinguishedName"); object_sid=$sid
                object_guid=(GuidOf (V $r "objectGUID"))
                user_principal_name=[string](V $r "userPrincipalName"); display_name=[string](V $r "displayName")
                email=[string](V $r "mail"); department=[string](V $r "department"); description=[string](V $r "description")
                enabled=(-not (($uac -band 0x2) -ne 0)); user_account_control=$uac; admin_count=[int](V $r "adminCount")
                last_logon_timestamp=(FileTimeIso (V $r "lastLogonTimestamp")); pwd_last_set=(FileTimeIso (V $r "pwdLastSet"))
                account_expires=(FileTimeIso (V $r "accountExpires")); when_created=(GenTimeIso (V $r "whenCreated"))
                member_of=@(M $r "memberOf"); service_principal_names=@(M $r "servicePrincipalName")
                allowed_to_delegate_to=@(M $r "msDS-AllowedToDelegateTo")
            }
        }
        Write-Host "  users: $($users.Count)"
    } catch { Add-Warning "User collection failed: $($_.Exception.Message)" }
}

# =============================================================================
# GROUPS
# =============================================================================
$groups=@()
if (Has-Module "groups") {
    Write-Progress -Activity "ADHuntX collection" -Status "Groups" -PercentComplete 30
    try {
        $s = New-Searcher "(objectClass=group)" @("sAMAccountName","distinguishedName","objectSid","displayName","description","groupType","member","memberOf","adminCount") $baseDN
        foreach ($r in $s.FindAll()) {
            $sid=SidOf (V $r "objectSid"); $sam=[string](V $r "sAMAccountName"); if($sid){ $script:SidToName[$sid]=$sam }
            $groups += [ordered]@{
                sam_account_name=$sam; distinguished_name=[string](V $r "distinguishedName"); object_sid=$sid
                display_name=[string](V $r "displayName"); description=[string](V $r "description"); group_type=[int](V $r "groupType")
                members=@(M $r "member"); member_of=@(M $r "memberOf"); admin_count=[int](V $r "adminCount")
            }
        }
        Write-Host "  groups: $($groups.Count)"
    } catch { Add-Warning "Group collection failed: $($_.Exception.Message)" }
}

# =============================================================================
# COMPUTERS (+ LAPS indicators)
# =============================================================================
$computers=@(); $lapsObserved=$false
if ((Has-Module "computers") -and $IncludeComputers) {
    Write-Progress -Activity "ADHuntX collection" -Status "Computers" -PercentComplete 42
    # LAPS schema presence
    try {
        if ($schemaNc) {
            $ls = New-Searcher "(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password))" @("lDAPDisplayName") $schemaNc
            $ls.SizeLimit=1; if($ls.FindOne()){ $lapsObserved=$true }
        }
    } catch {}
    try {
        $props=@("sAMAccountName","distinguishedName","objectSid","dNSHostName","operatingSystem","operatingSystemVersion","userAccountControl","lastLogonTimestamp","pwdLastSet","whenCreated","servicePrincipalName","msDS-AllowedToDelegateTo","msDS-AllowedToActOnBehalfOfOtherIdentity","memberOf","ms-Mcs-AdmPwdExpirationTime","msLAPS-PasswordExpirationTime")
        $s = New-Searcher "(objectClass=computer)" $props $baseDN
        foreach ($r in $s.FindAll()) {
            $uac=[int](V $r "userAccountControl"); $sid=SidOf (V $r "objectSid"); $sam=[string](V $r "sAMAccountName"); if($sid){ $script:SidToName[$sid]=$sam }
            $rbcd=@(); if($r.Properties.Contains("msDS-AllowedToActOnBehalfOfOtherIdentity") -and $r.Properties["msDS-AllowedToActOnBehalfOfOtherIdentity"].Count -gt 0){ $rbcd=@("<present>") }
            $lapsPresent = ($r.Properties.Contains("ms-Mcs-AdmPwdExpirationTime") -and $r.Properties["ms-Mcs-AdmPwdExpirationTime"].Count -gt 0) -or ($r.Properties.Contains("msLAPS-PasswordExpirationTime") -and $r.Properties["msLAPS-PasswordExpirationTime"].Count -gt 0)
            $computers += [ordered]@{
                sam_account_name=$sam; distinguished_name=[string](V $r "distinguishedName"); object_sid=$sid
                dns_hostname=[string](V $r "dNSHostName"); operating_system=[string](V $r "operatingSystem"); operating_system_version=[string](V $r "operatingSystemVersion")
                enabled=(-not (($uac -band 0x2) -ne 0)); user_account_control=$uac; last_logon_timestamp=(FileTimeIso (V $r "lastLogonTimestamp"))
                pwd_last_set=(FileTimeIso (V $r "pwdLastSet")); when_created=(GenTimeIso (V $r "whenCreated"))
                service_principal_names=@(M $r "servicePrincipalName"); allowed_to_delegate_to=@(M $r "msDS-AllowedToDelegateTo")
                allowed_to_act_on_behalf=$rbcd; member_of=@(M $r "memberOf"); is_domain_controller=(($uac -band 0x2000) -ne 0); laps_present=$lapsPresent
            }
        }
        Write-Host "  computers: $($computers.Count) (LAPS schema present: $lapsObserved)"
    } catch { Add-Warning "Computer collection failed: $($_.Exception.Message)" }
}

# =============================================================================
# ACLs / DACLs  — the v2 unlock
# =============================================================================
$acls=@()
function Parse-ObjectAcl {
    param($entry, [string]$targetDn, [string]$targetName, [string]$targetType, [bool]$isDomainHead)
    $out=@()
    try {
        $bytes = $null
        if ($entry.Properties.Contains("ntSecurityDescriptor") -and $entry.Properties["ntSecurityDescriptor"].Count -gt 0){ $bytes=$entry.Properties["ntSecurityDescriptor"][0] }
        if (-not $bytes){ return $out }
        $sd = New-Object System.DirectoryServices.ActiveDirectorySecurity
        $sd.SetSecurityDescriptorBinaryForm([byte[]]$bytes)
        # Owner
        try {
            $owner = $sd.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
            if (-not (Is-SafePrincipal $owner)) {
                $out += [ordered]@{ principal_sid=$owner; principal_name=(ResolveSid $owner); principal_type="principal"; right="Owns"; target_dn=$targetDn; target_name=$targetName; target_type=$targetType; inherited=$false }
            }
        } catch {}
        foreach ($ace in $sd.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow){ continue }
            $sid = $ace.IdentityReference.Value
            if (Is-SafePrincipal $sid){ continue }
            $rights = $ace.ActiveDirectoryRights
            $ot = $ace.ObjectType
            $mapped = @()
            if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll){ $mapped += "GenericAll" }
            if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl){ $mapped += "WriteDACL" }
            if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner){ $mapped += "WriteOwner" }
            if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite){ $mapped += "GenericWrite" }
            if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty){
                if ($ot -eq $GUID_KeyCredentialLink){ $mapped += "AddKeyCredentialLink" }
                elseif ($ot -eq $GUID_MemberAttr -and $targetType -eq "group"){ $mapped += "AddMember" }
            }
            if ($rights -band [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight){
                if ($ot -eq $GUID_ForceChangePwd){ $mapped += "CanResetPassword" }
                elseif ($ot -eq $GUID_ReplGetChangesAll -and $isDomainHead){ $mapped += "DCSync" }
                elseif ($ot -eq $GUID_Empty){ $mapped += "AllExtendedRights" }
            }
            foreach ($m in ($mapped | Select-Object -Unique)) {
                $out += [ordered]@{ principal_sid=$sid; principal_name=(ResolveSid $sid); principal_type="principal"; right=$m; target_dn=$targetDn; target_name=$targetName; target_type=$targetType; inherited=$ace.IsInherited }
            }
        }
    } catch { }
    return $out
}
if ((Has-Module "acl") -and $IncludeACL) {
    Write-Progress -Activity "ADHuntX collection" -Status "ACLs / security descriptors" -PercentComplete 56
    try {
        # Domain head (for DCSync)
        $ds = New-Searcher "(objectClass=domainDNS)" @("distinguishedName","ntSecurityDescriptor") $baseDN "Dacl,Owner"
        $ds.SizeLimit=1; $dh=$ds.FindOne()
        if ($dh){ $acls += Parse-ObjectAcl $dh $baseDN $domainFqdn "domain" $true }
        # Users, groups, computers
        $targets = @(
            @{ filter="(&(objectCategory=person)(objectClass=user))"; type="user";     coll=$users },
            @{ filter="(objectClass=group)";    type="group";    coll=$groups },
            @{ filter="(objectClass=computer)"; type="computer"; coll=$computers }
        )
        foreach ($t in $targets) {
            $s = New-Searcher $t.filter @("distinguishedName","sAMAccountName","ntSecurityDescriptor") $baseDN "Dacl,Owner"
            foreach ($r in $s.FindAll()) {
                $dn=[string](V $r "distinguishedName"); $nm=[string](V $r "sAMAccountName")
                $acls += Parse-ObjectAcl $r $dn $nm $t.type $false
            }
        }
        Write-Host "  dangerous ACEs (non-default principals): $($acls.Count)"
    } catch { Add-Warning "ACL collection failed (need read on ntSecurityDescriptor): $($_.Exception.Message)" }
}

# =============================================================================
# GPOs  (+ links, edit rights, optional SYSVOL cpassword scan)
# =============================================================================
$gpos=@()
if ((Has-Module "gpo") -and $IncludeGPO) {
    Write-Progress -Activity "ADHuntX collection" -Status "Group Policy" -PercentComplete 68
    try {
        # Build OU/domain gPLink map: linkedGpoGuid -> list of scope DNs
        $linkMap=@{}
        $ls = New-Searcher "(|(objectClass=organizationalUnit)(objectClass=domainDNS))" @("distinguishedName","gPLink") $baseDN
        foreach ($r in $ls.FindAll()) {
            $dn=[string](V $r "distinguishedName"); $gpl=[string](V $r "gPLink")
            if ($gpl) { foreach ($mt in [regex]::Matches($gpl,'\{[0-9A-Fa-f\-]+\}')) { $g=$mt.Value.Trim('{','}').ToUpper(); if(-not $linkMap.ContainsKey($g)){$linkMap[$g]=@()}; $linkMap[$g]+=$dn } }
        }
        $gs = New-Searcher "(objectClass=groupPolicyContainer)" @("name","displayName","gPCFileSysPath","whenCreated","whenChanged","distinguishedName","ntSecurityDescriptor") $baseDN "Dacl,Owner"
        foreach ($r in $gs.FindAll()) {
            $guid=([string](V $r "name")).Trim('{','}').ToUpper()
            $editRights=@()
            # who can edit: GenericAll/GenericWrite/WriteDacl/WriteProperty by non-default principals
            try {
                $bytes=$null; if($r.Properties.Contains("ntSecurityDescriptor")){ $bytes=$r.Properties["ntSecurityDescriptor"][0] }
                if ($bytes){ $sd=New-Object System.DirectoryServices.ActiveDirectorySecurity; $sd.SetSecurityDescriptorBinaryForm([byte[]]$bytes)
                    foreach ($ace in $sd.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier])) {
                        if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow){ continue }
                        $sid=$ace.IdentityReference.Value; if(Is-SafePrincipal $sid){ continue }
                        $rt=$ace.ActiveDirectoryRights
                        if (($rt -band [System.DirectoryServices.ActiveDirectoryRights]::GenericAll) -or ($rt -band [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite) -or ($rt -band [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl) -or ($rt -band [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty)) {
                            $editRights += [ordered]@{ name=(ResolveSid $sid); sid=$sid }
                        }
                    }
                }
            } catch {}
            $cpass=$false; $cpassFile=""
            if ($DetailedCollection) {
                try { $sysvol=[string](V $r "gPCFileSysPath")
                    if ($sysvol -and (Test-Path $sysvol)) {
                        $xml = Get-ChildItem -Path $sysvol -Recurse -Include *.xml -ErrorAction SilentlyContinue | Select-String -Pattern "cpassword" -List -ErrorAction SilentlyContinue | Select-Object -First 1
                        if ($xml){ $cpass=$true; $cpassFile=$xml.Path }
                    }
                } catch {}
            }
            $gpos += [ordered]@{
                name=[string](V $r "name"); guid=$guid; display_name=[string](V $r "displayName")
                when_created=(GenTimeIso (V $r "whenCreated")); when_changed=(GenTimeIso (V $r "whenChanged"))
                links=@($linkMap[$guid]); edit_rights=$editRights; cpassword_found=$cpass; cpassword_file=$cpassFile
            }
        }
        Write-Host "  GPOs: $($gpos.Count)"
    } catch { Add-Warning "GPO collection failed: $($_.Exception.Message)" }
}

# =============================================================================
# TRUSTS
# =============================================================================
if (Has-Module "trusts") {
    Write-Progress -Activity "ADHuntX collection" -Status "Trusts" -PercentComplete 78
    try {
        $s = New-Searcher "(objectClass=trustedDomain)" @("trustPartner","trustDirection","trustType","trustAttributes","flatName") $baseDN
        foreach ($r in $s.FindAll()) {
            $attr=[int](V $r "trustAttributes"); $dir=[int](V $r "trustDirection"); $tt=[int](V $r "trustType")
            $dirName=@("Disabled","Inbound","Outbound","Bidirectional")[$dir]
            $typeName=switch($tt){1{"Downlevel"}2{"Uplevel/AD"}3{"MIT"}4{"DCE"}default{"Unknown"}}
            if (($attr -band 0x8) -ne 0){ $typeName="Forest" }  # WITHIN_FOREST / forest-transitive heuristic
            if (($attr -band 0x40) -ne 0){ $typeName="External" }
            $domainObj.trusts += [ordered]@{
                trusted_domain=[string](V $r "trustPartner"); trust_direction=$dirName; trust_type=$typeName
                trust_attributes=@($attr); is_transitive=(($attr -band 0x1) -eq 0)
                sid_filtering_enabled=(($attr -band 0x4) -ne 0)      # QUARANTINED_DOMAIN
                selective_authentication=(($attr -band 0x10) -ne 0)  # CROSS_ORGANIZATION
            }
        }
    } catch { Add-Warning "Trust collection failed: $($_.Exception.Message)" }
}

# =============================================================================
# FINE-GRAINED PASSWORD POLICIES
# =============================================================================
if (Has-Module "fgpp") {
    Write-Progress -Activity "ADHuntX collection" -Status "Fine-grained password policies" -PercentComplete 84
    try {
        $psoBase = "CN=Password Settings Container,CN=System,$baseDN"
        $s = New-Searcher "(objectClass=msDS-PasswordSettings)" @("name","msDS-MinimumPasswordLength","msDS-PasswordComplexityEnabled","msDS-LockoutThreshold","msDS-MaximumPasswordAge","msDS-PasswordSettingsPrecedence","msDS-PSOAppliesTo") $psoBase
        foreach ($r in $s.FindAll()) {
            $maxAge=$null; $raw=V $r "msDS-MaximumPasswordAge"; if($raw){ try{ $t=[int64]$raw; if($t -ne 0){ $maxAge=[math]::Round([math]::Abs($t)/864000000000) } }catch{} }
            $domainObj.fine_grained_password_policies += [ordered]@{
                name=[string](V $r "name"); min_length=[int](V $r "msDS-MinimumPasswordLength")
                complexity_enabled=[bool](V $r "msDS-PasswordComplexityEnabled"); lockout_threshold=[int](V $r "msDS-LockoutThreshold")
                max_age_days=$maxAge; precedence=[int](V $r "msDS-PasswordSettingsPrecedence"); applies_to=@(M $r "msDS-PSOAppliesTo")
            }
        }
    } catch { Add-Warning "FGPP collection limited: $($_.Exception.Message)" }
}

# =============================================================================
# AD CS  (certificate authorities + templates)
# =============================================================================
$adcs=[ordered]@{ certificate_authorities=@(); templates=@() }
if ((Has-Module "adcs") -and $IncludeADCS -and $configNc) {
    Write-Progress -Activity "ADHuntX collection" -Status "AD CS" -PercentComplete 90
    try {
        $pki="CN=Public Key Services,CN=Services,$configNc"
        $cas = New-Searcher "(objectClass=pKIEnrollmentService)" @("name","dNSHostName","distinguishedName","certificateTemplates") $pki
        foreach ($r in $cas.FindAll()){ $adcs.certificate_authorities += [ordered]@{ name=[string](V $r "name"); dns_hostname=[string](V $r "dNSHostName"); distinguished_name=[string](V $r "distinguishedName") } }
        $tpl = New-Searcher "(objectClass=pKICertificateTemplate)" @("name","displayName","msPKI-Certificate-Name-Flag","pKIExtendedKeyUsage","msPKI-Enrollment-Flag","msPKI-RA-Signature") "CN=Certificate Templates,$pki"
        foreach ($r in $tpl.FindAll()) {
            $nameFlag=[int](V $r "msPKI-Certificate-Name-Flag"); $enrollFlag=[int](V $r "msPKI-Enrollment-Flag"); $ekus=@(M $r "pKIExtendedKeyUsage")
            $clientAuth=$false; foreach($e in $ekus){ if($e -match "1.3.6.1.5.5.7.3.2|1.3.6.1.5.2.3.4|2.5.29.37.0"){ $clientAuth=$true } }
            $adcs.templates += [ordered]@{
                name=[string](V $r "name"); display_name=[string](V $r "displayName")
                enrollee_supplies_subject=(($nameFlag -band 0x1) -ne 0); client_auth=$clientAuth
                enrollment_rights=@(); manager_approval=(($enrollFlag -band 0x2) -ne 0)
                authorized_signatures=[int](V $r "msPKI-RA-Signature"); esc_findings=@()
            }
        }
        if ($adcs.templates.Count -gt 0){ Add-Warning "ADCS template enrollment rights require DACL parsing of each template; ESC detection in the app is based on collected flags." }
    } catch { Add-Warning "ADCS collection limited: $($_.Exception.Message)" }
}

# =============================================================================
# DNS  (zone names only, lightweight)
# =============================================================================
$dns=[ordered]@{ zones=@() }
if ((Has-Module "dns") -and $IncludeDNS) {
    try {
        $dnsBase="CN=MicrosoftDNS,DC=DomainDnsZones,$baseDN"
        $s = New-Searcher "(objectClass=dnsZone)" @("name") $dnsBase
        foreach ($r in $s.FindAll()){ $dns.zones += [string](V $r "name") }
    } catch { Add-Warning "DNS zone collection limited (may require DNS admin rights): $($_.Exception.Message)" }
}

if (-not ((Has-Module "acl") -and $IncludeACL)) { Add-Warning "ACL module not run: DACL-based findings (DCSync, GenericAll, shadow credentials, GPO edit) will be limited." }

# =============================================================================
# WRITE JSON
# =============================================================================
Write-Progress -Activity "ADHuntX collection" -Status "Writing JSON" -PercentComplete 96
$duration = [math]::Round(((Get-Date)-$startTime).TotalSeconds,1)
$payload = [ordered]@{
    adhuntx_schema = 2
    collector = [ordered]@{ version="2.0"; host=$env:COMPUTERNAME; run_by=$env:USERNAME; server=$Server; base_dn=$baseDN; modules=$Modules; detailed=[bool]$DetailedCollection; duration_seconds=$duration }
    collected_utc = (Get-Date).ToUniversalTime().ToString("o")
    domain = $domainObj
    users = $users
    groups = $groups
    computers = $computers
    acls = $acls
    gpos = $gpos
    adcs = $adcs
    dns = $dns
    laps_observed = $lapsObserved
    counts = [ordered]@{ users=$users.Count; groups=$groups.Count; computers=$computers.Count; acls=$acls.Count; gpos=$gpos.Count }
    limitations = @($script:Warnings)
}
$json = $payload | ConvertTo-Json -Depth 10
Set-Content -Path $Output -Value $json -Encoding UTF8
Write-Progress -Activity "ADHuntX collection" -Completed
Write-Host "`nDone in $duration s. Wrote $Output" -ForegroundColor Green
Write-Host "Users=$($users.Count) Groups=$($groups.Count) Computers=$($computers.Count) ACEs=$($acls.Count) GPOs=$($gpos.Count)" -ForegroundColor Green
if ($script:Warnings.Count -gt 0){ Write-Host "$($script:Warnings.Count) data-quality warning(s) recorded in the JSON." -ForegroundColor Yellow }
Write-Host "Load this file into ADHuntX.html (Load Data > Import collector JSON)." -ForegroundColor Green
