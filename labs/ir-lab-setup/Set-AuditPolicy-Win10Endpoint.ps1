#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows 10 Enterprise (AD-Joined Endpoint) — Audit Policy Configurator v7.0
    Target : VM2 — Windows 10 Enterprise, domain-joined victim endpoint

.DESCRIPTION
    Phase 0  — Backup       : Save current auditpol state before any changes
    Phase 1  — Pre-Flight   : Verify OS, PS version, admin rights, AD join status
    Phase 2  — Configure    : Apply endpoint-specific audit subcategories + registry
    Phase 3  — Log Size     : Set Security log to 1 GB
    Phase 4  — Enforce      : gpupdate /force
    Phase 5  — Validate     : Policy checks + live event generation
    Phase 6  — Auto-Fix     : Re-apply any failed control, re-validate
    Phase 7  — Report       : Final pass/fail summary + interactive remediation

.NOTES
    Run as Administrator on Windows 10 Enterprise (domain-joined).
    PowerShell 5.1+ required.
    Version : 7.0
    Fixes   :
      - Replaced custom -WhatIf with -DryRun
      - Added transcript try/finally protection
      - Fixed broken failure guide array syntax
      - Added command-driven remediation/verification framework
      - Added interactive Execute / Verify / Manual / GUI options
      - Completed PowerShell logging auto-fix (Invocation + ModuleNames)
      - Standardized external command execution and output capture
#>

[CmdletBinding()]
param(
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Globals ──────────────────────────────────────────────────────────────────
$script:Results            = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:FixCount           = 0
$script:TranscriptStarted  = $false
$script:InteractiveEnabled = [Environment]::UserInteractive

$Timestamp        = Get-Date -Format 'yyyyMMdd_HHmmss'
$LogFile          = "$env:SystemDrive\AuditPolicy_Win10_$Timestamp.log"
$TranscriptFile   = "$env:SystemDrive\AuditPolicy_Win10_Transcript_$Timestamp.log"
$BackupFile       = "$env:SystemDrive\AuditPolicy_Backup_$Timestamp.csv"
$PSTranscriptDir  = "$env:SystemDrive\PSTranscripts"

try {
    Start-Transcript -Path $TranscriptFile -Append | Out-Null
    $script:TranscriptStarted = $true
} catch {
    Write-Warning "Could not start transcript: $($_.Exception.Message)"
}

# ── Script integrity hash ────────────────────────────────────────────────────
$ScriptHash = $null
try {
    if ($MyInvocation.MyCommand.Path) {
        $ScriptHash = (Get-FileHash -Path $MyInvocation.MyCommand.Path -Algorithm SHA256).Hash
    }
} catch {}

# ── Helpers ──────────────────────────────────────────────────────────────────
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')

    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line  = "[$ts][$Level] $Message"
    $color = switch ($Level) {
        'PASS' { 'Green' }
        'FAIL' { 'Red' }
        'FIX'  { 'Yellow' }
        'HEAD' { 'Cyan' }
        'WARN' { 'Magenta' }
        default { 'White' }
    }

    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $LogFile -Value $line -ErrorAction Stop } catch {}
}

function Add-Result {
    param([string]$Control, [string]$Status, [string]$Detail = '')
    $script:Results.Add([PSCustomObject]@{
        Control = $Control
        Status  = $Status
        Detail  = $Detail
    })
}

function Invoke-ExternalCommand {
    param(
        [Parameter(Mandatory)] [string]$FileName,
        [string]$Arguments = '',
        [switch]$CaptureOutput
    )

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = $FileName
    $psi.Arguments              = $Arguments
    $psi.UseShellExecute        = $false
    $psi.CreateNoWindow         = $true
    $psi.RedirectStandardOutput = $CaptureOutput.IsPresent
    $psi.RedirectStandardError  = $CaptureOutput.IsPresent

    $proc = [System.Diagnostics.Process]::Start($psi)

    $stdout = ''
    $stderr = ''

    if ($CaptureOutput) {
        $stdout = $proc.StandardOutput.ReadToEnd()
        $stderr = $proc.StandardError.ReadToEnd()
    }

    $proc.WaitForExit()

    [PSCustomObject]@{
        ExitCode = $proc.ExitCode
        StdOut   = $stdout
        StdErr   = $stderr
    }
}

function Invoke-AuditPol {
    param([string[]]$Arguments)

    $result = Invoke-ExternalCommand -FileName 'auditpol.exe' -Arguments ($Arguments -join ' ') -CaptureOutput
    [PSCustomObject]@{
        Output   = $result.StdOut
        Error    = $result.StdErr
        ExitCode = $result.ExitCode
    }
}

function Set-RegistryDword {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [int]$Value
    )

    if (-not (Test-Path $Path)) {
        $null = New-Item -Path $Path -Force
    }

    if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    } else {
        $null = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType DWord -Force
    }
}

function Set-RegistryString {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [string]$Value
    )

    if (-not (Test-Path $Path)) {
        $null = New-Item -Path $Path -Force
    }

    if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
        Set-ItemProperty -Path $Path -Name $Name -Value $Value -Force
    } else {
        $null = New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType String -Force
    }
}

function Set-AuditSubcategory {
    param([string]$SubCategory, [bool]$Success, [bool]$Failure)

    if ($DryRun) {
        $preview = "/set /subcategory:`"$SubCategory`""
        if ($Success) { $preview += ' /success:enable' }
        if ($Failure) { $preview += ' /failure:enable' }
        Write-Log "  [DRYRUN] auditpol $preview" -Level WARN
        return $true
    }

    $args = @('/set', "/subcategory:`"$SubCategory`"")
    if ($Success) { $args += '/success:enable' }
    if ($Failure) { $args += '/failure:enable' }

    $result = Invoke-AuditPol -Arguments $args
    return ($result.ExitCode -eq 0)
}

function Invoke-RemediationCommand {
    param(
        [Parameter(Mandatory)] [hashtable]$CommandSpec,
        [string]$Label = 'Command'
    )

    if (-not $CommandSpec.FileName) {
        Write-Log "  $Label missing FileName." -Level FAIL
        return $false
    }

    if ($DryRun) {
        Write-Log "  [DRYRUN] Would execute: $($CommandSpec.FileName) $($CommandSpec.Arguments)" -Level WARN
        return $true
    }

    $result = Invoke-ExternalCommand -FileName $CommandSpec.FileName -Arguments $CommandSpec.Arguments -CaptureOutput
    Write-Host ''
    Write-Host "  >>> $Label OUTPUT >>>" -ForegroundColor Cyan
    if ($result.StdOut) { Write-Host $result.StdOut -ForegroundColor Gray }
    if ($result.StdErr) { Write-Host $result.StdErr -ForegroundColor DarkYellow }
    Write-Host "  <<< ExitCode: $($result.ExitCode) <<<" -ForegroundColor Cyan
    Write-Host ''

    if ($result.ExitCode -eq 0) {
        Write-Log "  $Label executed successfully." -Level PASS
        return $true
    } else {
        Write-Log "  $Label failed with exit code $($result.ExitCode)." -Level FAIL
        return $false
    }
}

function Show-CommandSpec {
    param(
        [Parameter(Mandatory)] [hashtable]$CommandSpec,
        [string]$Label = 'Command'
    )

    Write-Host ''
    Write-Host "  $Label:" -ForegroundColor Cyan
    Write-Host "    $($CommandSpec.FileName) $($CommandSpec.Arguments)" -ForegroundColor White
    Write-Host ''
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 0 — BACKUP
# ─────────────────────────────────────────────────────────────────────────────
function Backup-AuditPolicy {
    Write-Log "PHASE 0 — Backing up current auditpol state -> $BackupFile" -Level HEAD

    if ($DryRun) {
        Write-Log "  [DRYRUN] Would run: auditpol /get /category:* /r > $BackupFile" -Level WARN
        return
    }

    try {
        $result = Invoke-AuditPol -Arguments @('/get', '/category:*', '/r')
        if ($result.ExitCode -eq 0) {
            Set-Content -Path $BackupFile -Value $result.Output -Encoding UTF8
            Write-Log "  Backup saved: $BackupFile" -Level PASS
        } else {
            Write-Log "  Backup failed (auditpol exit $($result.ExitCode)) $($result.Error)" -Level WARN
        }
    } catch {
        Write-Log "  Backup error: $($_.Exception.Message)" -Level WARN
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — PRE-FLIGHT
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-PreFlight {
    Write-Log "PHASE 1 — Pre-Flight Checks" -Level HEAD

    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    Write-Log "  OS      : $($os.Caption)"
    Write-Log "  Build   : $($os.BuildNumber)"
    Write-Log "  Host    : $env:COMPUTERNAME"
    Write-Log "  User    : $env:USERNAME"
    if ($ScriptHash) { Write-Log "  ScriptSHA256: $ScriptHash" }

    if ($os.Caption -notmatch 'Windows 10') {
        Write-Log "  WARNING: This script targets Windows 10. Detected: $($os.Caption)" -Level WARN
    }

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem
    if ($cs.PartOfDomain) {
        Write-Log "  AD Join : YES — Domain: $($cs.Domain)" -Level PASS
        Write-Log "  NOTE    : Domain GPO can override local audit settings at next GP refresh." -Level WARN
    } else {
        Write-Log "  AD Join : NO — Machine is not domain-joined" -Level WARN
    }

    Write-Log "  PS Ver  : $($PSVersionTable.PSVersion)"
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw 'PowerShell 5.1+ required'
    }

    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Script must run as Administrator'
    }

    Write-Log "  Admin   : Confirmed" -Level PASS

    if ($DryRun) {
        Write-Log "  MODE    : DRY RUN — No changes will be applied" -Level WARN
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — CONFIGURE
# ─────────────────────────────────────────────────────────────────────────────
function Set-AuditPolicies {
    Write-Log "PHASE 2 — Configuring Endpoint Audit Policies" -Level HEAD

    if (-not $DryRun) {
        Set-RegistryDword -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'SCENoApplyLegacyAuditPolicy' -Value 1
    }
    Write-Log "  SCENoApplyLegacyAuditPolicy = 1 (Advanced overrides Basic)"

    $policies = @(
        @{ Sub='Credential Validation';         S=$true;  F=$true  },
        @{ Sub='Logon';                         S=$true;  F=$true  },
        @{ Sub='Logoff';                        S=$true;  F=$false },
        @{ Sub='Account Lockout';               S=$true;  F=$false },
        @{ Sub='Special Logon';                 S=$true;  F=$false },
        @{ Sub='User Account Management';       S=$true;  F=$true  },
        @{ Sub='Security Group Management';     S=$true;  F=$false },
        @{ Sub='Sensitive Privilege Use';       S=$true;  F=$true  },
        @{ Sub='Process Creation';              S=$true;  F=$false },
        @{ Sub='Process Termination';           S=$true;  F=$false },
        @{ Sub='Audit Policy Change';           S=$true;  F=$true  },
        @{ Sub='Authentication Policy Change';  S=$true;  F=$false },
        @{ Sub='Security State Change';         S=$true;  F=$true  },
        @{ Sub='Security System Extension';     S=$true;  F=$false },
        @{ Sub='Other Object Access Events';    S=$true;  F=$false }
    )

    foreach ($p in $policies) {
        $ok  = Set-AuditSubcategory -SubCategory $p.Sub -Success $p.S -Failure $p.F
        $lvl = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "  [SET] $($p.Sub) — $(if($ok){'OK'}else{'FAILED'})" -Level $lvl
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2B — REGISTRY
# ─────────────────────────────────────────────────────────────────────────────
function Set-RegistryLogging {
    Write-Log "PHASE 2B — Registry-Based Logging" -Level HEAD

    if ($DryRun) {
        Write-Log "  [DRYRUN] Would write CmdLine, ScriptBlock, ModuleLogging, Transcription registry keys" -Level WARN
        return
    }

    $cmdPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    Set-RegistryDword -Path $cmdPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1
    Write-Log "  [SET] CmdLine in Event 4688 — OK"

    $sbPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    Set-RegistryDword -Path $sbPath -Name 'EnableScriptBlockLogging' -Value 1
    Set-RegistryDword -Path $sbPath -Name 'EnableScriptBlockInvocationLogging' -Value 1
    Write-Log "  [SET] PowerShell Script Block Logging — OK"

    $modPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    Set-RegistryDword -Path $modPath -Name 'EnableModuleLogging' -Value 1
    $modNames = "$modPath\ModuleNames"
    if (-not (Test-Path $modNames)) { $null = New-Item -Path $modNames -Force }
    Set-RegistryString -Path $modNames -Name '*' -Value '*'
    Write-Log "  [SET] PowerShell Module Logging (all modules) — OK"

    $transPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    Set-RegistryDword  -Path $transPath -Name 'EnableTranscripting'    -Value 1
    Set-RegistryDword  -Path $transPath -Name 'EnableInvocationHeader' -Value 1
    Set-RegistryString -Path $transPath -Name 'OutputDirectory'        -Value $PSTranscriptDir

    if (-not (Test-Path $PSTranscriptDir)) {
        $null = New-Item -Path $PSTranscriptDir -ItemType Directory -Force
    }

    try {
        $acl = Get-Acl -Path $PSTranscriptDir
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { $null = $acl.RemoveAccessRule($_) }

        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            'NT AUTHORITY\SYSTEM','FullControl','ContainerInherit,ObjectInherit','None','Allow'))
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            'BUILTIN\Administrators','FullControl','ContainerInherit,ObjectInherit','None','Allow'))

        Set-Acl -Path $PSTranscriptDir -AclObject $acl
        Write-Log "  [SET] PSTranscripts ACL restricted (SYSTEM + Admins only) — OK"
    } catch {
        Write-Log "  [WARN] Could not set PSTranscripts ACL: $($_.Exception.Message)" -Level WARN
    }

    Write-Log "  [SET] PowerShell Transcription -> $PSTranscriptDir — OK"
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 3 — LOG SIZE
# ─────────────────────────────────────────────────────────────────────────────
function Set-SecurityLogSize {
    Write-Log "PHASE 3 — Configuring Security Event Log Size (1 GB)" -Level HEAD

    if ($DryRun) {
        Write-Log "  [DRYRUN] wevtutil sl Security /ms:1073741824 /rt:false" -Level WARN
        return
    }

    try {
        $result = Invoke-ExternalCommand -FileName 'wevtutil.exe' -Arguments 'sl Security /ms:1073741824 /rt:false' -CaptureOutput
        if ($result.ExitCode -eq 0) {
            Write-Log "  [SET] Security log max size = 1 GB, retention = manual — OK" -Level PASS
        } else {
            Write-Log "  [ERR] wevtutil exited with code $($result.ExitCode): $($result.StdErr)" -Level FAIL
        }
    } catch {
        Write-Log "  [ERR] Failed to set log size: $($_.Exception.Message)" -Level FAIL
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 4 — GPUPDATE
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-GPUpdate {
    Write-Log "PHASE 4 — gpupdate /force" -Level HEAD

    if ($DryRun) {
        Write-Log "  [DRYRUN] Would run: gpupdate /force" -Level WARN
        return
    }

    $result = Invoke-ExternalCommand -FileName 'gpupdate.exe' -Arguments '/force' -CaptureOutput
    Write-Log "  gpupdate exit code: $($result.ExitCode)"
    Start-Sleep -Seconds 4
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 5 — VALIDATE
# ─────────────────────────────────────────────────────────────────────────────
function Test-AuditPolSetting {
    param([string]$Sub, [bool]$NeedSuccess, [bool]$NeedFailure = $false)

    $result = Invoke-AuditPol -Arguments @('/get', "/subcategory:`"$Sub`"")
    $line   = ($result.Output -split "`r?`n") |
              Where-Object { $_ -match [regex]::Escape($Sub) } |
              Select-Object -First 1

    if (-not $line)                                   { return $false }
    if ($line -match 'No Auditing')                   { return $false }
    if ($NeedSuccess -and $line -notmatch 'Success') { return $false }
    if ($NeedFailure -and $line -notmatch 'Failure') { return $false }
    return $true
}

function Test-RegDWord {
    param([string]$Path, [string]$Name, [int]$Expected = 1)
    try { return ((Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop) -eq $Expected) }
    catch { return $false }
}

function Test-LiveEvent4688 {
    $marker = "AuditVerify_$(Get-Date -Format 'HHmmssff')"
    $before = Get-Date

    $null = Invoke-ExternalCommand -FileName 'cmd.exe' -Arguments "/c echo $marker"
    Start-Sleep -Seconds 3

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 4688
        StartTime = $before
    } -ErrorAction SilentlyContinue

    if (-not $events) { return @{ Found=$false; HasCmdLine=$false } }

    $match      = $events | Where-Object { $_.Message -match [regex]::Escape($marker) }
    $found      = ($null -ne $match)
    $hasCmdLine = $false

    if ($found) {
        $hasCmdLine = ($match | Select-Object -First 1).Message -match 'Process Command Line\s*:\s*\S+'
    }

    @{ Found=$found; HasCmdLine=$hasCmdLine }
}

function Test-LivePS4104 {
    $marker = "PSTest_$(Get-Date -Format 'HHmmssff')"
    $before = Get-Date

    $null = Invoke-ExternalCommand -FileName 'powershell.exe' -Arguments "-NoProfile -NonInteractive -Command `"Write-Output '$marker'`"" -CaptureOutput
    Start-Sleep -Seconds 3

    $events = Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-PowerShell/Operational'
        Id        = 4104
        StartTime = $before
    } -ErrorAction SilentlyContinue

    if (-not $events) { return $false }
    return ($null -ne ($events | Where-Object { $_.Message -match [regex]::Escape($marker) }))
}

function Invoke-Validation {
    Write-Log "PHASE 5 — Validation" -Level HEAD

    $checks = @(
        @{ Label='Credential Validation Audit';      Sub='Credential Validation';        S=$true;  F=$true  },
        @{ Label='Logon Audit';                      Sub='Logon';                        S=$true;  F=$true  },
        @{ Label='Logoff Audit';                     Sub='Logoff';                       S=$true;  F=$false },
        @{ Label='Account Lockout Audit';            Sub='Account Lockout';              S=$true;  F=$false },
        @{ Label='Special Logon Audit';              Sub='Special Logon';                S=$true;  F=$false },
        @{ Label='User Account Mgmt Audit';          Sub='User Account Management';      S=$true;  F=$true  },
        @{ Label='Security Group Mgmt Audit';        Sub='Security Group Management';    S=$true;  F=$false },
        @{ Label='Sensitive Privilege Use Audit';    Sub='Sensitive Privilege Use';      S=$true;  F=$true  },
        @{ Label='Process Creation Audit';           Sub='Process Creation';             S=$true;  F=$false },
        @{ Label='Process Termination Audit';        Sub='Process Termination';          S=$true;  F=$false },
        @{ Label='Audit Policy Change';              Sub='Audit Policy Change';          S=$true;  F=$true  },
        @{ Label='Auth Policy Change Audit';         Sub='Authentication Policy Change'; S=$true;  F=$false },
        @{ Label='Security State Change Audit';      Sub='Security State Change';        S=$true;  F=$true  },
        @{ Label='Security System Extension Audit';  Sub='Security System Extension';    S=$true;  F=$false },
        @{ Label='Other Object Access Events Audit'; Sub='Other Object Access Events';   S=$true;  F=$false }
    )

    foreach ($c in $checks) {
        $ok     = Test-AuditPolSetting -Sub $c.Sub -NeedSuccess $c.S -NeedFailure $c.F
        $status = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "  $($c.Label) — $status" -Level $status
        Add-Result $c.Label $status
    }

    $regChecks = @(
        @{ Label='CmdLine in Event 4688 (Reg)';
           Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';
           Name='ProcessCreationIncludeCmdLine_Enabled' },
        @{ Label='PS Script Block Logging (Reg)';
           Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';
           Name='EnableScriptBlockLogging' },
        @{ Label='PS Module Logging (Reg)';
           Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';
           Name='EnableModuleLogging' }
    )

    foreach ($r in $regChecks) {
        $ok     = Test-RegDWord -Path $r.Path -Name $r.Name
        $status = if ($ok) { 'PASS' } else { 'FAIL' }
        Write-Log "  $($r.Label) — $status" -Level $status
        Add-Result $r.Label $status
    }

    $logInfo = Get-WinEvent -ListLog 'Security'
    $logMB   = [math]::Round($logInfo.MaximumSizeInBytes / 1MB)
    $logOk   = $logInfo.MaximumSizeInBytes -ge 1073741824
    $status  = if ($logOk) { 'PASS' } else { 'FAIL' }

    Write-Log "  Security Log Size = $logMB MB — $status $(if(-not $logOk){'(needs >= 1024 MB)'})" -Level $status
    Add-Result 'Security Log Size >= 1 GB' $status

    Write-Log "  Running live Event 4688 test..."
    $live = Test-LiveEvent4688

    if ($live.Found -and $live.HasCmdLine) {
        Write-Log "  LIVE 4688 + CmdLine — PASS" -Level PASS
        Add-Result 'LIVE Event 4688 + CmdLine' 'PASS' 'Event found, command line populated'
    } elseif ($live.Found) {
        Write-Log "  LIVE 4688 — FAIL: Event exists but CmdLine field is EMPTY" -Level FAIL
        Add-Result 'LIVE Event 4688 + CmdLine' 'FAIL' 'CmdLine blank — needs reboot or GP refresh'
    } else {
        Write-Log "  LIVE 4688 — FAIL: No event generated" -Level FAIL
        Add-Result 'LIVE Event 4688 + CmdLine' 'FAIL' 'No 4688 event — Process Creation audit not active'
    }

    Write-Log "  Running live PS Script Block test (Event 4104)..."
    $ps4104 = Test-LivePS4104
    $status = if ($ps4104) { 'PASS' } else { 'FAIL' }
    Write-Log "  LIVE PS ScriptBlock 4104 — $status" -Level $status
    Add-Result 'LIVE PS ScriptBlock Event 4104' $status
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 6 — AUTO-FIX
# ─────────────────────────────────────────────────────────────────────────────
function Invoke-AutoFix {
    Write-Log "PHASE 6 — Auto-Fix" -Level HEAD

    if ($DryRun) {
        Write-Log "  [DRYRUN] Auto-Fix skipped in dry-run mode. Run without -DryRun to apply." -Level WARN
        return
    }

    $failures = $script:Results | Where-Object Status -eq 'FAIL'
    if (-not $failures) {
        Write-Log "  No failures. Auto-Fix skipped." -Level PASS
        return
    }

    foreach ($f in $failures) {
        Write-Log "  Fixing: $($f.Control)" -Level FIX
        $script:FixCount++

        switch -Wildcard ($f.Control) {
            'Credential Validation Audit'       { $null = Set-AuditSubcategory 'Credential Validation'       $true $true  }
            'Logon Audit'                       { $null = Set-AuditSubcategory 'Logon'                       $true $true  }
            'Logoff Audit'                      { $null = Set-AuditSubcategory 'Logoff'                      $true $false }
            'Account Lockout Audit'             { $null = Set-AuditSubcategory 'Account Lockout'            $true $false }
            'Special Logon Audit'               { $null = Set-AuditSubcategory 'Special Logon'              $true $false }
            'User Account Mgmt Audit'           { $null = Set-AuditSubcategory 'User Account Management'    $true $true  }
            'Security Group Mgmt Audit'         { $null = Set-AuditSubcategory 'Security Group Management'  $true $false }
            'Sensitive Privilege Use Audit'     { $null = Set-AuditSubcategory 'Sensitive Privilege Use'    $true $true  }
            'Process Creation Audit'            { $null = Set-AuditSubcategory 'Process Creation'           $true $false }
            'Process Termination Audit'         { $null = Set-AuditSubcategory 'Process Termination'        $true $false }
            'Audit Policy Change'               { $null = Set-AuditSubcategory 'Audit Policy Change'        $true $true  }
            'Auth Policy Change Audit'          { $null = Set-AuditSubcategory 'Authentication Policy Change' $true $false }
            'Security State Change Audit'       { $null = Set-AuditSubcategory 'Security State Change'      $true $true  }
            'Security System Extension Audit'   { $null = Set-AuditSubcategory 'Security System Extension'  $true $false }
            'Other Object Access Events Audit'  { $null = Set-AuditSubcategory 'Other Object Access Events' $true $false }

            'CmdLine in Event 4688 (Reg)' {
                Set-RegistryDword -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' `
                                  -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1
            }

            'PS Script Block Logging (Reg)' {
                $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
                Set-RegistryDword -Path $p -Name 'EnableScriptBlockLogging' -Value 1
                Set-RegistryDword -Path $p -Name 'EnableScriptBlockInvocationLogging' -Value 1
            }

            'PS Module Logging (Reg)' {
                $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
                Set-RegistryDword -Path $p -Name 'EnableModuleLogging' -Value 1
                $moduleNames = "$p\ModuleNames"
                if (-not (Test-Path $moduleNames)) { $null = New-Item -Path $moduleNames -Force }
                Set-RegistryString -Path $moduleNames -Name '*' -Value '*'
            }

            'Security Log Size*' {
                $null = Invoke-ExternalCommand -FileName 'wevtutil.exe' -Arguments 'sl Security /ms:1073741824 /rt:false'
            }

            'LIVE*' {
                Write-Log "    Live failure — downstream of above fixes. Will re-test." -Level FIX
            }
        }
    }

    Write-Log "  Re-running gpupdate /force after fixes..." -Level FIX
    $null = Invoke-ExternalCommand -FileName 'gpupdate.exe' -Arguments '/force' -CaptureOutput
    Start-Sleep -Seconds 5

    Write-Log "PHASE 6B — Re-Validation" -Level HEAD
    $script:Results.Clear()
    Invoke-Validation
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 7 — FAILURE GUIDE / COMMAND MAP
# ─────────────────────────────────────────────────────────────────────────────
$script:FailureGuide = @{

    'Logon Audit' = @{
        Hint = 'Logon audit is not effectively applied. Domain GPO may be overriding local policy.'
        Manual = @(
            'Run the verify command below to inspect the effective setting.',
            'If it reverts after gpupdate, fix the controlling domain GPO on the DC.',
            'On the DC GPO path: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Logon/Logoff > Audit Logon = Success + Failure'
        )
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Logon" /success:enable /failure:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Logon"'
        }
        GuiExe  = ''
        GuiPath = @(
            'No endpoint GUI can reliably show Advanced Audit Policy subcategories',
            'Run gpresult /h C:\GPReport.html',
            'Open the report and search for: Audit Logon',
            'Find the Source GPO',
            'Fix that GPO on the Domain Controller'
        )
    }

    'Logoff Audit' = @{
        Hint = 'Logoff audit is not effectively applied. Domain GPO may be overriding local policy.'
        Manual = @(
            'Run the verify command below.',
            'If it reverts after gpupdate, fix the controlling domain GPO on the DC.',
            'On the DC GPO path: Advanced Audit Policy Configuration > Logon/Logoff > Audit Logoff = Success'
        )
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Logoff" /success:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Logoff"'
        }
        GuiExe  = ''
        GuiPath = @(
            'No endpoint GUI can reliably show Advanced Audit Policy subcategories',
            'Use the same GPO identified for Logon Audit',
            'Fix Audit Logoff on the Domain Controller'
        )
    }

    'Credential Validation Audit' = @{
        Hint = 'Credential Validation auditing is not correctly set.'
        Manual = @(
            'Apply the remediation command.',
            'Then run the verify command.'
        )
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Credential Validation" /success:enable /failure:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Credential Validation"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > Account Logon',
            'Open Audit Credential Validation',
            'Enable Success + Failure'
        )
    }

    'Account Lockout Audit' = @{
        Hint = 'Account Lockout auditing is not correctly set.'
        Manual = @('Apply the remediation command, then run the verify command.')
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Account Lockout" /success:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Account Lockout"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > Logon/Logoff',
            'Open Audit Account Lockout',
            'Enable Success'
        )
    }

    'Special Logon Audit' = @{
        Hint = 'Special Logon auditing is not correctly set.'
        Manual = @('Apply the remediation command, then run the verify command.')
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Special Logon" /success:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Special Logon"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > Logon/Logoff',
            'Open Audit Special Logon',
            'Enable Success'
        )
    }

    'User Account Mgmt Audit' = @{
        Hint = 'User Account Management auditing is not correctly set.'
        Manual = @('Apply the remediation command, then run the verify command.')
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"User Account Management" /success:enable /failure:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"User Account Management"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > Account Management',
            'Open Audit User Account Management',
            'Enable Success + Failure'
        )
    }

    'Security Group Mgmt Audit' = @{
        Hint = 'Security Group Management auditing is not correctly set.'
        Manual = @('Apply the remediation command, then run the verify command.')
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Security Group Management" /success:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Security Group Management"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > Account Management',
            'Open Audit Security Group Management',
            'Enable Success'
        )
    }

    'Sensitive Privilege Use Audit' = @{
        Hint = 'Sensitive Privilege Use auditing is not correctly set.'
        Manual = @('Apply the remediation command, then run the verify command.')
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Sensitive Privilege Use"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > Privilege Use',
            'Open Audit Sensitive Privilege Use',
            'Enable Success + Failure'
        )
    }

    'Process Creation Audit' = @{
        Hint = 'Process Creation auditing is not enabled.'
        Manual = @(
            'Apply the remediation command.',
            'Then run the verify command.'
        )
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Process Creation" /success:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Process Creation"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > Detailed Tracking',
            'Open Audit Process Creation',
            'Enable Success'
        )
    }

    'Process Termination Audit' = @{
        Hint = 'Process Termination auditing is not enabled.'
        Manual = @('Apply the remediation command, then run the verify command.')
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Process Termination" /success:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Process Termination"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > Detailed Tracking',
            'Open Audit Process Termination',
            'Enable Success'
        )
    }

    'Audit Policy Change' = @{
        Hint = 'Audit Policy Change is not correctly set.'
        Manual = @('Apply the remediation command, then run the verify command.')
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Audit Policy Change" /success:enable /failure:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Audit Policy Change"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > Policy Change',
            'Open Audit Audit Policy Change',
            'Enable Success + Failure'
        )
    }

    'Auth Policy Change Audit' = @{
        Hint = 'Authentication Policy Change is not correctly set.'
        Manual = @('Apply the remediation command, then run the verify command.')
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Authentication Policy Change" /success:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Authentication Policy Change"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > Policy Change',
            'Open Audit Authentication Policy Change',
            'Enable Success'
        )
    }

    'Security State Change Audit' = @{
        Hint = 'Security State Change is not correctly set.'
        Manual = @('Apply the remediation command, then run the verify command.')
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Security State Change" /success:enable /failure:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Security State Change"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > System',
            'Open Audit Security State Change',
            'Enable Success + Failure'
        )
    }

    'Security System Extension Audit' = @{
        Hint = 'Security System Extension is not correctly set.'
        Manual = @('Apply the remediation command, then run the verify command.')
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Security System Extension" /success:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Security System Extension"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > System',
            'Open Audit Security System Extension',
            'Enable Success'
        )
    }

    'Other Object Access Events Audit' = @{
        Hint = 'Other Object Access Events is not correctly set.'
        Manual = @('Apply the remediation command, then run the verify command.')
        Command = @{
            FileName  = 'auditpol.exe'
            Arguments = '/set /subcategory:"Other Object Access Events" /success:enable'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Other Object Access Events"'
        }
        GuiExe  = 'secpol.msc'
        GuiPath = @(
            'Open Local Security Policy',
            'Navigate: Security Settings > Advanced Audit Policy Configuration > Object Access',
            'Open Audit Other Object Access Events',
            'Enable Success'
        )
    }

    'CmdLine in Event 4688 (Reg)' = @{
        Hint = 'Command-line capture for Event 4688 is not enabled.'
        Manual = @(
            'Apply the registry command.',
            'Then verify the registry value.'
        )
        Command = @{
            FileName  = 'reg.exe'
            Arguments = 'add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f'
        }
        Verify = @{
            FileName  = 'reg.exe'
            Arguments = 'query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled'
        }
        GuiExe  = 'regedit.exe'
        GuiPath = @(
            'Open Registry Editor',
            'Navigate to HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit',
            'Create or edit DWORD ProcessCreationIncludeCmdLine_Enabled',
            'Set value to 1'
        )
    }

    'PS Script Block Logging (Reg)' = @{
        Hint = 'PowerShell Script Block Logging is not enabled.'
        Manual = @(
            'Enable both ScriptBlockLogging values.',
            'Then verify them.'
        )
        Command = @{
            FileName  = 'powershell.exe'
            Arguments = '-NoProfile -Command "& { reg add ''HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'' /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f; reg add ''HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'' /v EnableScriptBlockInvocationLogging /t REG_DWORD /d 1 /f }"'
        }
        Verify = @{
            FileName  = 'reg.exe'
            Arguments = 'query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"'
        }
        GuiExe  = 'regedit.exe'
        GuiPath = @(
            'Open Registry Editor',
            'Navigate to HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging',
            'Create DWORD EnableScriptBlockLogging = 1',
            'Create DWORD EnableScriptBlockInvocationLogging = 1'
        )
    }

    'PS Module Logging (Reg)' = @{
        Hint = 'PowerShell Module Logging is not fully enabled.'
        Manual = @(
            'Enable Module Logging.',
            'Create ModuleNames\* = *',
            'Then verify.'
        )
        Command = @{
            FileName  = 'powershell.exe'
            Arguments = '-NoProfile -Command "& { reg add ''HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'' /v EnableModuleLogging /t REG_DWORD /d 1 /f; reg add ''HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames'' /v * /t REG_SZ /d * /f }"'
        }
        Verify = @{
            FileName  = 'reg.exe'
            Arguments = 'query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /s'
        }
        GuiExe  = 'regedit.exe'
        GuiPath = @(
            'Open Registry Editor',
            'Navigate to HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging',
            'Create DWORD EnableModuleLogging = 1',
            'Create subkey ModuleNames',
            'Create string * = * inside ModuleNames'
        )
    }

    'Security Log Size >= 1 GB' = @{
        Hint = 'Security event log size is too small.'
        Manual = @(
            'Apply the wevtutil command.',
            'Then verify the Security log size.'
        )
        Command = @{
            FileName  = 'wevtutil.exe'
            Arguments = 'sl Security /ms:1073741824 /rt:false'
        }
        Verify = @{
            FileName  = 'powershell.exe'
            Arguments = '-NoProfile -Command "(Get-WinEvent -ListLog ''Security'').MaximumSizeInBytes"'
        }
        GuiExe  = 'eventvwr.msc'
        GuiPath = @(
            'Open Event Viewer',
            'Go to Windows Logs > Security > Properties',
            'Set Maximum log size (KB) to 1048576',
            'Set retention to Do not overwrite events'
        )
    }

    'LIVE Event 4688 + CmdLine' = @{
        Hint = 'Process Creation audit may be inactive or command-line capture may not yet be effective.'
        Manual = @(
            'Verify Process Creation audit status.',
            'Verify command-line registry setting.',
            'If still failing, reboot and re-run the script.'
        )
        Command = @{
            FileName  = 'cmd.exe'
            Arguments = '/c echo Live 4688 failures generally need upstream policy correction or reboot'
        }
        Verify = @{
            FileName  = 'auditpol.exe'
            Arguments = '/get /subcategory:"Process Creation"'
        }
        GuiExe  = ''
        GuiPath = @(
            'Verify Process Creation audit',
            'Verify command-line registry setting',
            'Reboot if settings are correct but event data is still incomplete'
        )
    }

    'LIVE PS ScriptBlock Event 4104' = @{
        Hint = 'Script Block logging applies to new PowerShell sessions.'
        Manual = @(
            'Close the current PowerShell session.',
            'Open a fresh elevated PowerShell.',
            'Re-run the script.'
        )
        Command = @{
            FileName  = 'cmd.exe'
            Arguments = '/c echo Open a NEW elevated PowerShell session, then re-run this script'
        }
        Verify = @{
            FileName  = 'reg.exe'
            Arguments = 'query "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"'
        }
        GuiExe  = ''
        GuiPath = @(
            'Close current PowerShell session',
            'Open a new elevated PowerShell window',
            'Re-run this script'
        )
    }
}

function Invoke-AutoNavGui {
    param([string]$Control)

    $guide = $script:FailureGuide[$Control]
    if (-not $guide -or -not $guide.GuiPath) {
        Write-Host '  No GUI navigation guide for this control.' -ForegroundColor Yellow
        return
    }

    if (-not $guide.GuiExe) {
        Write-Host ''
        Write-Host '  Running gpresult /r /scope computer...' -ForegroundColor Cyan
        Write-Host ''

        try {
            $result = Invoke-ExternalCommand -FileName 'gpresult.exe' -Arguments '/r /scope computer' -CaptureOutput
            if ($result.StdOut) { Write-Host $result.StdOut -ForegroundColor Gray }
            if ($result.StdErr) { Write-Host $result.StdErr -ForegroundColor DarkYellow }
        } catch {
            Write-Host "  Could not run gpresult: $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    if ($guide.GuiExe) {
        Write-Host "`n  Checking if $($guide.GuiExe) is available..." -ForegroundColor Cyan

        $exeFound = $false
        try {
            $mscPath = "$env:SystemRoot\System32\$($guide.GuiExe)"
            if (Test-Path $mscPath) {
                $exeFound = $true
            } elseif (Get-Command $guide.GuiExe -ErrorAction SilentlyContinue) {
                $exeFound = $true
            }
        } catch {}

        if ($exeFound) {
            Write-Host "  Launching $($guide.GuiExe)..." -ForegroundColor Cyan
            try {
                $psi                 = [System.Diagnostics.ProcessStartInfo]::new()
                $psi.FileName        = $guide.GuiExe
                $psi.UseShellExecute = $true
                $null = [System.Diagnostics.Process]::Start($psi)
                Start-Sleep -Seconds 2
            } catch {
                Write-Host "  Launch failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "  $($guide.GuiExe) is not installed on this machine." -ForegroundColor Red
        }
    }

    Write-Host ''
    Write-Host '  ┌── GUI Navigation Steps ─────────────────────────────────┐' -ForegroundColor Cyan
    $i = 1
    foreach ($step in $guide.GuiPath) {
        Write-Host "  │  Step $i : $step" -ForegroundColor White
        $i++
    }
    Write-Host '  └─────────────────────────────────────────────────────────┘' -ForegroundColor Cyan
}

function Invoke-FailurePrompt {
    $failures = $script:Results | Where-Object Status -eq 'FAIL'
    if (-not $failures) { return }

    if (-not $script:InteractiveEnabled) {
        Write-Log '  Non-interactive session detected — skipping failure prompt.' -Level WARN
        return
    }

    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════╗' -ForegroundColor Yellow
    Write-Host '║         REMAINING FAILURES — YOUR ACTION NEEDED         ║' -ForegroundColor Yellow
    Write-Host '╚══════════════════════════════════════════════════════════╝' -ForegroundColor Yellow

    foreach ($f in $failures) {
        $guide = $script:FailureGuide[$f.Control]
        $hint  = if ($guide) { $guide.Hint } else { 'No guide available — check the log file.' }

        Write-Host ''
        Write-Host "FAILED: $($f.Control)" -ForegroundColor Red
        Write-Host "Why   : $hint" -ForegroundColor DarkYellow
        if ($f.Detail) {
            Write-Host "Detail: $($f.Detail)" -ForegroundColor DarkGray
        }

        if (-not $guide) {
            Write-Host 'No structured remediation guide available.' -ForegroundColor Yellow
            continue
        }

        $done = $false
        while (-not $done) {
            Write-Host ''
            Write-Host 'Choose an action:' -ForegroundColor White
            Write-Host '  [M] Show manual steps' -ForegroundColor Green
            Write-Host '  [C] Show remediation command' -ForegroundColor Cyan
            Write-Host '  [V] Run verify command now' -ForegroundColor Cyan
            Write-Host '  [E] Execute remediation command now' -ForegroundColor Yellow
            Write-Host '  [G] Show GUI guidance' -ForegroundColor Magenta
            Write-Host '  [S] Skip this failure' -ForegroundColor DarkGray
            Write-Host '  [Q] Quit prompt' -ForegroundColor DarkGray
            Write-Host -NoNewline 'Choice [M/C/V/E/G/S/Q]: ' -ForegroundColor White

            $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
            Write-Host $key.Character

            switch ($key.Character.ToString().ToUpper()) {
                'M' {
                    Write-Host ''
                    Write-Host 'Manual steps:' -ForegroundColor Green
                    foreach ($step in $guide.Manual) {
                        Write-Host "  - $step" -ForegroundColor White
                    }
                }
                'C' {
                    if ($guide.Command) {
                        Show-CommandSpec -CommandSpec $guide.Command -Label 'Remediation command'
                    } else {
                        Write-Host 'No remediation command defined.' -ForegroundColor Yellow
                    }
                }
                'V' {
                    if ($guide.Verify) {
                        $null = Invoke-RemediationCommand -CommandSpec $guide.Verify -Label 'Verify command'
                    } else {
                        Write-Host 'No verify command defined.' -ForegroundColor Yellow
                    }
                }
                'E' {
                    if ($guide.Command) {
                        $ok = Invoke-RemediationCommand -CommandSpec $guide.Command -Label 'Remediation command'
                        if ($ok -and $guide.Verify) {
                            Write-Host 'Running verify command after remediation...' -ForegroundColor Cyan
                            $null = Invoke-RemediationCommand -CommandSpec $guide.Verify -Label 'Verify command'
                        }
                    } else {
                        Write-Host 'No remediation command defined.' -ForegroundColor Yellow
                    }
                }
                'G' {
                    Invoke-AutoNavGui -Control $f.Control
                }
                'S' {
                    $done = $true
                    Write-Host 'Skipped.' -ForegroundColor DarkGray
                }
                'Q' {
                    Write-Host ''
                    Write-Host 'Exiting failure prompt.' -ForegroundColor DarkGray
                    return
                }
                default {
                    Write-Host 'Invalid choice.' -ForegroundColor Yellow
                }
            }
        }
    }
}

function Write-FinalReport {
    $pass  = ($script:Results | Where-Object Status -eq 'PASS').Count
    $fail  = ($script:Results | Where-Object Status -eq 'FAIL').Count
    $total = $script:Results.Count
    $ts    = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    function Log {
        param([string]$Line, [string]$Color = 'White')
        try { Add-Content -Path $LogFile -Value $Line } catch {}
        Write-Host $Line -ForegroundColor $Color
    }

    Log ''
    Log '=================================================' 'Cyan'
    Log '  AUDIT POLICY REPORT — Windows 10 Endpoint (VM2)' 'Cyan'
    Log "  Host       : $env:COMPUTERNAME  |  User : $env:USERNAME"
    Log "  Time       : $ts"
    Log "  Log        : $LogFile"
    Log "  Transcript : $TranscriptFile"
    Log "  Backup     : $BackupFile"
    Log "  Mode       : $(if($DryRun){'DRY RUN'}else{'APPLIED'})"
    if ($ScriptHash) { Log "  ScriptHash : $ScriptHash (SHA256)" }
    Log '=================================================' 'Cyan'

    foreach ($r in $script:Results) {
        $detail = if ($r.Detail) { " | $($r.Detail)" } else { '' }
        $color  = if ($r.Status -eq 'PASS') { 'Green' } else { 'Red' }
        Log "  [$($r.Status)] $($r.Control)$detail" $color

        if ($r.Status -eq 'FAIL' -and $script:FailureGuide.ContainsKey($r.Control)) {
            $guide = $script:FailureGuide[$r.Control]

            if ($guide.Command) {
                Log "      Remediate: $($guide.Command.FileName) $($guide.Command.Arguments)" 'Yellow'
            }
            if ($guide.Verify) {
                Log "      Verify   : $($guide.Verify.FileName) $($guide.Verify.Arguments)" 'Cyan'
            }
        }
    }

    Log '--------------------------------------------------'
    Log "  Total: $total  |  Passed: $pass  |  Failed: $fail"
    Log "  Auto-Fix Attempts: $($script:FixCount)"
    Log '================================================='

    if ($fail -gt 0) {
        Log "[$ts][FAIL]   $fail control(s) need manual or interactive remediation." 'Red'
    } else {
        Log "[$ts][PASS]   ALL CONTROLS VERIFIED. Endpoint logging fully operational." 'Green'
    }
}

# ── ENTRY POINT ───────────────────────────────────────────────────────────────
try {
    Write-Log "Windows 10 Endpoint Audit Policy Configurator v7.0 — Starting" -Level HEAD
    Backup-AuditPolicy
    Invoke-PreFlight
    Set-AuditPolicies
    Set-RegistryLogging
    Set-SecurityLogSize
    Invoke-GPUpdate
    Invoke-Validation
    Invoke-AutoFix
}
finally {
    if ($script:TranscriptStarted) {
        try { Stop-Transcript | Out-Null } catch {}
    }
}

Write-FinalReport
Invoke-FailurePrompt
