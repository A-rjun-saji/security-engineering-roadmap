#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Server 2025 Domain Controller - Audit Policy Configurator v2.7
    Target : VM4 - Windows Server 2025 DC

.NOTES
    Author  : Security Engineering Roadmap | github: A-rjun-saji
    Version : 2.7
    Fixes from v2.6:
      - FIX: .Count on $null under Set-StrictMode -> wrap Where-Object in @() throughout
    New in v2.7:
      - ADDED: 'Detailed Directory Service Replication' subcategory (S+F)
        Closes DCSync (T1207) detection gap — total controls now 31
    New in v2.6:
      - Post-run PASSED CONTROLS TABLE: shows every succeeded control
        with live auditpol /get confirmation (Inclusion Setting column)
      - Color-coded final dashboard: PASSED / FAILED / SKIPPED counts
      - Auditpol live-read section printed to both console and log file
#>

[CmdletBinding()]
param(
    [switch]$WhatIf,
    [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Results      = [System.Collections.Generic.List[PSCustomObject]]::new()
$script:FixCount     = 0
$script:IsDC         = $false

$script:LogFile        = "$env:SystemDrive\AuditPolicy_DC_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:TranscriptPath = "$env:SystemDrive\AuditPolicy_DC_Transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

Start-Transcript -Path $script:TranscriptPath -Append -Force

# ---------------------------------------------------------------------------
#  LOGGING
# ---------------------------------------------------------------------------
function Write-Log {
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]          # FIX: reject empty strings before StrictMode throws
        [string]$Message,

        [ValidateSet('INFO','PASS','FAIL','FIX','HEAD','WARN')]
        [string]$Level = 'INFO'
    )

    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$Level] $Message"

    $color = switch ($Level) {
        'PASS' { 'Green'   }
        'FAIL' { 'Red'     }
        'FIX'  { 'Yellow'  }
        'HEAD' { 'Cyan'    }
        'WARN' { 'Magenta' }
        default{ 'White'   }
    }

    Write-Host $line -ForegroundColor $color
    Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
}

# FIX: Dedicated separator — no empty string passed to Write-Log
function Write-Separator {
    param([string]$Char = '=', [int]$Width = 56)
    $line = $Char * $Width
    Write-Host $line -ForegroundColor Cyan
    Add-Content -Path $script:LogFile -Value $line -Encoding UTF8
}

function Add-Result {
    param(
        [Parameter(Mandatory)][string]$Control,
        [Parameter(Mandatory)][ValidateSet('PASS','FAIL')][string]$Status,
        [string]$Detail   = '',
        [string]$Category = 'auditpol'
    )
    $existing = $script:Results | Where-Object { $_.Control -eq $Control }
    if ($existing) { $script:Results.Remove($existing) | Out-Null }
    $script:Results.Add([PSCustomObject]@{
        Control  = $Control
        Status   = $Status
        Detail   = $Detail
        Category = $Category
    })
}

# ---------------------------------------------------------------------------
#  AUDIT POLICY TARGETS
# ---------------------------------------------------------------------------
function Get-AuditPolicyTargets {
    @(
        @{ Sub='Credential Validation';              S=$true;  F=$true  }
        @{ Sub='Kerberos Authentication Service';    S=$true;  F=$true  }
        @{ Sub='Kerberos Service Ticket Operations'; S=$true;  F=$true  }
        @{ Sub='Other Account Logon Events';         S=$true;  F=$true  }
        @{ Sub='User Account Management';            S=$true;  F=$true  }
        @{ Sub='Computer Account Management';        S=$true;  F=$true  }
        @{ Sub='Security Group Management';          S=$true;  F=$true  }
        @{ Sub='Other Account Management Events';    S=$true;  F=$true  }
        @{ Sub='Logon';                              S=$true;  F=$true  }
        @{ Sub='Logoff';                             S=$true;  F=$false }
        @{ Sub='Account Lockout';                    S=$true;  F=$false }
        @{ Sub='Special Logon';                      S=$true;  F=$false }
        @{ Sub='Directory Service Access';           S=$true;  F=$true  }
        @{ Sub='Directory Service Changes';          S=$true;  F=$true  }
        @{ Sub='Directory Service Replication';          S=$true;  F=$true  }
        @{ Sub='Detailed Directory Service Replication'; S=$true;  F=$true  }  # FIX v2.7: DCSync full coverage (T1207)
        @{ Sub='Sensitive Privilege Use';                S=$true;  F=$true  }
        @{ Sub='Process Creation';                   S=$true;  F=$false }
        @{ Sub='Audit Policy Change';                S=$true;  F=$true  }
        @{ Sub='Authentication Policy Change';       S=$true;  F=$true  }
        @{ Sub='Authorization Policy Change';        S=$true;  F=$false }
        @{ Sub='Security State Change';              S=$true;  F=$true  }
        @{ Sub='Security System Extension';          S=$true;  F=$true  }
        @{ Sub='System Integrity';                   S=$true;  F=$true  }
    )
}

function Get-AuditTargetByName {
    param([Parameter(Mandatory)][string]$Name)
    return (Get-AuditPolicyTargets | Where-Object { $_.Sub -eq $Name } | Select-Object -First 1)
}

# ---------------------------------------------------------------------------
#  AUDITPOL WRAPPERS
# ---------------------------------------------------------------------------
function Set-AuditSubcategory {
    param(
        [Parameter(Mandatory)][string]$SubCategory,
        [Parameter(Mandatory)][bool]$Success,
        [Parameter(Mandatory)][bool]$Failure
    )

    $successMode = if ($Success) { 'enable' } else { 'disable' }
    $failureMode = if ($Failure) { 'enable' } else { 'disable' }

    if ($WhatIf) {
        Write-Log "[WHATIF] Would set: $SubCategory (S=$successMode F=$failureMode)" -Level WARN
        return $true
    }

    $auditArgs = @(
        '/set'
        "/subcategory:`"$SubCategory`""
        "/success:$successMode"
        "/failure:$failureMode"
    )

    try {
        $output   = & "$env:SystemRoot\System32\auditpol.exe" @auditArgs 2>&1
        $exitCode = $LASTEXITCODE
        if ($exitCode -eq 0) { return $true }
        Write-Log "auditpol exit $exitCode for '$SubCategory': $($output -join ' | ')" -Level WARN
        return $false
    }
    catch {
        Write-Log "EXCEPTION setting '$SubCategory': $($_.Exception.Message)" -Level WARN
        return $false
    }
}

function Test-AuditPolSetting {
    param(
        [Parameter(Mandatory)][string]$Sub,
        [Parameter(Mandatory)][bool]$NeedSuccess,
        [Parameter(Mandatory)][bool]$NeedFailure
    )

    try {
        $raw = & "$env:SystemRoot\System32\auditpol.exe" /get "/subcategory:`"$Sub`"" /r 2>&1
        if ($LASTEXITCODE -ne 0 -or -not $raw) { return $false }

        $cleanRaw = $raw | ForEach-Object { $_ -replace '^\xEF\xBB\xBF', '' -replace '^\?', '' }
        $csv = $cleanRaw | ConvertFrom-Csv
        if (-not $csv) { return $false }

        $row = $csv | Where-Object {
            ($_.PSObject.Properties['Subcategory'].Value).Trim() -eq $Sub
        } | Select-Object -First 1
        if (-not $row) { return $false }

        $setting    = ([string]$row.'Inclusion Setting').Trim()
        if ([string]::IsNullOrWhiteSpace($setting)) { return $false }

        $hasSuccess = $setting -match '\bSuccess\b'
        $hasFailure = $setting -match '\bFailure\b'
        $noAuditing = $setting -match '\bNo Auditing\b'

        if ($noAuditing)                          { return $false }
        if ($NeedSuccess   -and -not $hasSuccess) { return $false }
        if ($NeedFailure   -and -not $hasFailure) { return $false }

        return $true
    }
    catch {
        Write-Log "Test-AuditPolSetting exception for '$Sub': $($_.Exception.Message)" -Level WARN
        return $false
    }
}

# NEW: Get the raw auditpol Inclusion Setting string for a subcategory (used in success table)
function Get-AuditPolInclusionSetting {
    param([Parameter(Mandatory)][string]$Sub)

    try {
        $raw = & "$env:SystemRoot\System32\auditpol.exe" /get "/subcategory:`"$Sub`"" /r 2>&1
        if ($LASTEXITCODE -ne 0 -or -not $raw) { return 'READ ERROR' }

        $cleanRaw = $raw | ForEach-Object { $_ -replace '^\xEF\xBB\xBF', '' -replace '^\?', '' }
        $csv = $cleanRaw | ConvertFrom-Csv
        if (-not $csv) { return 'PARSE ERROR' }

        $row = $csv | Where-Object {
            ($_.PSObject.Properties['Subcategory'].Value).Trim() -eq $Sub
        } | Select-Object -First 1

        if (-not $row) { return 'NOT FOUND' }
        return ([string]$row.'Inclusion Setting').Trim()
    }
    catch {
        return 'EXCEPTION'
    }
}

function Test-RegDWord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Name,
        [int]$Expected = 1
    )
    try {
        $val = Get-ItemPropertyValue -Path $Path -Name $Name -ErrorAction Stop
        return ($val -eq $Expected)
    }
    catch { return $false }
}

# ---------------------------------------------------------------------------
#  LIVE EVENT TESTS
# ---------------------------------------------------------------------------
function Test-LiveEvent4688 {
    $before = (Get-Date).AddSeconds(-10)
    try {
        Start-Process -FilePath 'cmd.exe' -ArgumentList '/c echo DC4688Test > nul' `
                      -WindowStyle Hidden -Wait -ErrorAction Stop
    }
    catch {
        Write-Log "Failed to spawn 4688 test process: $($_.Exception.Message)" -Level WARN
        return @{ Found = $false; HasCmdLine = $false }
    }

    Start-Sleep -Seconds 10

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName='Security'; Id=4688; StartTime=$before
        } -MaxEvents 500 -ErrorAction SilentlyContinue

        if (-not $events) { return @{ Found=$false; HasCmdLine=$false } }

        $match = $events | Where-Object {
            $_.Message -match '(?im)New Process Name:\s+.*\\cmd\.exe' -and
            $_.Message -match '(?im)Process Command Line:\s+.+'
        } | Select-Object -First 1

        if (-not $match) { return @{ Found=$false; HasCmdLine=$false } }
        $hasCmdLine = $match.Message -match '(?im)Process Command Line:\s+\S+'
        return @{ Found=$true; HasCmdLine=$hasCmdLine }
    }
    catch {
        Write-Log "4688 live test exception: $($_.Exception.Message)" -Level WARN
        return @{ Found=$false; HasCmdLine=$false }
    }
}

function Test-LivePS4104 {
    $marker = "PS4104-$(Get-Random -Minimum 10000 -Maximum 999999)"
    $before = (Get-Date).AddSeconds(-5)
    try {
        $argStr = "-NoProfile -ExecutionPolicy Bypass -Command `"Write-Output '$marker' | Out-Null`""
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argStr `
                      -WindowStyle Hidden -Wait -ErrorAction Stop
    }
    catch {
        Write-Log "Failed to spawn PS 4104 test process: $($_.Exception.Message)" -Level WARN
        return $false
    }

    Start-Sleep -Seconds 10

    try {
        $events = Get-WinEvent -FilterHashtable @{
            LogName='Microsoft-Windows-PowerShell/Operational'; Id=4104; StartTime=$before
        } -MaxEvents 200 -ErrorAction SilentlyContinue

        if (-not $events) { return $false }
        return ($null -ne ($events | Where-Object { $_.Message -match [regex]::Escape($marker) } | Select-Object -First 1))
    }
    catch {
        Write-Log "4104 live test exception: $($_.Exception.Message)" -Level WARN
        return $false
    }
}

# ---------------------------------------------------------------------------
#  PHASES 1-4
# ---------------------------------------------------------------------------
function Invoke-PreFlight {
    Write-Log 'PHASE 1 - Pre-Flight Checks' -Level HEAD

    $os = Get-CimInstance Win32_OperatingSystem
    Write-Log " OS    : $($os.Caption)"
    Write-Log " Build : $($os.BuildNumber)"
    Write-Log " Host  : $env:COMPUTERNAME"
    Write-Log " User  : $env:USERNAME"

    if ($os.Caption -notmatch '2025') {
        Write-Log "WARNING: Script optimized for Server 2025 - detected: $($os.Caption)" -Level WARN
    }

    if (Get-SmbShare -Name SYSVOL -ErrorAction SilentlyContinue) {
        Write-Log 'SYSVOL share -> OK (DC appears promoted)' -Level PASS
    }
    else {
        Write-Log 'SYSVOL share missing -> DC may not be fully promoted' -Level WARN
    }

    $cs = Get-CimInstance Win32_ComputerSystem
    if ($cs.DomainRole -in 4,5) {
        $script:IsDC = $true
        Write-Log 'Detected Domain Controller - local audit changes may be overridden by GPO.' -Level WARN
        Write-Log 'For persistent changes, configure Advanced Audit Policies via gpmc.msc.' -Level WARN
    }

    if (-not (Test-Path "$env:SystemRoot\System32\auditpol.exe")) {
        Write-Log 'auditpol.exe NOT FOUND -> cannot continue' -Level FAIL
        exit 1
    }
    Write-Log 'auditpol.exe found -> OK' -Level PASS

    if ($WhatIf) { Write-Log 'MODE: DRY-RUN (WhatIf) - no changes will be made' -Level WARN }
}

function Set-AuditPolicies {
    Write-Log 'PHASE 2 - Configuring Advanced Audit Policies' -Level HEAD

    if ($WhatIf) {
        Write-Log '[WHATIF] Would set SCENoApplyLegacyAuditPolicy=1' -Level WARN
    }
    else {
        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
                         -Name 'SCENoApplyLegacyAuditPolicy' -Value 1 -Type DWord -Force -ErrorAction Stop
        Write-Log 'SCENoApplyLegacyAuditPolicy = 1 (enforce advanced audit)' -Level PASS
    }

    foreach ($p in Get-AuditPolicyTargets) {
        $ok = Set-AuditSubcategory -SubCategory $p.Sub -Success $p.S -Failure $p.F
        Write-Log "[SET] $($p.Sub) -> $(if ($ok) {'OK'} else {'FAILED'})" -Level $(if ($ok) {'PASS'} else {'FAIL'})
    }
}

function Set-RegistryLogging {
    Write-Log 'PHASE 2B - Registry-Based Enhanced Logging' -Level HEAD
    if ($WhatIf) { Write-Log '[WHATIF] Would configure registry logging keys' -Level WARN; return }

    $auditPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
    if (-not (Test-Path $auditPath)) { New-Item -Path $auditPath -Force | Out-Null }
    Set-ItemProperty -Path $auditPath -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force
    Write-Log 'ProcessCreationIncludeCmdLine_Enabled = 1 -> OK' -Level PASS

    $sbPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    if (-not (Test-Path $sbPath)) { New-Item -Path $sbPath -Force | Out-Null }
    Set-ItemProperty -Path $sbPath -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force
    Write-Log 'Script Block Logging enabled -> OK' -Level PASS

    $modPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
    if (-not (Test-Path $modPath)) { New-Item -Path $modPath -Force | Out-Null }
    Set-ItemProperty -Path $modPath -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force
    $modNames = Join-Path $modPath 'ModuleNames'
    if (-not (Test-Path $modNames)) { New-Item -Path $modNames -Force | Out-Null }
    Set-ItemProperty -Path $modNames -Name '*' -Value '*' -Type String -Force
    Write-Log 'Module Logging enabled (all modules) -> OK' -Level PASS

    $transPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'
    if (-not (Test-Path $transPath)) { New-Item -Path $transPath -Force | Out-Null }
    Set-ItemProperty -Path $transPath -Name 'EnableTranscripting'    -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $transPath -Name 'EnableInvocationHeader' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $transPath -Name 'OutputDirectory'        -Value "$env:SystemDrive\PSTranscripts" -Type String -Force

    $transDir = "$env:SystemDrive\PSTranscripts"
    if (-not (Test-Path $transDir)) { New-Item -Path $transDir -ItemType Directory -Force | Out-Null }
    Write-Log 'PowerShell Transcription -> OK' -Level PASS
}

function Set-EventLogSizes {
    Write-Log 'PHASE 3 - Event Log Maximum Sizes' -Level HEAD
    if ($WhatIf) { Write-Log '[WHATIF] Security=1GB, System/DS=512MB' -Level WARN; return }

    $logs = @(
        @{ Name='Security';          MB=1024 }
        @{ Name='System';            MB=512  }
        @{ Name='Directory Service'; MB=512  }
    )

    foreach ($l in $logs) {
        try {
            # FIX: Pre-compute size to avoid wevtutil argument split bug
            $sizeBytes = [long]$l.MB * 1MB
            & wevtutil.exe sl $l.Name "/ms:$sizeBytes" "/rt:false" 2>&1 | Out-Null
            Write-Log "$($l.Name) log -> $($l.MB) MB - OK" -Level PASS
        }
        catch {
            Write-Log "$($l.Name) log resize failed: $($_.Exception.Message)" -Level FAIL
        }
    }
}

function Invoke-GPUpdate {
    Write-Log 'PHASE 4 - gpupdate /force' -Level HEAD
    if ($WhatIf) { Write-Log '[WHATIF] Would run gpupdate /force' -Level WARN; return }

    try {
        $out  = & gpupdate.exe /force 2>&1
        $last = ($out | Select-Object -Last 1)
        Write-Log "gpupdate -> $(if ($last) {($last -replace '\s+',' ').Trim()} else {'completed'})" -Level INFO
        Start-Sleep -Seconds 6
    }
    catch { Write-Log "gpupdate failed: $($_.Exception.Message)" -Level WARN }
}

# ---------------------------------------------------------------------------
#  PHASE 5 - VALIDATION
# ---------------------------------------------------------------------------
function Invoke-Validation {
    Write-Log 'PHASE 5 - Validation' -Level HEAD

    foreach ($c in Get-AuditPolicyTargets) {
        $ok     = Test-AuditPolSetting -Sub $c.Sub -NeedSuccess $c.S -NeedFailure $c.F
        $status = if ($ok) {'PASS'} else {'FAIL'}
        Write-Log "$($c.Sub) -> $status" -Level $status
        Add-Result -Control $c.Sub -Status $status -Category 'auditpol'
    }

    $regChecks = @(
        @{ Label='CmdLine in 4688 (reg)'; Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit';             Name='ProcessCreationIncludeCmdLine_Enabled'; Category='registry' }
        @{ Label='Script Block Logging';  Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging';           Name='EnableScriptBlockLogging';             Category='registry' }
        @{ Label='Module Logging';        Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging';                Name='EnableModuleLogging';                  Category='registry' }
    )
    foreach ($r in $regChecks) {
        $ok     = Test-RegDWord -Path $r.Path -Name $r.Name
        $status = if ($ok) {'PASS'} else {'FAIL'}
        Write-Log "$($r.Label) -> $status" -Level $status
        Add-Result -Control $r.Label -Status $status -Category $r.Category
    }

    foreach ($log in @('Security','Directory Service')) {
        try {
            $li  = Get-WinEvent -ListLog $log -ErrorAction Stop
            $mb  = [math]::Round($li.MaximumSizeInBytes / 1MB, 0)
            $min = if ($log -eq 'Security') {1024} else {512}
            $ok  = $mb -ge $min
            $status = if ($ok) {'PASS'} else {'FAIL'}
            Write-Log "$log log = $mb MB (want >= $min) -> $status" -Level $status
            Add-Result -Control "$log Log Size" -Status $status -Detail "${mb}MB" -Category 'logsize'
        }
        catch {
            Write-Log "$log log -> cannot read size" -Level FAIL
            Add-Result -Control "$log Log Size" -Status 'FAIL' -Category 'logsize'
        }
    }

    Write-Log 'Running live 4688 (process creation + cmdline) test...' -Level HEAD
    $r4688 = Test-LiveEvent4688
    if ($r4688.Found -and $r4688.HasCmdLine) {
        Write-Log 'LIVE 4688 + command line -> PASS' -Level PASS
        Add-Result -Control 'LIVE 4688 + CmdLine' -Status 'PASS' -Category 'live'
    }
    elseif ($r4688.Found) {
        Write-Log 'LIVE 4688 found but NO command line -> FAIL' -Level FAIL
        Add-Result -Control 'LIVE 4688 + CmdLine' -Status 'FAIL' -Detail 'CmdLine empty - may need reboot' -Category 'live'
    }
    else {
        Write-Log 'No 4688 event captured -> FAIL' -Level FAIL
        Add-Result -Control 'LIVE 4688 + CmdLine' -Status 'FAIL' -Detail 'No event - Process Creation audit not active' -Category 'live'
    }

    Write-Log 'Running live PowerShell 4104 (script block) test...' -Level HEAD
    $ok4104     = Test-LivePS4104
    $status4104 = if ($ok4104) {'PASS'} else {'FAIL'}
    Write-Log "LIVE 4104 Script Block -> $status4104" -Level $status4104
    Add-Result -Control 'LIVE PS ScriptBlock 4104' -Status $status4104 `
               -Detail $(if (-not $ok4104) {'May need reboot or GPO refresh'} else {''}) -Category 'live'
}

# ---------------------------------------------------------------------------
#  NEW v2.6 - PASSED CONTROLS DASHBOARD WITH AUDITPOL LIVE VERIFICATION
# ---------------------------------------------------------------------------
function Write-SuccessDashboard {
    Write-Separator '=' 70
    Write-Log 'PASSED CONTROLS - LIVE AUDITPOL VERIFICATION' -Level HEAD
    Write-Separator '=' 70

    $passedAuditpol = $script:Results | Where-Object { $_.Status -eq 'PASS' -and $_.Category -eq 'auditpol' }
    $passedRegistry = $script:Results | Where-Object { $_.Status -eq 'PASS' -and $_.Category -eq 'registry' }
    $passedLogSize  = $script:Results | Where-Object { $_.Status -eq 'PASS' -and $_.Category -eq 'logsize'  }
    $passedLive     = $script:Results | Where-Object { $_.Status -eq 'PASS' -and $_.Category -eq 'live'     }
    $failed         = $script:Results | Where-Object { $_.Status -eq 'FAIL' }

    # ---- SECTION 1: Audit Subcategories (live auditpol read) ---------------
    if ($passedAuditpol) {
        Write-Log 'AUDIT SUBCATEGORIES (verified via auditpol /get /r)' -Level HEAD
        Write-Separator '-' 70

        # Column widths
        $colW1 = 42
        $colW2 = 26

        $header = ('  {0,-42} {1,-26}' -f 'Subcategory', 'Inclusion Setting (auditpol)')
        Write-Host $header -ForegroundColor Cyan
        Add-Content -Path $script:LogFile -Value $header -Encoding UTF8

        $divider = '  ' + ('-' * 42) + ' ' + ('-' * 26)
        Write-Host $divider -ForegroundColor DarkCyan
        Add-Content -Path $script:LogFile -Value $divider -Encoding UTF8

        foreach ($r in $passedAuditpol) {
            $liveSetting = Get-AuditPolInclusionSetting -Sub $r.Control
            $row = ('  {0,-42} {1,-26}' -f $r.Control, $liveSetting)
            Write-Host $row -ForegroundColor Green
            Add-Content -Path $script:LogFile -Value "[PASS-AUDIT] $row" -Encoding UTF8
        }
        Write-Separator '-' 70
    }

    # ---- SECTION 2: Registry Controls --------------------------------------
    if ($passedRegistry) {
        Write-Log 'REGISTRY LOGGING CONTROLS' -Level HEAD
        Write-Separator '-' 70

        $regDetails = @{
            'CmdLine in 4688 (reg)' = @{
                Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
                Name = 'ProcessCreationIncludeCmdLine_Enabled'
                Desc = 'Command line in 4688 events'
            }
            'Script Block Logging' = @{
                Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
                Name = 'EnableScriptBlockLogging'
                Desc = 'PS script block logging (Event 4104)'
            }
            'Module Logging' = @{
                Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
                Name = 'EnableModuleLogging'
                Desc = 'PS module logging'
            }
        }

        foreach ($r in $passedRegistry) {
            $info = $regDetails[$r.Control]
            if ($info) {
                try {
                    $liveVal = Get-ItemPropertyValue -Path $info.Path -Name $info.Name -ErrorAction Stop
                    $row = ('  {0,-35} RegValue={1}  ({2})' -f $r.Control, $liveVal, $info.Desc)
                    Write-Host $row -ForegroundColor Green
                    Add-Content -Path $script:LogFile -Value "[PASS-REG]   $row" -Encoding UTF8
                }
                catch {
                    $row = ('  {0,-35} (could not read live value)' -f $r.Control)
                    Write-Host $row -ForegroundColor Yellow
                    Add-Content -Path $script:LogFile -Value "[PASS-REG]   $row" -Encoding UTF8
                }
            }
        }
        Write-Separator '-' 70
    }

    # ---- SECTION 3: Event Log Sizes ----------------------------------------
    if ($passedLogSize) {
        Write-Log 'EVENT LOG SIZES (live read via Get-WinEvent)' -Level HEAD
        Write-Separator '-' 70

        foreach ($r in $passedLogSize) {
            $logName = $r.Control -replace ' Log Size',''
            try {
                $li  = Get-WinEvent -ListLog $logName -ErrorAction Stop
                $mb  = [math]::Round($li.MaximumSizeInBytes / 1MB, 0)
                $row = ('  {0,-30} MaxSize={1} MB' -f $r.Control, $mb)
                Write-Host $row -ForegroundColor Green
                Add-Content -Path $script:LogFile -Value "[PASS-LOG]   $row" -Encoding UTF8
            }
            catch {
                $row = ('  {0,-30} (could not read live size)' -f $r.Control)
                Write-Host $row -ForegroundColor Yellow
                Add-Content -Path $script:LogFile -Value "[PASS-LOG]   $row" -Encoding UTF8
            }
        }
        Write-Separator '-' 70
    }

    # ---- SECTION 4: Live Event Tests ----------------------------------------
    if ($passedLive) {
        Write-Log 'LIVE EVENT TESTS' -Level HEAD
        Write-Separator '-' 70

        $liveDesc = @{
            'LIVE 4688 + CmdLine'      = 'Process creation event + command line captured in Security log'
            'LIVE PS ScriptBlock 4104' = 'PowerShell script block logged in PS/Operational log'
        }

        foreach ($r in $passedLive) {
            $desc = $liveDesc[$r.Control]
            $row  = ('  {0,-30} {1}' -f $r.Control, $desc)
            Write-Host $row -ForegroundColor Green
            Add-Content -Path $script:LogFile -Value "[PASS-LIVE]  $row" -Encoding UTF8
        }
        Write-Separator '-' 70
    }

    # ---- SECTION 5: Failed Controls Summary --------------------------------
    if ($failed) {
        Write-Log 'FAILED CONTROLS' -Level FAIL
        Write-Separator '-' 70
        foreach ($r in $failed) {
            $detail = if ($r.Detail) { " | $($r.Detail)" } else { '' }
            $row = ('  {0,-42} {1}' -f $r.Control, "FAILED$detail")
            Write-Host $row -ForegroundColor Red
            Add-Content -Path $script:LogFile -Value "[FAIL]       $row" -Encoding UTF8
        }
        Write-Separator '-' 70
    }

    # ---- SECTION 6: Score --------------------------------------------------
    # FIX: @() forces array context so .Count is always valid under Set-StrictMode
    $pass  = @($script:Results | Where-Object { $_.Status -eq 'PASS' }).Count
    $fail  = @($script:Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $total = $script:Results.Count
    $pct   = if ($total -gt 0) { [math]::Round(($pass / $total) * 100, 1) } else { 0 }

    Write-Separator '=' 70
    $scoreLine = "  SCORE: $pass / $total PASSED  ($pct%)   |   FAILED: $fail   |   Fix attempts: $($script:FixCount)"
    Write-Host $scoreLine -ForegroundColor $(if ($fail -eq 0) {'Green'} else {'Yellow'})
    Add-Content -Path $script:LogFile -Value $scoreLine -Encoding UTF8
    Write-Separator '=' 70

    if ($fail -eq 0) {
        Write-Log 'ALL CONTROLS PASSED - DC audit/logging fully configured' -Level PASS
        Write-Log 'Events now firing: 4624 4625 4634 4662 4672 4688 4706 4719 5136 4104' -Level PASS
    }
    else {
        Write-Log 'REMAINING FAILURES - Action Required:' -Level FAIL
        Write-Log ' 1. DC GPO overrides local policy -> fix via gpmc.msc (Default Domain Controllers Policy)' -Level FAIL
        Write-Log ' 2. Verify: auditpol /get /category:*' -Level FAIL
        Write-Log ' 3. Enable: Force audit policy subcategory settings (Security Options in GPO)' -Level FAIL
        Write-Log ' 4. Live test failures -> reboot or wait 15-30 min after other fixes' -Level FAIL
        Write-Log ' 5. Confirm you are Domain Admin (not only local admin)' -Level FAIL
    }
    Write-Separator '=' 70
}

# ---------------------------------------------------------------------------
#  INTERACTIVE REMEDIATION
# ---------------------------------------------------------------------------
function Get-GPOPathForSubcategory {
    param([string]$Sub)
    $map = @{
        'Credential Validation'='Account Logon'; 'Kerberos Authentication Service'='Account Logon'
        'Kerberos Service Ticket Operations'='Account Logon'; 'Other Account Logon Events'='Account Logon'
        'User Account Management'='Account Management'; 'Computer Account Management'='Account Management'
        'Security Group Management'='Account Management'; 'Other Account Management Events'='Account Management'
        'Logon'='Logon/Logoff'; 'Logoff'='Logon/Logoff'; 'Account Lockout'='Logon/Logoff'; 'Special Logon'='Logon/Logoff'
        'Directory Service Access'='DS Access'; 'Directory Service Changes'='DS Access'; 'Directory Service Replication'='DS Access'; 'Detailed Directory Service Replication'='DS Access'
        'Sensitive Privilege Use'='Privilege Use'; 'Process Creation'='Detailed Tracking'
        'Audit Policy Change'='Policy Change'; 'Authentication Policy Change'='Policy Change'; 'Authorization Policy Change'='Policy Change'
        'Security State Change'='System'; 'Security System Extension'='System'; 'System Integrity'='System'
    }
    return $map[$Sub]
}

function Write-ManualInstructions {
    param(
        [Parameter(Mandatory)][string]$Control,
        [Parameter(Mandatory)][string]$Category
    )

    Write-Host ''
    Write-Separator '=' 60
    Write-Host "  MANUAL FIX: $Control" -ForegroundColor Yellow
    Write-Separator '=' 60

    switch ($Category) {
        'auditpol' {
            $gpoPath = Get-GPOPathForSubcategory -Sub $Control
            if ($script:IsDC) {
                Write-Host @"

  DC DETECTED - use GPO (local auditpol may be overridden).

  OPTION A  gpmc.msc (GUI - recommended):
  ------------------------------------------
  1. Open gpmc.msc
  2. Forest > Domains > [your domain] > Domain Controllers
  3. Right-click Default Domain Controllers Policy > Edit
  4. Navigate to:
       Computer Configuration > Policies > Windows Settings
       > Security Settings > Advanced Audit Policy Configuration
       > Audit Policies > $gpoPath
  5. Double-click: $Control
  6. Tick: Configure the following audit events
  7. Enable required Success / Failure checkboxes
  8. OK > close GPME
  9. Run in a new window: gpupdate /force
  10. Wait ~30 sec, then press D here to re-validate.

  OPTION B  PowerShell (only if GPO not blocking):
  ------------------------------------------
  auditpol /set /subcategory:"$Control" /success:enable /failure:enable
  auditpol /get /subcategory:"$Control"

"@ -ForegroundColor White
            }
            else {
                Write-Host @"

  Run in an elevated PowerShell window:
  ------------------------------------------
  auditpol /set /subcategory:"$Control" /success:enable /failure:enable
  auditpol /get /subcategory:"$Control"

"@ -ForegroundColor White
            }
        }

        'registry' {
            $regInfo = switch ($Control) {
                'CmdLine in 4688 (reg)' { @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name='ProcessCreationIncludeCmdLine_Enabled' } }
                'Script Block Logging'  { @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging' } }
                'Module Logging'        { @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name='EnableModuleLogging' } }
                default                 { @{ Path='(unknown)'; Name='(unknown)' } }
            }
            Write-Host @"

  Run in an elevated PowerShell window:
  ------------------------------------------
  if (-not (Test-Path '$($regInfo.Path)')) { New-Item -Path '$($regInfo.Path)' -Force }
  Set-ItemProperty -Path '$($regInfo.Path)' -Name '$($regInfo.Name)' -Value 1 -Type DWord -Force
  # Verify (expect: 1):
  Get-ItemPropertyValue -Path '$($regInfo.Path)' -Name '$($regInfo.Name)'

"@ -ForegroundColor White
        }

        'logsize' {
            $logName = $Control -replace ' Log Size',''
            $minMB   = if ($logName -eq 'Security') {1024} else {512}
            $minB    = [long]$minMB * 1MB
            Write-Host @"

  Run in an elevated CMD or PowerShell window:
  ------------------------------------------
  wevtutil sl "$logName" /ms:$minB /rt:false
  # Verify:
  wevtutil gl "$logName" | findstr "maxSize"

"@ -ForegroundColor White
        }

        'live' {
            Write-Host @"

  Live test failures typically mean:
  ------------------------------------------
  A) Upstream audit policy not yet active -> fix auditpol/GPO controls first.
  B) Registry settings need a reboot to fully take effect.
  C) Re-run the script after all other controls pass.

  No manual registry steps required here.

"@ -ForegroundColor White
        }
    }
    Write-Separator '=' 60
    Write-Host ''
}

function Invoke-AutoFixControl {
    param([Parameter(Mandatory)][PSCustomObject]$ControlResult)
    $script:FixCount++

    if ($WhatIf) {
        Write-Log "[WHATIF] Would auto-fix: $($ControlResult.Control)" -Level WARN
        return $true
    }

    $target = Get-AuditTargetByName -Name $ControlResult.Control
    if ($null -ne $target) {
        return (Set-AuditSubcategory -SubCategory $target.Sub -Success $target.S -Failure $target.F)
    }

    switch ($ControlResult.Control) {
        'CmdLine in 4688 (reg)' {
            $p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
            Set-ItemProperty -Path $p -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord -Force
            return $true
        }
        'Script Block Logging' {
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
            Set-ItemProperty -Path $p -Name 'EnableScriptBlockLogging' -Value 1 -Type DWord -Force
            return $true
        }
        'Module Logging' {
            $p = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'
            if (-not (Test-Path $p)) { New-Item -Path $p -Force | Out-Null }
            Set-ItemProperty -Path $p -Name 'EnableModuleLogging' -Value 1 -Type DWord -Force
            return $true
        }
        'Security Log Size' {
            $sizeBytes = [long]1024 * 1MB
            & wevtutil.exe sl Security "/ms:$sizeBytes" "/rt:false" 2>&1 | Out-Null
            return $true
        }
        'Directory Service Log Size' {
            $sizeBytes = [long]512 * 1MB
            & wevtutil.exe sl 'Directory Service' "/ms:$sizeBytes" "/rt:false" 2>&1 | Out-Null
            return $true
        }
        default {
            Write-Log "No auto-fix handler for: $($ControlResult.Control)" -Level WARN
            return $false
        }
    }
}

function Invoke-SingleValidation {
    param([Parameter(Mandatory)][PSCustomObject]$ControlResult)

    switch ($ControlResult.Category) {
        'auditpol' {
            $t = Get-AuditTargetByName -Name $ControlResult.Control
            if (-not $t) { return $false }
            $ok = Test-AuditPolSetting -Sub $t.Sub -NeedSuccess $t.S -NeedFailure $t.F
            Add-Result -Control $ControlResult.Control -Status $(if ($ok) {'PASS'} else {'FAIL'}) -Category 'auditpol'
            return $ok
        }
        'registry' {
            $regMap = @{
                'CmdLine in 4688 (reg)' = @{ Path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; Name='ProcessCreationIncludeCmdLine_Enabled' }
                'Script Block Logging'  = @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Name='EnableScriptBlockLogging' }
                'Module Logging'        = @{ Path='HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Name='EnableModuleLogging' }
            }
            if (-not $regMap.ContainsKey($ControlResult.Control)) { return $false }
            $ok = Test-RegDWord -Path $regMap[$ControlResult.Control].Path -Name $regMap[$ControlResult.Control].Name
            Add-Result -Control $ControlResult.Control -Status $(if ($ok) {'PASS'} else {'FAIL'}) -Category 'registry'
            return $ok
        }
        'logsize' {
            $logName = $ControlResult.Control -replace ' Log Size',''
            $min     = if ($logName -eq 'Security') {1024} else {512}
            try {
                $li = Get-WinEvent -ListLog $logName -ErrorAction Stop
                $mb = [math]::Round($li.MaximumSizeInBytes / 1MB, 0)
                $ok = $mb -ge $min
                Add-Result -Control $ControlResult.Control -Status $(if ($ok) {'PASS'} else {'FAIL'}) -Detail "${mb}MB" -Category 'logsize'
                return $ok
            }
            catch { Add-Result -Control $ControlResult.Control -Status 'FAIL' -Category 'logsize'; return $false }
        }
        'live' {
            if ($ControlResult.Control -eq 'LIVE 4688 + CmdLine') {
                $r  = Test-LiveEvent4688
                $ok = $r.Found -and $r.HasCmdLine
                Add-Result -Control $ControlResult.Control -Status $(if ($ok) {'PASS'} else {'FAIL'}) -Category 'live'
                return $ok
            }
            elseif ($ControlResult.Control -eq 'LIVE PS ScriptBlock 4104') {
                $ok = Test-LivePS4104
                Add-Result -Control $ControlResult.Control -Status $(if ($ok) {'PASS'} else {'FAIL'}) -Category 'live'
                return $ok
            }
            return $false
        }
    }
    return $false
}

function Invoke-InteractiveRemediation {
    $failures = @($script:Results | Where-Object { $_.Status -eq 'FAIL' })

    if ($failures.Count -eq 0) {
        Write-Log 'No failures to remediate.' -Level PASS
        return
    }

    Write-Separator '=' 60
    Write-Log "FAILED CONTROLS SUMMARY ($($failures.Count) items)" -Level FAIL
    Write-Separator '=' 60

    $i = 1
    foreach ($f in $failures) {
        $detail = if ($f.Detail) { "  -> $($f.Detail)" } else { '' }
        Write-Host ("  [{0:D2}] [{1,-10}] {2}{3}" -f $i, $f.Category.ToUpper(), $f.Control, $detail) -ForegroundColor Red
        $i++
    }
    Write-Separator '=' 60
    Write-Host ''

    if ($NonInteractive) {
        Write-Log 'NonInteractive mode: attempting auto-fix on all failures...' -Level FIX
        foreach ($f in $failures) { Invoke-AutoFixControl -ControlResult $f | Out-Null }
        return
    }

    $idx = 0
    foreach ($f in $failures) {
        $idx++
        Write-Host ''
        Write-Separator '-' 60
        Write-Host ("  FAILURE $idx / $($failures.Count)  [{0}]  {1}" -f $f.Category.ToUpper(), $f.Control) -ForegroundColor Yellow
        if ($f.Detail) { Write-Host "  Detail : $($f.Detail)" -ForegroundColor DarkYellow }
        Write-Host ''

        if ($f.Category -eq 'auditpol' -and $script:IsDC) {
            Write-Host '  [!] DC: auditpol may be blocked by Default Domain Controllers Policy.' -ForegroundColor Magenta
            Write-Host '      Auto-fix will try locally. Manual (M) via gpmc.msc is more reliable.' -ForegroundColor Magenta
            Write-Host ''
        }

        Write-Host '  [A] Auto-fix   - script attempts fix automatically then re-validates' -ForegroundColor Green
        Write-Host '  [M] Manual     - step-by-step instructions, confirm when done'         -ForegroundColor Cyan
        Write-Host '  [S] Skip       - leave as-is, continue'                                -ForegroundColor DarkGray
        Write-Host ''

        $choice = ''
        while ($choice -notin @('A','M','S')) {
            $choice = (Read-Host '  Choice [A/M/S]').Trim().ToUpper()
        }

        switch ($choice) {
            'A' {
                Write-Log "Auto-fix: $($f.Control)" -Level FIX
                Invoke-AutoFixControl -ControlResult $f | Out-Null
                Write-Log "Re-validating: $($f.Control)" -Level INFO
                $ok = Invoke-SingleValidation -ControlResult $f

                if ($ok) {
                    Write-Log "$($f.Control) -> NOW PASSING" -Level PASS
                }
                else {
                    Write-Log "$($f.Control) -> Still failing after auto-fix" -Level FAIL
                    if ($script:IsDC -and $f.Category -eq 'auditpol') {
                        Write-Host '  [!] GPO override likely. Consider using Manual (M) option.' -ForegroundColor Magenta
                    }
                }
            }

            'M' {
                Write-ManualInstructions -Control $f.Control -Category $f.Category

                if ($f.Category -eq 'live') {
                    Write-Host '  Press ENTER to continue...' -ForegroundColor DarkGray
                    Read-Host | Out-Null
                }
                else {
                    $confirm = ''
                    while ($confirm -notin @('D','S')) {
                        $confirm = (Read-Host '  [D]one (re-validate) / [S]kip').Trim().ToUpper()
                    }

                    if ($confirm -eq 'D') {
                        if (-not $WhatIf) {
                            Write-Log 'Running gpupdate /force...' -Level INFO
                            & gpupdate.exe /force 2>&1 | Out-Null
                            Start-Sleep -Seconds 8
                        }
                        $ok = Invoke-SingleValidation -ControlResult $f
                        if ($ok) {
                            Write-Log "$($f.Control) -> CONFIRMED PASSING after manual fix" -Level PASS
                        }
                        else {
                            Write-Log "$($f.Control) -> Still failing" -Level FAIL
                            Write-Host '  Possible reasons:' -ForegroundColor Magenta
                            Write-Host '  - GPO not refreshed yet (wait 5-15 min or reboot)' -ForegroundColor Magenta
                            Write-Host '  - GPO setting not saved correctly (recheck gpmc.msc)' -ForegroundColor Magenta
                            Write-Host '  - Conflicting GPO blocking this subcategory' -ForegroundColor Magenta
                        }
                    }
                    else {
                        Write-Log "Skipped: $($f.Control)" -Level WARN
                    }
                }
            }

            'S' {
                Write-Log "Skipped: $($f.Control)" -Level WARN
            }
        }
    }
}

# ---------------------------------------------------------------------------
#  MAIN
# ---------------------------------------------------------------------------
try {
    Write-Log 'Windows Server 2025 DC Audit Policy Configurator v2.7 - Starting' -Level HEAD

    Invoke-PreFlight
    Set-AuditPolicies
    Set-RegistryLogging
    Set-EventLogSizes
    Invoke-GPUpdate
    Invoke-Validation
    Invoke-InteractiveRemediation

    # Final dashboard — always runs, shows passed controls with live auditpol reads
    Write-SuccessDashboard
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" -Level FAIL
    throw
}
finally {
    Stop-Transcript | Out-Null
}
