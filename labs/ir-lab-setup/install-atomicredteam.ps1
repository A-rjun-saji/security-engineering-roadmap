# Atomic Red Team - Clean Install / Repair Script for Windows
# Use in a lab only. Review before running.

[CmdletBinding()]
param(
    [string]$InstallRoot = "C:\AtomicRedTeam",
    [switch]$SkipCleanup,
    [switch]$RunSafeTest
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Write-Step {
    param([string]$Message)
    Write-Host "`n[+] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Test-IsAdmin {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Remove-PathSafe {
    param([string]$PathToRemove)

    if (Test-Path $PathToRemove) {
        Write-WarnMsg "Removing: $PathToRemove"
        Remove-Item $PathToRemove -Recurse -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
    }
}

function Get-RealAtomicYamlFiles {
    param([string]$AtomicsRoot)

    if (-not (Test-Path $AtomicsRoot)) {
        return @()
    }

    return Get-ChildItem $AtomicsRoot -Recurse -File -Include *.yaml, *.yml |
        Where-Object {
            $_.FullName -notmatch '\\Indexes\\' -and
            $_.DirectoryName -match '\\T\d'
        }
}

try {
    Write-Step "Checking elevation"
    if (-not (Test-IsAdmin)) {
        throw "This script must be run in PowerShell as Administrator."
    }
    Write-Ok "Administrator session confirmed"

    $modulePathUser = Join-Path $env:USERPROFILE "Documents\WindowsPowerShell\Modules"
    $invokeInstallerUrl = "https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1"
    $atomicsRoot = Join-Path $InstallRoot "atomics"
    $frameworkRoot = Join-Path $InstallRoot "invoke-atomicredteam"
    $moduleManifest = Join-Path $frameworkRoot "Invoke-AtomicRedTeam.psd1"
    $tempInstaller = Join-Path $env:TEMP "install-atomicredteam.ps1"

    if (-not $SkipCleanup) {
        Write-Step "Cleaning previous Atomic Red Team install"
        Remove-PathSafe -PathToRemove $InstallRoot

        $oldInvokeModule = Join-Path $modulePathUser "Invoke-AtomicRedTeam"
        Remove-PathSafe -PathToRemove $oldInvokeModule

        Write-Ok "Cleanup completed"
    }
    else {
        Write-WarnMsg "SkipCleanup set. Existing files will be reused where possible."
    }

    Write-Step "Checking PowerShell execution policy"
    try {
        $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
        Write-Ok "Current user execution policy: $currentPolicy"
    }
    catch {
        Write-WarnMsg "Could not read execution policy. Continuing."
        Write-WarnMsg $_.Exception.Message
    }

    Write-Step "Installing required PowerShell modules"
    Install-Module -Name powershell-yaml -Scope CurrentUser -Force -AllowClobber
    Install-Module -Name invoke-atomicredteam -Scope CurrentUser -Force -AllowClobber
    Write-Ok "Required modules installed"

    Write-Step "Downloading official Atomic Red Team installer"
    Invoke-WebRequest -Uri $invokeInstallerUrl -OutFile $tempInstaller -UseBasicParsing
    if (-not (Test-Path $tempInstaller)) {
        throw "Failed to download installer script."
    }
    Write-Ok "Installer downloaded: $tempInstaller"

    Write-Step "Running clean install of framework and atomics"
    . $tempInstaller
    Install-AtomicRedTeam -InstallPath $InstallRoot -getAtomics -Force
    Write-Ok "Install-AtomicRedTeam completed"

    Write-Step "Verifying install paths"
    if (-not (Test-Path $frameworkRoot)) {
        throw "Framework path missing: $frameworkRoot"
    }
    if (-not (Test-Path $atomicsRoot)) {
        throw "Atomics path missing: $atomicsRoot"
    }
    if (-not (Test-Path $moduleManifest)) {
        throw "Module manifest missing: $moduleManifest"
    }
    Write-Ok "Framework, atomics, and module manifest are present"

    Write-Step "Importing Invoke-AtomicRedTeam module"
    Import-Module $moduleManifest -Force
    Write-Ok "Module imported successfully"

    Write-Step "Validating atomic YAML files"
    $yamlFiles = Get-RealAtomicYamlFiles -AtomicsRoot $atomicsRoot

    if (-not $yamlFiles -or $yamlFiles.Count -eq 0) {
        throw "No valid atomic YAML files found under $atomicsRoot. This usually means download/extraction failed or AV interfered."
    }

    Write-Ok ("Found {0} valid atomic YAML files" -f $yamlFiles.Count)

    Write-Step "Parsing a sample atomic YAML safely"
    $sampleYaml = $yamlFiles | Select-Object -First 1
    $technique = Get-AtomicTechnique -Path $sampleYaml.FullName
    if (-not $technique) {
        throw "Get-AtomicTechnique returned no result for sample file: $($sampleYaml.FullName)"
    }
    Write-Ok ("Parsed sample technique from: {0}" -f $sampleYaml.FullName)

    Write-Step "Quick visibility checks"
    Write-Host "`nInstall Root   : $InstallRoot"
    Write-Host "Framework Root : $frameworkRoot"
    Write-Host "Atomics Root   : $atomicsRoot"
    Write-Host "Sample YAML    : $($sampleYaml.FullName)"

    Write-Step "Listing a few valid atomic YAML files"
    $yamlFiles | Select-Object -First 10 -ExpandProperty FullName | ForEach-Object {
        Write-Host " - $_"
    }

    Write-Step "Showing details for a safe example technique"
    try {
        Invoke-AtomicTest T1059.001 -ShowDetailsBrief
        Write-Ok "Technique detail lookup for T1059.001 succeeded"
    }
    catch {
        Write-WarnMsg "T1059.001 detail lookup failed. This does not necessarily mean install failed."
        Write-WarnMsg $_.Exception.Message
    }

    if ($RunSafeTest) {
        Write-Step "Running one safe Atomic test example: T1059.001 test 17"
        Write-WarnMsg "This will generate activity on the endpoint and may trigger AV/EDR/Wazuh alerts."
        Invoke-AtomicTest T1059.001 -TestNumbers 17
        Write-Ok "Safe test execution completed"
    }
    else {
        Write-WarnMsg "Safe test execution skipped. Re-run with -RunSafeTest to execute one example test."
    }

    Write-Step "Final result"
    Write-Ok "Atomic Red Team clean install and validation completed successfully"
}
catch {
    Write-Fail $_.Exception.Message

    Write-Host "`n--- Likely Causes / Fixes ---" -ForegroundColor Yellow
    Write-Host "1. Antivirus / Defender blocked extraction or quarantined files."
    Write-Host "2. Old partial install caused path conflicts."
    Write-Host "3. Network/download issue interrupted GitHub fetch."
    Write-Host "4. Running non-atomic index YAML files through Get-AtomicTechnique."
    Write-Host "5. Execution policy modification blocked by security policy."
    Write-Host "6. Safe validation test should use T1059.001-17, not AutoIt-based T1059-1."

    Write-Host "`n--- Fast Checks ---" -ForegroundColor Yellow
    Write-Host "Test-Path `"$InstallRoot\atomics`""
    Write-Host "Test-Path `"$InstallRoot\invoke-atomicredteam`""
    Write-Host "Get-ChildItem `"$InstallRoot\atomics`" -Recurse -File -Include *.yaml,*.yml | Select-Object -First 20 FullName"

    exit 1
}
