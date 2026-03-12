# Incident Response Lab – Atomic Red Team Setup

This lab installs Atomic Red Team on a Windows endpoint and runs a validation attack simulation.

## Requirements

- Windows 10 / Windows Server
- PowerShell 5+
- Administrator access
- Internet connection

## Installation

Run in **PowerShell (Administrator)**:

powershell -ExecutionPolicy Bypass -Command "IEX (IWR https://raw.githubusercontent.com/A-rjun-saji/security-engineering-roadmap/main/labs/ir-lab-setup/install-atomicredteam.ps1)"

## What the Script Does

1. Sets PowerShell execution policy
2. Installs required modules
3. Downloads Atomic Red Team
4. Installs atomic test library
5. Imports Invoke-AtomicRedTeam module
6. Lists PowerShell atomic tests
7. Executes validation test

## Validation Test

Technique used:

T1059.001 – PowerShell Command Execution

Expected output:

Hello, from PowerShell!
Exit code: 0

## Detection Validation

After execution verify:

• Sysmon Event ID 1  
• PowerShell logs  
• Wazuh alert detection
