# Incident Response Lab – Atomic Red Team Setup

This lab installs Atomic Red Team on a Windows endpoint, validates the Atomic test library, and optionally runs a safe PowerShell-based test for telemetry and detection verification.

## Requirements

- Windows 10 / Windows Server
- PowerShell 5+
- Administrator PowerShell session
- Internet connection
- Sysmon installed for endpoint telemetry
- Wazuh agent installed if SIEM validation is required

## Installation

Run this in **PowerShell (Administrator)**:

```powershell
powershell -ExecutionPolicy Bypass -Command "IEX (IWR https://raw.githubusercontent.com/A-rjun-saji/security-engineering-roadmap/main/labs/ir-lab-setup/install-atomicredteam.ps1)"
