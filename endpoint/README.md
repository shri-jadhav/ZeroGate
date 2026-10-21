# ZeroGate Cloud — Endpoint Telemetry & FIM Guide

This directory contains endpoint telemetry assets for Windows endpoints integrated with the ZeroGate Cloud security architecture.

## 1. Components

- `sysmonconfig.xml`: Tailored Sysmon configuration capturing process creation (Event ID 1), outbound proxy/DNS network connections (Event ID 3), and file creations in confidential folders (Event ID 11).
- `agent.conf`: Centralized Wazuh Agent configuration managing File Integrity Monitoring (FIM) and Windows Event Channel collection.

---

## 2. Windows Sysmon Deployment

1. Download Sysmon from Microsoft Sysinternals:
   ```powershell
   # Administrator PowerShell
   Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
   Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "$env:TEMP\Sysmon"
   ```
2. Install Sysmon using the ZeroGate lab configuration:
   ```powershell
   & "$env:TEMP\Sysmon\Sysmon64.exe" -accepteula -i .\endpoint\sysmonconfig.xml
   ```
3. Verify Sysmon is active and logging:
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
   ```

---

## 3. Wazuh Agent File Integrity Monitoring (FIM)

The designated confidential test folder is:
`C:\Users\Admin\Documents\ZeroGate\data\confidential`

When a file is created, modified, or deleted within this directory, the Wazuh syscheck daemon captures the change in real time and raises:
- Rule 550 (Integrity checksum changed)
- Rule 554 (File added to the system)

### Verification:
```powershell
# Create test file
New-Item -Path "data\confidential\policy_doc.txt" -ItemType File -Value "Confidential Data"

# Verify FIM detection in Wazuh manager alerts.log
# Alerts appear under group: syscheck
```
