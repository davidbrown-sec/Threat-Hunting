#  Unauthorized RDP Access Leads to Full Attack Chain

Analyst: David Brown  
Date Completed: 2025-09-18  
Environment Investigated: Cloud-Hosted Windows Server  
Timeframe: 2025-09-14

---

## Scenario  

Multiple failed RDP login attempts originating from an external IP were followed by a successful authentication using valid credentials. Once inside the system, the attacker executed a malicious binary, established persistence via scheduled tasks, modified Microsoft Defender settings to evade detection, conducted extensive host discovery, archived sensitive data, communicated with a command-and-control server, and attempted exfiltration.

Your mission is to reconstruct the timeline, analyze execution patterns, highlight attacker tradecraft, and map each activity to MITRE ATT&CK.

---

## Executive Summary

The attacker brute-forced RDP login access from external IP **159.26.106.84**, logging in as **slflare**.  
Immediately after gaining initial access, the actor executed **msupdate.exe** using a bypassed execution policy.  
Persistence was established via a scheduled task named **MicrosoftUpdateSync**, while defense evasion involved adding a Defender exclusion for **C:\Windows\Temp**.

Discovery commands (such as `systeminfo`) were executed to map the environment, followed by the creation of an archive file (**backup_sync.zip**) of collected data.  
C2 communication occurred with **185.92.220.87**, and data exfiltration was attempted via **185.92.220.87:8081**.

This attack chain reflects a classic post-credential compromise: execution → persistence → defense evasion → discovery → collection → exfiltration.

---

## Timeline of Adversary Activity

| Time (Approx.) | Flag | Action Observed | Key Evidence |
|----------------|------|-----------------|--------------|
| Initial Event | 1 | Successful RDP login after brute-force attempts | Source: `159.26.106.84` |
| + | 2 | Valid user account compromised | Account used: `slflare` |
| + | 3 | Malicious binary executed | File: `msupdate.exe` |
| + | 4 | Command used to execute binary | `"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1` |
| + | 5 | Persistence mechanism created | Scheduled Task: `MicrosoftUpdateSync` |
| + | 6 | Defender tampering performed | Folder exclusion: `C:\Windows\Temp` |
| + | 7 | System discovery initiated | `"cmd.exe" /c systeminfo` |
| + | 8 | Archive for exfil created | `backup_sync.zip` |
| + | 9 | C2 destination contacted | `185.92.220.87` |
| + | 10 | Exfiltration attempted | `185.92.220.87:8081` |

---

# Flag-by-Flag Findings

---

## 🚩 **Flag 1 – Attacker IP Address (Initial Access)**  
🎯 **Objective:** Identify the earliest external IP that successfully authenticated via RDP after multiple failures.  
📌 **Finding (answer):** **159.26.106.84**

🔍 **Evidence:**  
- Multiple RDP login failures followed by success  
- External IP sourced from authentication logs

**KQL Query Used:**

📸 *Screenshot Placeholder*

---

## 🚩 **Flag 2 – Compromised Account**  
🎯 **Objective:** Determine which user account was used for the successful RDP login.  
📌 **Finding (answer):** **slflare**

🔍 **Evidence:**  
- Successful authentication tied to attacker IP  
- Account associated with event

**KQL Query Used:**
📸 *Screenshot Placeholder*

---

## 🚩 **Flag 3 – Executed Binary Name**  
🎯 **Objective:** Identify the binary executed by the attacker post-RDP login.  
📌 **Finding (answer):** **msupdate.exe**

🔍 **Evidence:**  
- Binary executed from suspicious location  
- Process associated with compromised account

**KQL Query Used:**
📸 *Screenshot Placeholder*

---

## 🚩 **Flag 4 – Command Line Used to Execute Binary**  
🎯 **Objective:** Identify the exact command line used to execute the binary from Flag 3.  
📌 **Finding (answer):**  
**"msupdate.exe" -ExecutionPolicy Bypass -File C:\Users\Public\update_check.ps1**

🔍 **Evidence:**  
- PowerShell invoked with execution-policy bypass  
- Launch of attacker binary confirmed

**KQL Query Used:**

📸 *Screenshot Placeholder*

---

## 🚩 **Flag 5 – Persistence Mechanism Created**  
🎯 **Objective:** Identify the scheduled task established to maintain persistence.  
📌 **Finding (answer):** **MicrosoftUpdateSync**

🔍 **Evidence:**  
- `schtasks.exe` used with `/create` and `/onlogon`  
- Task persists across reboots/logins

**KQL Query Used:**
📸 *Screenshot Placeholder*

---

## 🚩 **Flag 6 – Modified Microsoft Defender Setting**  
🎯 **Objective:** Identify the folder path added to Defender exclusions.  
📌 **Finding (answer):** **C:\Windows\Temp**

🔍 **Evidence:**  
- Registry modification logs confirm exclusion  
- Used for hiding malicious staging activity

**KQL Query Used:**

📸 *Screenshot Placeholder*

---

## 🚩 **Flag 7 – Discovery Command Executed**  
🎯 **Objective:** Identify the earliest attacker discovery command.  
📌 **Finding (answer):**  
**"cmd.exe" /c systeminfo**

🔍 **Evidence:**  
- Basic OS discovery  
- Standard attacker system enumeration pattern

**KQL Query Used:**

📸 *Screenshot Placeholder*

---

## 🚩 **Flag 8 – Archive File Created**  
🎯 **Objective:** Identify the archive file created for data staging.  
📌 **Finding (answer):** **backup_sync.zip**

🔍 **Evidence:**  
- Archive appears in user-accessible location  
- Likely staging for exfiltration

**KQL Query Used:**

📸 *Screenshot Placeholder*

---

## 🚩 **Flag 9 – C2 Connection Destination**  
🎯 **Objective:** Identify the destination IP/domain contacted for C2.  
📌 **Finding (answer):** **185.92.220.87**

🔍 **Evidence:**  
- Outbound traffic to suspicious IP  
- Occurred shortly after malicious execution

**KQL Query Used:**

📸 *Screenshot Placeholder*

---

## 🚩 **Flag 10 – Exfiltration Attempt (IP:Port)**  
🎯 **Objective:** Identify the external IP address and port used for exfiltration.  
📌 **Finding (answer):** **185.92.220.87:8081**

🔍 **Evidence:**  
- Outbound transfer attempt  
- Matches attack patterns for unencrypted exfiltration

**KQL Query Used:**

📸 *Screenshot Placeholder*

---

# MITRE ATT&CK — Mapping Summary

### Initial Access
- **T1110.001 – Brute Force: Password Guessing**

### Execution
- **T1059.003 – Command and Scripting Interpreter: Windows Command Shell**  
- **T1204.002 – User Execution: Malicious File**

### Persistence
- **T1053.005 – Scheduled Task**

### Defense Evasion
- **T1562.001 – Impair Defenses: Disable/Modify Defender**

### Discovery
- **T1082 – System Information Discovery**

### Collection
- **T1560.001 – Archive Collected Data**

### Command & Control
- **T1071.001 – Application Layer Protocol (HTTP/S)**  
- **T1105 – Ingress Tool Transfer**

### Exfiltration
- **T1048.003 – Exfiltration Over Unencrypted Protocol**

---

# Recommended Actions

### 1. Containment  
- Revoke all active sessions tied to `slflare`  
- Isolate affected VM  

### 2. Credential Reset  
- Rotate credentials for compromised accounts  
- Enforce MFA

### 3. Persistence Removal  
- Delete scheduled task `MicrosoftUpdateSync`  
- Remove Defender exclusion for `C:\Windows\Temp`

### 4. Audit & Hunt  
- Search environment for `msupdate.exe` & similar binaries  
- Review outbound traffic to `185.92.220.87`  

### 5. Strengthen RDP Exposure  
- Restrict RDP to VPN-only access  
- Enable account lockout policies

---
