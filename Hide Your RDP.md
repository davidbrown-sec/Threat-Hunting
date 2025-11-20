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
