#  Threat Hunt Report: Assistance 

Analyst: David Brown

Date Completed: 2025-11-11

Environment Investigated: gab-intrn-vm

Timeframe: Oct-9-2025

## Executive Summary

On the workstation gab-intern-vm, during the period of October 1–15, 2025, multiple downloaded “support” executables were executed from user folders, followed by outbound PowerShell commands used to fetch additional tools  ￼. The actor then performed reconnaissance — enumerating processes, services, user sessions, clipboard data, and testing outbound network connectivity. A scheduled task was created to maintain persistence beyond the active session. Finally, a user-facing file was left behind to justify the activity, serving as a planted explanation to reduce suspicion.


## Timeline of Adversary Activity (gab-intern-vm)

| **Time (UTC)**           | **Flag** | **Action Observed**                          | **Key Evidence**                                        |
| ------------------------ | -------- | -------------------------------------------- | ------------------------------------------------------- |
| **2025-10-01T07:12:03Z** | Flag 1   | Initial tool delivery to Downloads folder    | Executables with “help/support/desk”                    |
| **2025-10-01T07:18:45Z** | Flag 2   | Download via PowerShell / web utilities      | `Invoke-WebRequest` / `curl` observed pulling remote content. |
| **2025-10-01T07:20:12Z** | Flag 3   | Execution of downloaded “support” binary     | Launched from Downloads, initiated by `explorer.exe`. |
| **2025-10-02T02:33:27Z** | Flag 4   | System reconnaissance (process/service scan) | Commands including `tasklist`, `wmic`, `sc`, `Get-Process`. |
| **2025-10-03T11:05:09Z** | Flag 5   | User/session enumeration                     | `qwinsta`, `query session`, `quser`. |
| **2025-10-04T09:42:50Z** | Flag 6   | Clipboard probing                             | PowerShell clipboard access (`Get-Clipboard`). |
| **2025-10-05T13:17:34Z** | Flag 7   | Repeated broad enumeration sweep              | Multiple repeated `tasklist` / `Get-Process` executions. |
| **2025-10-06T16:29:01Z** | Flag 8   | Environment mapping across other machines     | Similar executables/naming conventions on multiple endpoints. |
| **2025-10-09T12:52:14Z** | Flag 9   | Outbound network tests begin                  | PowerShell egress activity (DNS + HTTP). |
| **2025-10-09T12:52:30Z** | Flag 10  | Continuous DNS/HTTP outbound activity         | `DeviceNetworkEvents` to remote IP/URL. |
| **2025-10-09T12:53:05Z** | Flag 11  | File creation/modification during staging     | `FileCreated`, `FileRenamed`, `FileCopied`. |
| **2025-10-10T04:01:18Z** | Flag 12  | Persistence created                           | Scheduled task using `/create` + `onlogon`. |
| **2025-10-10T04:05:02Z** | Flag 13  | Narrative / cover artifact dropped            | File intended to justify activity (readme/report). |
| **2025-10-11T08:22:47Z** | Flag 14  | Proliferation of temp/log/readme artifacts    | Matches `(temp|readme|log|cover|report)` pattern across file events. |
| **2025-10-12T15:40:12Z** | Flag 15  | Exfil-staged CSV discovered                   | `2786_CompanyFinancials_pwncrypt.csv`. |




---
### Starting Point – Identifying the Initial System

**Objective:**
Determine where to begin hunting based on provided indicators such as HR related stuffs or tools were recently touched...over the mid-july weekends.

**Host of Interest (Starting Point):** 
`gab-intrn-vm`  

**Why:** 
1. Multiple machines in the department started spawning processes originating from the download folders. This unexpected scenario occurred during the first half of October. 
2. Several machines were found to share the same types of files — similar executables, naming patterns, and other traits.
3. Common keywords among the discovered files included “desk,” “help,” “support,” and “tool.”
4. Intern operated machines seem to be affected to certain degree.

**KQL Query Used:**
```
let hits = DeviceFileEvents
| where FileName has_any ("desk","help","support","tool")   // or use explicit filename
| where TimeGenerated  between (datetime(2025-10-01) .. datetime(2025-10-15))
| summarize TotalOccurrences = count() by DeviceName;
hits
| order by TotalOccurrences desc
| serialize
| extend Rank = row_number()
| project Rank, DeviceName, TotalOccurrences
```
<img width="428" height="258" alt="Screenshot 2025-08-17 213533" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/20fae68f6c29e0431c6d6ed4e865786fc32bbd02/screen%20captures/pre-flag.png" />


---

## Flag-by-Flag Findings

---

🚩 **Flag 1 – Initial Execution Detection**  
🎯 **Objective:** Detect the earliest anomalous execution that could represent an entry point.  
📌 **Finding (answer):** -ExecutionPolicy
🔍 **Evidence:**  
- **Host:** gab-intrn-vm  
- **Timestamp:** 2025-10-06T12:13:22.4483418Z
- **Process:** powershell.exe  
- **CommandLine:** `powershell -ExecutionPolicy Unrestricted -File script0.ps1`  
- **SHA256:** `badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0`  
  **Why it matters:** Pinpointing the first unusual execution helps you anchor the timeline and follow the actor’s parent/child process chain.
  
**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated  between(datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine contains "Invoke-WebRequest"
    or ProcessCommandLine contains "curl"
    or ProcessCommandLine contains "bitsadmin"
    or ProcessCommandLine contains "wget"
| project TimeGenerated, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,SHA256
| order by TimeGenerated asc
```
<img width="528" height="313" alt="Screenshot 2025-08-17 213848" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/a3d9648024f39de2b6b0294cdc9ed3fc68ab2c79/screen%20captures/Assistance-F1.png"/>


---

🚩 **Flag 2 – Defense Disabling**  
🎯 **Objective:** Find a file that was manually accessed and implies tampering with security settings.  
📌 **Finding (answer):** `DefenderTamperArtifact.lnk`  
🔍 **Evidence:**  
- **Host:** gab-intrn-vm 
- **Timestamp:** 2025-10-09T12:34:59.1260624Z 
- **Process:** explorer.exe
- **Filename** DefenderTamperArtifact.lnk
- **SHA256:** `3ec18510105244255bf8e3c4790ca2ff8fe3433bd433f9b0c7bd130868a38662`  
💡 **Why it matters:** `Reveals tamper intent — attacker tries to simulate or spoof a change in security posture.`

**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01 06:00:00) .. datetime(2025-10-10 12:30:00))
| where InitiatingProcessFileName has_cs "explorer.exe"
| project TimeGenerated, InitiatingProcessFileName, FileName, FolderPath, ActionType
| order by TimeGenerated asc
```
<img width="824" height="264" alt="Screenshot 2025-08-17 215913" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/42ebc4f43667337c1214030f877b197eece1fbf8/screen%20captures/Assistance-F2.png" />

---

🚩 **Flag 3 – Quick Data Probe**  
🎯 **Objective:** Spot brief, opportunistic checks for readily avialable sensitive content.  
📌 **Finding (answer):** `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }`  
🔍 **Evidence:**  
- **Host:** gab-intrn-vm   
- **Timestamp:** 2025-10-09T12:50:39.955931Z 
- **Process:** powershell.exe  
- **CommandLine:** `"powershell.exe" -NoProfile -Sta -Command "try { Get-Clipboard | Out-Null } catch { }"  
- **SHA256:** `9785001b0dcf755eddb8af294a373c0b87b2498660f724e76c4d53f9c217c7a3`  
💡 **Why it matters:** Attackers look for low-effort wins first; these quick probes often procede broader reconnaissance.

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01 06:00:00) .. datetime(2025-10-10 12:30:00))
| where tolower(ProcessCommandLine) has_any ("clipboard","get-clipboard","set-clipboard","system.windows.forms.clipboard","clipboard::gettext","clipboard::settext")
| project TimeGenerated, FileName, InitiatingProcessFileName, ProcessCommandLine,SHA256
| order by TimeGenerated asc
```
<img width="867" height="343" alt="Screenshot 2025-08-17 215559" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/240660d57ce66c4d31a346d3c4534154ad9967a8/screen%20captures/Assistance-F3.png" />


---

🚩 **Flag 4 – Host Context Recon**  
🎯 **Objective:** Find activity that gathers basic host and user context to inform follow-up actions..  
📌 **Finding (answer):** `qwinsta.exe`  
🔍 **Evidence:**  
- **Host:** gab-intrn-vm 
- **Timestamp:** ~2025-10-09T12:51:44.3425653Z 
- **Process:** `"powershell.exe"  → spawned **"cmd.exe" /c qwinsta → "qwinsta.exe"
- 💡 **Why it matters:** Context-gathering shapes attacker decisions - who, what, and where to target

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where ProcessCommandLine has_any ("qwinsta")
| project TimeGenerated, FileName, InitiatingProcessCommandLine, ProcessCommandLine,SHA256
| order by TimeGenerated asc
```
<img width="729" height="610" alt="Screenshot 2025-08-17 214913" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/c6ad8e1098afbedc54ba857ef3ecdb61fc5a62e4/screen%20captures/Assistance-F4.png" />

---

🚩 **Flag 5 – Storage Surface Mapping**  
🎯 **Objective:** Detect discovery of local or network storage locations that might hold interesting data.  
📌 **Finding (answer):** `
🔍 **Evidence:**  
- **Host:** gab-intrn-vm 
- **Timestamps:** 2025-10-09T12:51:18.5628399Z  
- **Process:** powershell.exe → cmd.exe 
- **CommandLine:** `wmic logicaldisk get name,freespace,size`  
- **SHA256:** `da603fa720ab43aa6d4d36aa9fdb828dab9645523eabaac209af6451d5b4d757`  
💡 **Why it matters:** Mapping where data lives is a preparatory step for collection and staging.

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-06) .. datetime(2025-10-10))
| where FileName in~ ("Wmic.exe","netstat.exe","powershell.exe","cmd.exe","wmic.exe")
    or ProcessCommandLine has_any ("size","disk", "wmic")
| project TimeGenerated,FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine,SHA256
| order by TimeGenerated desc
| take 200
```
<img width="797" height="613" alt="Screenshot 2025-08-17 220314" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/1843006f10dd06665b82ddf56ae8dc5d7b029833/screen%20captures/Assistance-F5.png" />

---

🚩 **Flag 6 – Connectivity & Name resolution Check**  
🎯 **Objective:** Identify checks that validate network reachability and name resolution.  
📌 **Finding (answer):** RuntimeBroker.exe
🔍 **Evidence:**  
- **Host:** gab-intrn-vm  
- **Timestamp:** 2025-10-09T12:51:44.3081129Z
- **InitiatingProcessParentFileName** RuntimeBroker.exe
- **SHA256:** `badf4752413cb0cbdc03fb95820ca167f0cdc63b597ccdb5ef43111180e088b0`
  **Why it matters:** Confirming egress is a necessary precondition before any attempt to move data off-host.

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where tolower(ProcessCommandLine) contains "session" 
   or tolower(ProcessCommandLine) contains "qwinsta"
   or tolower(ProcessCommandLine) contains "quser"
   or tolower(ProcessCommandLine) contains "query session"
| project TimeGenerated, InitiatingProcessParentFileName, InitiatingProcessFileName, ProcessCommandLine,SHA256
| order by TimeGenerated desc
```
<img width="868" height="792" alt="Screenshot 2025-08-17 220703" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/05009310acf44e522fd81bda8cf0657da5a138c1/screen%20captures/Assistance-F6.png" />

---

🚩 **Flag 7 –   **  
🎯 **Objective:**  
📌 **Finding (answer):** 
🔍 **Evidence:**  
- **Host:** gab-intrn-vm  
- **Timestamps:**  
- **Process:** 
- **CommandLines:**  

- **Initiating:** powershell.exe  
- **SHA256:**
💡 **Why it matters:**

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where tolower(ProcessCommandLine) contains "session" 
   or tolower(ProcessCommandLine) contains "qwinsta"
   or tolower(ProcessCommandLine) contains "quser"
   or tolower(ProcessCommandLine) contains "query session"
| project TimeGenerated, InitiatingProcessUniqueId,FileName, InitiatingProcessFileName, ProcessCommandLine,SHA256
| order by TimeGenerated desc

```
<img width="879" height="567" alt="Screenshot 2025-08-17 221121" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/772745a01428edf05265a55d7bd2a0fd51ef494d/screen%20captures/Assistance-F7.png" />

---

🚩 **Flag 8 – Runtime Application Inventory**  
🎯 **Objective:** Detect enumeration of running applications and services to inform risk and opportunity.  
📌 **Finding (answer):** `tasklist.exe`  
🔍 **Evidence:**  
- **Host:** gab-intrn-vm   
- **Timestamp:**  2025-10-09T12:51:57.6866149Z 
- **Process:**   tasklist /v
- **SHA256:** be7241a74fe9a9d30e0631e41533a362b21c8f7aae3e5b6ad319cc15c024ec3f
  
  **Why it matters:** A process inventory shows what's present and what to avoid or target for collection.

**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "HRConfig.json"
| project Timestamp, DeviceId, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="760" height="268" alt="Screenshot 2025-08-17 221257" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/7c29fcc436e67762e2eecfb6f33b660f95e3fdbe/screen%20captures/Assistance-F8.png" />

---

🚩 **Flag 9 – Privilege Surface Check**  
🎯 **Objective:** Detect attempts to understand privileges available to the current actor.

📌 **Finding** (answer):**2025-10-09T12:52:14.3135459Z

🔍 **Evidence:**  
- **Host:** gab-intrn-vm
- **Timestamp:**  2025-10-09T12:52:14.3135459Z

 **Why it matters:** Privilege mapping informs whether the actor proceeds as a user or seeks elevation.

**KQL Query Used:**
```
DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated between (datetime(2025-10-06) .. datetime(2025-10-10))
| where FileName in~ ("tasklist.exe","wmic.exe","netstat.exe","sc.exe","powershell.exe","pwsh.exe","cmd.exe","cscript.exe","wmic.exe")
    or ProcessCommandLine has_any ("tasklist","/svc","/fo list","/v","process list","Get-Process","Get-Service","Get-WmiObject","Get-CimInstance","gwmi","gps","sc query","pslist","psinfo","procexp","handle.exe","listdlls","procmon")
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
| take 200
```
<img width="498" height="575" alt="Screenshot 2025-08-17 221558" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/6c3284e679e9a394a427924647763174e0533150/screen%20captures/Assistance-F9.png" />

---

🚩 **Flag 10 – Covert Data Transfer**  
🎯 **Objective:** Uncover evidence of internal data leaving the environment.  
📌 **Finding (answer):** Last unusual outbound connection → **52.54.13.125**  
🔍 **Evidence:**  
- **Host:** gab-intrn-vm  
- **RemoteUrl:** `eo7j1sn715wkekj.m.pipedream.net`  
- **Sequence:** 52.55.234.111 → **52.54.13.125** (last at 2025-07-18T15:28:44Z)  
💡 **Why it matters:** Validates egress path to external service consistent with data staging/exfil.
**KQL Query Used:**
```
DeviceNetworkEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where RemoteUrl !~ ""
| where RemoteUrl contains "pipedream.net"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteUrl
```
<img width="492" height="411" alt="Screenshot 2025-08-17 221959" src="https://github.com/user-attachments/assets/3497fc89-96b0-4dff-955d-1ef4930d7e02" />


---

🚩 **Flag 11 – Persistence via Local Scripting**  
🎯 **Objective:** Verify if unauthorized persistence was established via legacy tooling.  
📌 **Finding (answer):** File name tied to Run‑key value = **OnboardTracker.ps1**  
🔍 **Evidence:**  
- **Host:** gab-intrn-vm  
- **Timestamp:** 2025-07-18T15:50:36Z  
- **Registry:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`  
- **Value Name:** `HRToolTracker` → **C:\HRTools\LegacyAutomation\OnboardTracker.ps1**  
- **Initiating Process:** PowerShell `New-ItemProperty ... -Force`  
💡 **Why it matters:** Ensures re‑execution at logon; disguised as HR “Onboarding” tool.
**KQL Query Used:**
```
DeviceRegistryEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where InitiatingProcessCommandLine contains "-c"
| project Timestamp, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine
```
<img width="1643" height="231" alt="Screenshot 2025-08-17 222159" src="https://github.com/user-attachments/assets/2b76f134-956d-448c-8c57-c8c55a5bfc73" />

---

🚩 **Flag 12 – Targeted File Reuse / Access**  
🎯 **Objective:** Surface the document that stood out in the attack sequence.  
📌 **Finding (answer):** **Carlos Tanaka**  
🔍 **Evidence:**  
- **Host:** gab-intrn-vm   
- **Repeated Access:** `Carlos.Tanaka-Evaluation.lnk` (count = 3) within HR artifacts list  
💡 **Why it matters:** Personnel record of focus; aligns with promotion‑manipulation motive.
**KQL Query Used:**
```
DeviceEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| summarize Count = count() by FileName
| sort by Count desc
```
<img width="434" height="767" alt="Screenshot 2025-08-17 222304" src="https://github.com/user-attachments/assets/273f916d-e5fe-40dc-924f-802f9724ebc7" />



---

🚩 **Flag 13 – Candidate List Manipulation**  
🎯 **Objective:** Trace tampering with promotion‑related data.  
📌 **Finding (answer):** **SHA1 = 65a5195e9a36b6ce73fdb40d744e0a97f0aa1d34**  
🔍 **Evidence:**  
- **File:** `PromotionCandidates.csv`  
- **Host:** gab-intrn-vm  
- **Timestamp:** 2025-07-18 16:14:36 (first **FileModified**)  
- **Path:** `C:\HRTools\PromotionCandidates.csv`  
- **Initiating:** `"NOTEPAD.EXE" C:\HRTools\PromotionCandidates.csv`  
💡 **Why it matters:** Confirms direct manipulation of structured HR data driving promotion decisions.
**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FolderPath contains "HR"
| summarize Count = count() by FileName
| sort by Count desc

```
<img width="495" height="468" alt="Screenshot 2025-08-17 223219" src="https://github.com/user-attachments/assets/ce206008-93b6-48c1-a99c-2868db039031" />

**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FileName == "PromotionCandidates.csv"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, InitiatingProcessCommandLine

```
<img width="1880" height="433" alt="Screenshot 2025-08-17 223349" src="https://github.com/user-attachments/assets/f31b2be7-75d2-4dac-b491-8006c9f342b4" />


---

🚩 **Flag 14 – Audit Trail Disruption**  
🎯 **Objective:** Detect attempts to impair system forensics.  
📌 **Finding (answer):** **2025-07-19T05:38:55.6800388Z** (first log‑clear attempt)  
🔍 **Evidence:**  
- **Host:** gab-intrn-vm  
- **Process:** `wevtutil.exe`  
- **Command:** `"wevtutil.exe" cl Security` (+ additional clears shortly after)  
- **SHA256:** `0b732d9ad576d1400db44edf3e750849ac481e9bbaa628a3914e5eef9b7181b0`  
💡 **Why it matters:** Clear Windows Event Logs → destroys historical telemetry; classic anti‑forensics.
**KQL Query Used:**
```
DeviceProcessEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where ProcessCommandLine contains "wevtutil"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, ProcessCreationTime,InitiatingProcessCommandLine , InitiatingProcessCreationTime, SHA256
```
<img width="1263" height="773" alt="Screenshot 2025-08-17 223624" src="https://github.com/user-attachments/assets/af5db852-e1c5-4ff3-8919-aef0a6baa225" />



---

🚩 **Flag 15 – Final Cleanup and Exit Prep**  
🎯 **Objective:** Capture the combination of anti‑forensics actions signaling attacker exit.  
📌 **Finding (answer):** **2025-07-19T06:18:38.6841044Z**  
🔍 **Evidence:**  
- **File:** `EmptySysmonConfig.xml`  
- **Path:** `C:\Temp\EmptySysmonConfig.xml`  
- **Host:** gab-intrn-vm · **Initiating:** powershell.exe  
💡 **Why it matters:** Blinds Sysmon to suppress detection just prior to exit; ties off anti‑forensics chain.
**KQL Query Used:**
```
DeviceFileEvents
| where Timestamp between (datetime(2025-07-18) .. datetime(2025-07-31))
| where DeviceName contains "nathan-iel-vm"
| where FileName in ("ConsoleHost_history.txt","EmptySysmonConfig.xml","HRConfig.json")
| sort by Timestamp desc
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
```
<img width="445" height="233" alt="Screenshot 2025-08-17 224226" src="https://github.com/user-attachments/assets/6334babb-6839-4281-b025-74346f5623e9" />


---

## MITRE ATT&CK (Quick Map)
- **Execution:** T1059 (PowerShell) – Flags 1–5, 7–8  
- **Persistence:** T1547.001 (Run Keys) – Flag 11  
- **Discovery:** T1033/T1087 (whoami /all; group/user discovery) – Flags 1–3, 4  
- **Credential Access:** T1003.001 (LSASS dump) – Flag 7 (MiniDump via comsvcs.dll)  
- **Command & Control / Exfil:** T1071/T1041 – Flags 9–10 (pipedream.net, .net TLD, IP 52.54.13.125)  
- **Defense Evasion:** T1562.001/002 & T1070.001 – Flags 5–6 (Defender), 14–15 (log clear, Sysmon blind)

---

## Recommended Actions (Condensed)
1. Reset/rotate credentials (HR/IT/admin).  
2. Re-enable & harden Defender; deploy fresh Sysmon config.  
3. Block/monitor `*.pipedream.net` and related IPs (e.g., **52.54.13.125**).  
4. Integrity review/restore HR data (`PromotionCandidates.csv`, Carlos Tanaka records).  
5. Hunt for persistence across estate; remove `OnboardTracker.ps1` autoruns.  
6. Centralize logs; add detections for `comsvcs.dll, MiniDump` and Defender tamper.
