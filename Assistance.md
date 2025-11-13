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
📌 **Finding** (answer): `2025-10-09T12:52:14.3135459Z`;

🔍 **Evidence:**
- **Host:** `gab-intrn-vm` 
- **Timestamp:**  `2025-10-09T12:52:14.3135459Z`

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

🚩 **Flag 10 – Proof-of-Access & Egress Validation**  
🎯 **Objective:** Find actions that both validate outbound reachability and attempt to capture host state for exfiltration value.

📌 **Finding (answer):** `www[.]msftconnecttest[.]com`

🔍 **Evidence:**  
- **Host:** `gab-intrn-vm` 
- **RemoteUrl:** `www[.]msftconnecttest[.]com`
- **RemoteIP:** `23[.]218[.]218[.]182`
- 💡 **Why it matters:** This step demonstrates both access and the potential to move meaningful data off the host...
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated > datetime(2025-10-09T12:52:14.3135459Z)
| where InitiatingProcessCommandLine contains "powershell"
| where ActionType in ("DnsQuery", "HttpRequest", "ConnectionSuccess")
| project TimeGenerated, RemoteUrl, RemoteIP, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by TimeGenerated asc
```
<img width="492" height="411" alt="Screenshot 2025-08-17 221959" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/fcc4994190d726bd97dc20b56f6daae5e50d18b8/screen%20captures/Assistance-F10.png" />


---

🚩 **Flag 11 – Bundling / Staging Artifacts**  
🎯 **Objective:** Detect consolidation of artifacts into a single location or package for transfer.  
📌 **Finding (answer):** Full folder path = **C:\Users\Public\ReconArtifacts.zip**  
🔍 **Evidence:**  
- **Host:** gab-intrn-vm  
- **Timestamp:** 2025-10-09T12:58:17.4364257Z 
- **Value Name:** `ReconArtifacts.zip` → **C:\Users\Public\ReconArtifacts.zip**    
- **Initiating Process:**  `RuntimeBroker.exe`  -> powershell.exe`
  
💡 **Why it matters:** Staging is the practical step that simplifies exfiltration and should be correlated back to prior recon.

**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated > datetime(2025-10-09T12:52:14.3135459Z)
| where InitiatingProcessCommandLine contains "powershell"
| where ActionType in ("FileCreated", "FileRenamed", "FileCopied")
| project TimeGenerated, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine,InitiatingProcessParentFileName, SHA256
| order by TimeGenerated asc
```
<img width="1643" height="231" alt="Screenshot 2025-08-17 222159" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/70b0bc01411e3bcc737bfdca521eaeb3b2037332/screen%20captures/Assistance-F11.png" />

---

🚩 **Flag 12 –  **  
🎯 **Objective:**   
🔍 **Evidence:**  
- **Host:** gab-intrn-vm
- **RemoteUrl:** `www[.]httpbin.org[.]com`
- **RemoteIP:** `100[.]29[.]147[.]161`
💡 **Why it matters:**

**KQL Query Used:**
```
DeviceNetworkEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated > datetime(2025-10-09T12:52:14.3135459Z)
| where InitiatingProcessCommandLine contains "powershell"
| where ActionType in ("DnsQuery", "HttpRequest", "ConnectionSuccess")
| project TimeGenerated, RemoteUrl, RemoteIP,  InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
| order by TimeGenerated asc
```
<img width="434" height="767" alt="Screenshot 2025-08-17 222304" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/5a05c5de86c3a527db92611d5b7f8de9a31f84c6/screen%20captures/Assistance-F12.png" />



---

🚩 **Flag 13 – Candidate List Manipulation**  
🎯 **Objective:**  
📌 **Finding (answer):**   
🔍 **Evidence:**   
- **Host:** gab-intrn-vm  
- **Timestamp:** 2025-07-18 16:14:36
- **Initiating:** 
💡 **Why it matters:** 
**KQL Query Used:**
```
​​DeviceProcessEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated > datetime(2025-10-09T12:52:14.3135459Z)
| where tolower(ProcessCommandLine) contains "/create"
   and tolower(ProcessCommandLine) contains "onlogon"
| project TimeGenerated, ProcessCommandLine
| order by TimeGenerated asc
```
<img width="495" height="468" alt="Screenshot 2025-08-17 223219" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/94ee3ff9cde27dae632e847f783c8974072381a9/screen%20captures/Assistance-F13.png" />



---

🚩 **Flag 14 – **  
🎯 **Objective:**   
📌 **Finding (answer):**   
🔍 **Evidence:**  
- **Host:** gab-intrn-vm  
- **Process:** `  
- **Command:** `
- **SHA256:** `  
💡 **Why it matters:** 
**KQL Query Used:**
```

```
<img width="1263" height="773" alt="Screenshot 2025-08-17 223624" src="" />



---

🚩 **Flag 15 – Planted Narrative / Cover Artifact**  
🎯 **Objective:** Identify a narrative or explanatory artifact intended to justify the 
📌 **Finding (answer):**  SupportChat_log.lnk
🔍 **Evidence:**  
- **File:** `SupportChat_log.lnk`
- **Timestamp:** `2025-10-09T13:02:41.5698148Z`
- **Path:** `C:\Users\g4bri3lintern\AppData\Roaming\Microsoft\Windows\Recent\SupportChat_log.lnk`
- **SHA256** `3d612fb329f4278d7d1c36c5859797bbe30dca318e27bd2afdf69b1c42198809`
- **Host:** gab-intrn-vm
- 
💡 **Why it matters:** A planted explanation is a classic misdirection. The sequence and context reveal deception more than the text itself.

**KQL Query Used:**
```
DeviceFileEvents
| where DeviceName == "gab-intern-vm"
| where TimeGenerated > datetime(2025-10-06T12:52:14.3135459Z)
| where FileName matches regex @"(?i)(temp|readme|log|cover|report)\.(txt|csv|docx|lnk)"
| project TimeGenerated, FileName, InitiatingProcessCommandLine,SHA256, FolderPath
```
<img width="445" height="233" alt="Screenshot 2025-08-17 224226" src="https://github.com/davidbrown-sec/Threat-Hunting/blob/4567529fc8acf0be80499e690a7805ce7a7089da/screen%20captures/Assistance-F15.png" />


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
