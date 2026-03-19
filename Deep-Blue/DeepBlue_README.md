# Deep Blue — Full Writeup

**Platform:** Blue Team Labs Online (Retired)  
**Difficulty:** Very Easy  

---

## Scenario Summary

A Windows workstation was compromised via an attack against an internet-facing RDP service. Meterpreter was subsequently deployed. We are provided with Security.evtx and System.evtx exports from the compromised machine and tasked with verifying the findings using DeepBlueCLI.

---

## Setup

The log files are located at:
```
C:\Users\BTLOTest\Desktop\Investigation\Security.evtx
C:\Users\BTLOTest\Desktop\Investigation\System.evtx
```

DeepBlueCLI is located at:
```
C:\Users\BTLOTest\Desktop\Investigation\DeepBlueCLI-master\
```

Open PowerShell from inside the DeepBlueCLI-master folder (Shift + Right-click → Open PowerShell window here).

If you get an execution policy error run this first:
```powershell
Set-ExecutionPolicy Bypass -Scope Process
```

---

## Investigation

### Question 1 — Which user account ran GoogleUpdate.exe?

**Approach:** Run DeepBlueCLI against Security.evtx. It flags GoogleUpdate.exe with encoded Base64 in the command line and identifies the user who ran it.

```powershell
.\DeepBlue.ps1 "C:\Users\BTLOTest\Desktop\Investigation\Security.evtx"
```

**Answer:** `Mike Smith`

*(add screenshot of DeepBlueCLI output flagging GoogleUpdate.exe under Mike Smith)*

---

### Question 2 — At what time is there likely evidence of Meterpreter activity?

**Approach:** In the same DeepBlueCLI Security.evtx output, look for the alert flagging Meterpreter activity. DeepBlueCLI detects the named pipe impersonation technique Meterpreter uses for privilege escalation (getsystem).

**Answer:** `4/10/2021 10:48:14`

*(add screenshot of DeepBlueCLI Meterpreter alert)*

---

### Question 3 — What is the name of the suspicious service created?

**Approach:** Run DeepBlueCLI against System.evtx. New service installation events (Event ID 7045) are flagged automatically. The service name is randomly generated to avoid detection.

```powershell
.\DeepBlue.ps1 "C:\Users\BTLOTest\Desktop\Investigation\System.evtx"
```

**Answer:** `rztbzn`

*(add screenshot of DeepBlueCLI service creation alert)*

---

### Question 4 — Identify the malicious executable used to gain the Meterpreter reverse shell

**Approach:** Open Security.evtx in Event Viewer. Filter for Event ID 4688 (process creation). Navigate to the 10:30–10:50 AM window on 10th April 2021. Look for executables running from suspicious locations — legitimate Windows processes run from System32 or known application folders, not from user Downloads folders.

The key indicator here was the **file path** — `C:\Users\Mike Smith\Downloads\` is not a legitimate location for any real Windows process or application.

In Event Viewer:
1. File → Open Saved Log → Security.evtx
2. Right-click → Filter Current Log → Event ID: 4688
3. Navigate to the 10:30–10:50 AM window on 10th April 2021
4. Look for executables running from Downloads, Temp, Desktop, or AppData

**Answer:** `Mike Smith, serviceupdate.exe`

*(add screenshot of Event ID 4688 showing serviceupdate.exe running from Downloads)*

---

### Question 5 — What was the command line used to create the persistence account?

**Approach:** Filter Event Viewer for Event ID 4688 in the 11:25–11:40 AM window on 10th April 2021. Look for net.exe commands creating a new user. The account is named ServiceAct — deliberately chosen to blend in as a legitimate service account.

**Answer:** `C:\Windows\system32\net.exe net user ServiceAct /add`

*(add screenshot of the net user command in Event Viewer)*

---

### Question 6 — What two local groups was the new account added to?

**Approach:** Continue reviewing 4688 events in the same time window. Look for subsequent net.exe commands adding the new account to local groups. Two separate commands were run — one for each group.

**Answer:** `administrators, Remote Desktop Users`

*(add screenshot of the group addition commands)*

---

## Attack Chain Summary

| Time | Event |
|------|-------|
| Before attack | Security log cleared (Event ID 1102) |
| 10:30–10:50 AM 10/04/2021 | serviceupdate.exe downloaded and run from Mike Smith's Downloads folder |
| 10:48:14 AM 10/04/2021 | Meterpreter shell established — service rztbzn installed for persistence |
| 11:25–11:40 AM 10/04/2021 | Backdoor account ServiceAct created |
| 11:25–11:40 AM 10/04/2021 | ServiceAct added to Administrators and Remote Desktop Users groups |

---

## MITRE ATT&CK Mapping

| Technique ID | Name | Evidence |
|-------------|------|---------|
| T1110 | Brute Force | RDP brute force to gain initial access |
| T1036 | Masquerading | serviceupdate.exe named to appear as a legitimate update |
| T1059 | Command and Scripting Interpreter | net.exe used to create accounts and modify groups |
| T1543 | Create or Modify System Process | Malicious service rztbzn installed (Event ID 7045) |
| T1136 | Create Account | ServiceAct backdoor account created (net user /add) |
| T1098 | Account Manipulation | ServiceAct added to Administrators and RDP Users groups |

---

## Key Takeaways

- **DeepBlueCLI is the fastest first step** — run it against both Security.evtx and System.evtx before opening Event Viewer
- **File path matters as much as filename** — serviceupdate.exe sounds legitimate but running from Downloads immediately flags it
- **Attackers name things to blend in** — ServiceAct looks like a service account, rztbzn looks random but was installed as a service
- **Two groups for maximum persistence** — Administrators for full control, Remote Desktop Users to maintain RDP access
- **Log clearing (Event ID 1102) doesn't always mean evidence is gone** — events can survive or be found via other means

---

*Writeup by Richard Skerritt | BTL1 candidate | [LinkedIn](https://www.linkedin.com/in/richard-skerritt-25558254)*
