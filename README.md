# SOC Detection Lab — 30 MITRE ATT&CK Techniques

A hands-on home lab where I built a full attack-and-detect pipeline from scratch.
Every technique was executed with Atomic Red Team on a Windows host and detected
in Splunk using custom SPL. No guided walkthroughs. No pre-built alerts. Built,
broken, and fixed by hand.

---

## Why I Built This

I've spent 8 years working with security tools at financial institutions —
Splunk, CrowdStrike, Cortex XSOAR, Prisma Cloud. I knew the tools. What I wanted
to prove — to myself and to any future employer — was that I could think like an
attacker and catch them in the logs.

This lab is that proof.

---

## Lab Environment

| Machine | OS | IP | Role |
|---|---|---|---|
| SIEM | Kali Linux | 192.168.56.101 | Runs Splunk (ingestion, search, detection) |
| Target | Windows 11 | 192.168.56.102 | Sysmon + Universal Forwarder; Atomic Red Team executed here |

- **Network:** VirtualBox Host-Only (192.168.56.0/24)
- **Log pipeline:** Sysmon (SwiftOnSecurity config) → Universal Forwarder → Splunk on Kali
- **Ingestion:** Logs land as raw `XmlWinEventLog` and are parsed at search time with `rex` field extractions
- **Attack framework:** Atomic Red Team, executed via PowerShell on the Windows target
- **Detection identity:** `WINDOWS\khaled`

> Note on SPL style: because Sysmon events are ingested as raw XML rather than
> pre-parsed fields, every detection query extracts Image, CommandLine,
> ParentImage, User, and UtcTime with `rex` before tabling the results. This
> mirrors a real-world scenario where the Splunk Add-on for Sysmon isn't
> installed and the analyst has to parse the raw event themselves.

---

## The 30 Techniques — Full Kill Chain

*Techniques are grouped below into a narrative kill-chain for readability. A few techniques' official MITRE tactic differs from the phase they appear in here (e.g. T1105 Ingress Tool Transfer is formally **Command and Control**); each writeup's header lists the accurate MITRE tactic.*

### Phase 1 — Discovery: Learn the Environment (Attacks 1–10)
*The attacker just got in. First move: figure out where they are.*

| # | What I Simulated | MITRE ID |
|---|---|---|
| 1 | Whoami — who am I logged in as? | T1033 |
| 2 | Systeminfo — what machine is this? | T1082 |
| 3 | Tasklist — what processes are running? | T1057 |
| 4 | Ipconfig — what network am I on? | T1016 |
| 5 | Netstat — who is this machine talking to? | T1049 |
| 6 | Net user — what accounts exist? | T1087.001 |
| 7 | Net localgroup — who has admin rights? | T1069.001 |
| 8 | Net share — what shared folders exist? | T1135 |
| 9 | Get-ChildItem — what files are on this machine? | T1083 |
| 10 | Reg query — what is hiding in the registry? | T1012 |

### Phase 2 — Execution: Run Malicious Code (Attacks 11–12)
*Time to run something that shouldn't be running.*

| # | What I Simulated | MITRE ID |
|---|---|---|
| 11 | PowerShell encoded commands | T1059.001 |
| 12 | CMD and batch file execution | T1059.003 |

### Phase 3 — Persistence: Stay on the Machine (Attacks 13–15)
*If the machine reboots, the attacker comes back automatically.*

| # | What I Simulated | MITRE ID |
|---|---|---|
| 13 | Scheduled task created at startup | T1053.005 |
| 14 | Registry run key added for persistence | T1547.001 |
| 15 | Ingress tool transfer via certutil download | T1105 |

### Phase 4 — Defense Evasion: Hide from Security Tools (Attacks 16–19)
*Cover the tracks. Make it look like nothing happened.*

| # | What I Simulated | MITRE ID |
|---|---|---|
| 16 | Rundll32 used to run malicious code | T1218.011 |
| 17 | Evidence deleted from disk | T1070.004 |
| 18 | Command history cleared | T1070.003 |
| 19 | Registry modified to disable security | T1112 |

### Phase 5 — Discovery 2: Deeper Reconnaissance (Attacks 20–22)
*The attacker now goes deeper — looking for timing, visuals, clipboard data.*

| # | What I Simulated | MITRE ID |
|---|---|---|
| 20 | System time queried | T1124 |
| 21 | Screenshot taken of active desktop | T1113 |
| 22 | Clipboard contents stolen | T1115 |

### Phase 6 — Collection: Package the Data (Attacks 23–24)
*Gather everything worth stealing and prepare it for exfiltration.*

| # | What I Simulated | MITRE ID |
|---|---|---|
| 23 | Files archived with makecab (SAM hive staged) | T1560.001 |
| 24 | Data exfiltrated over C2 channel | T1041 |

### Phase 7 — Impact: Damage and Destroy (Attacks 25–30)
*The final stage. Ransomware, cleanup, and exit.*

| # | What I Simulated | MITRE ID |
|---|---|---|
| 25 | Files encrypted — ransomware simulation | T1486 |
| 26 | Password policy dumped | T1201 |
| 27 | Security software identified | T1518.001 |
| 28 | USB and peripheral devices enumerated | T1120 |
| 29 | BITS job used for silent background download | T1197 |
| 30 | System shutdown to destroy evidence | T1529 |

---

## Detection Writeups

Each technique has its own writeup in the `/detections` folder, following a
consistent structure:
- What the attack does and why attackers use it
- The exact Atomic Red Team command executed
- What Sysmon captured (Image, CommandLine, ParentImage, User)
- The SPL detection query
- **Detection Logic** — why the query works and what the real signal is
- **False Positives / Tuning** — how I'd operationalize it without flooding the SOC
- Screenshots of both the attack (Windows side) and the detection (Splunk side)

Several tests behaved realistically rather than cleanly — payloads that failed to
resolve, tools missing from the host, commands blocked by Defender. Those are
documented honestly, because a failed or blocked action still leaves a forensic
trail, and recognizing that trail is the job.

→ [Browse all detection writeups](https://github.com/KBS320/SOC-Home-Lab/tree/main/detections)

---

## Tools and Stack

- **Splunk** — SIEM: log ingestion, search, and detection
- **Sysmon** — Deep Windows event logging (SwiftOnSecurity config)
- **Atomic Red Team** — Open-source attack simulation mapped to MITRE ATT&CK
- **VirtualBox** — Virtualization / host-only lab network
- **PowerShell** — Attack execution on the Windows target

---

## What I'd Do Differently in Production

This is a single-host lab, so a few things are deliberately simplified:
- `index=*` is used for portability; in production each source would go to a
  dedicated, access-controlled index.
- Most Discovery queries are intentionally high-recall / low-precision. The
  writeups call out where a detection needs correlation (parent process, command
  chaining, time windows) before it's alert-worthy.
- There are no correlation searches or notable-event workflows here — the focus
  is on building the detection logic first, which is the foundation those layers
  sit on.

---

## Background

8+ years working hands-on with security tools across financial institutions
including TD Bank and Fiserv. Proficient in Splunk, CrowdStrike, Cortex XSOAR,
and Prisma Cloud. Security+ certified.

This lab was built to go beyond tool familiarity — to develop real detection
instincts by thinking through each attack before writing a single SPL query.
