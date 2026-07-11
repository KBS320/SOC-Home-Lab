# SOC Detection Lab — 30 MITRE ATT&CK Techniques

A hands-on home lab where I built a full attack-and-detect pipeline from scratch.
Every technique was simulated using Atomic Red Team and detected in Splunk.
No guided walkthroughs. No pre-built alerts. Built and broken and fixed by hand.

---

## Why I Built This

I have spent 8 years working with security tools at financial institutions —
Splunk, CrowdStrike, Cortex XSOAR, Prisma Cloud. I knew the tools.
What I wanted to prove — to myself and to any future employer — was that
I could think like an attacker and catch them in logs.

This lab is that proof.

---

## Lab Environment

| Machine         | OS                  | IP             | Role                               |
| --------------- | ------------------- | -------------- | ----------------------------------- |
| SIEM / Attacker | Kali Linux          | 192.168.56.101 | Runs Splunk, executes Atomic tests |
| Target          | Windows 11 Home     | 192.168.56.102 | Sysmon + Universal Forwarder       |

- Network: VirtualBox Host-Only (192.168.56.0/24)
- Log pipeline: Sysmon → Universal Forwarder → Splunk on Kali
- Attack framework: Atomic Red Team (PowerShell)
- Sysmon config: SwiftOnSecurity

---

## The 30 Techniques — Full Kill Chain

### Phase 1 — Discovery: Learn the Environment (Attacks 1–10)

*The attacker just got in. First move: figure out where they are.*

| #  | What I Simulated                            | MITRE ID  | Writeup |
| --- | ------------------------------------------- | --------- | ------- |
| 1  | Whoami — who am I logged in as?             | T1033     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1033-whoami.md) |
| 2  | Systeminfo — what machine is this?          | T1082     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1082-system-info.md) |
| 3  | Tasklist — what processes are running?      | T1057     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1057-process-discovery.md) |
| 4  | Ipconfig — what network am I on?            | T1016     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1016-network-config.md) |
| 5  | Netstat — who is this machine talking to?   | T1049     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1049-network-connections.md) |
| 6  | Net user — what accounts exist?             | T1087.001 | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1087-local-account-discovery.md) |
| 7  | Net localgroup — who has admin rights?      | T1069.001 | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1069-local-group-discovery.md) |
| 8  | Net share — what shared folders exist?      | T1135     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1135-network-share-discovery.md) |
| 9  | Dir/tree — what files are on this machine?  | T1083     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1083-file-directory-discovery.md) |
| 10 | Reg query — what is hiding in the registry? | T1012     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1012-query-registry.md) |

### Phase 2 — Execution: Run Malicious Code (Attacks 11–12)

*Time to run something that shouldn't be running.*

| #  | What I Simulated             | MITRE ID  | Writeup |
| --- | ---------------------------- | --------- | ------- |
| 11 | PowerShell encoded commands  | T1059.001 | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1059-001-powershell.md) |
| 12 | CMD and batch file execution | T1059.003 | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1059-003-cmd-shell.md) |

### Phase 3 — Persistence: Stay on the Machine (Attacks 13–15)

*If the machine reboots, the attacker comes back automatically.*

| #  | What I Simulated                       | MITRE ID  | Writeup |
| --- | -------------------------------------- | --------- | ------- |
| 13 | Scheduled task created at startup      | T1053.005 | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1053-005-scheduled-task.md) |
| 14 | Registry run key added for persistence | T1547.001 | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1547-001-registry-run-key.md) |
| 15 | Remote tool downloaded to target       | T1105     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1105-ingress-tool-transfer.md) |

### Phase 4 — Defense Evasion: Hide from Security Tools (Attacks 16–19)

*Cover the tracks. Make it look like nothing happened.*

| #  | What I Simulated                      | MITRE ID  | Writeup |
| --- | -------------------------------------- | --------- | ------- |
| 16 | Rundll32 used to run malicious code   | T1218.011 | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1218-011-rundll32.md) |
| 17 | Evidence deleted from disk            | T1070.004 | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1070-004-file-deletion.md) |
| 18 | Command history cleared               | T1070.003 | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1070-003-clear-history.md) |
| 19 | Registry modified to disable security | T1112     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1112-modify-registry.md) |

### Phase 5 — Discovery 2: Deeper Reconnaissance (Attacks 20–22)

*The attacker now goes deeper — looking for timing, visuals, clipboard data.*

| #  | What I Simulated                   | MITRE ID | Writeup |
| --- | ---------------------------------- | -------- | ------- |
| 20 | System time queried                | T1124    | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1124-system-time-discovery.md) |
| 21 | Screenshot taken of active desktop | T1113    | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1113-screen-capture.md) |
| 22 | Clipboard contents stolen          | T1115    | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1115-clipboard-data.md) |

### Phase 6 — Collection: Package the Data (Attacks 23–24)

*Gather everything worth stealing and prepare it for exfiltration.*

| #  | What I Simulated                 | MITRE ID  | Writeup |
| --- | --------------------------------- | --------- | ------- |
| 23 | Files archived into a zip        | T1560.001 | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1560-001-archive-data.md) |
| 24 | Data exfiltrated over C2 channel | T1041     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1041-exfiltration-c2.md) |

### Phase 7 — Impact: Damage and Destroy (Attacks 25–30)

*The final stage. Ransomware, cleanup, and exit.*

| #  | What I Simulated                             | MITRE ID  | Writeup |
| --- | ---------------------------------------------- | --------- | ------- |
| 25 | Files encrypted — ransomware simulation      | T1486     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1486-ransomware-encryption.md) |
| 26 | Password policy dumped                       | T1201     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1201-password-policy.md) |
| 27 | Security software identified                 | T1518.001 | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1518-001-security-software.md) |
| 28 | USB and peripheral devices enumerated        | T1120     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1120-peripheral-devices.md) |
| 29 | BITS job used for silent background download | T1197     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1197-bits-jobs.md) |
| 30 | System shutdown to destroy evidence          | T1529     | [View →](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/T1529-system-shutdown.md) |

---

## Detection Writeups

Each technique has its own writeup in the `/detections` folder with:

- What the attack does and why attackers use it
- The exact Atomic Red Team command used
- The raw Splunk event captured
- The SPL query that detected it
- A screenshot of the Splunk alert firing

→ [Browse all detection writeups](https://github.com/KBS320/SOC-Home-Lab/blob/main/detections/README.md)

---

## Tools and Stack

- **Splunk** — SIEM, log ingestion, search and alerting
- **Sysmon** — Deep Windows event logging (SwiftOnSecurity config)
- **Atomic Red Team** — Open-source attack simulation mapped to MITRE ATT&CK
- **VirtualBox** — Virtualization
- **PowerShell** — Attack execution on Windows target

---

---

## Second Lab — Wazuh SOC Deployment (Network + Host)

The lab above focuses on host-based detection in Splunk. I also built a second, independent detection stack to get hands-on with an open-source SIEM and network intrusion detection — the kind of stack a lot of SOCs run instead of Splunk.

| Component    | Details                                                    |
| ------------- | ----------------------------------------------------------- |
| SIEM          | Wazuh Manager 4.5.4                                        |
| Log pipeline  | Suricata → Wazuh → Filebeat → Elasticsearch → Kibana (full TLS) |
| NIDS          | Suricata 6.0.4 (51,851 ET Open signatures)                  |
| Host          | Ubuntu 22.04 on VirtualBox, 192.168.56.103                  |

**Verified working:** full TLS pipeline confirmed end to end, live detection fired correctly (GPL ATTACK_RESPONSE id check returned root — Rule 86601), 245 security events collected, MITRE ATT&CK mapping enabled in the Kibana dashboard.

→ [Full writeup and dashboard screenshots](https://github.com/KBS320/SOC-Home-Lab/blob/main/wazuh-lab/README.md)

## Background

8+ years working hands-on with security tools across financial institutions
including TD Bank and Fiserv. Proficient in Splunk, CrowdStrike, Cortex XSOAR,
and Prisma Cloud. CompTIA CySA+ certified.

This lab was built to go beyond tool familiarity — to develop real detection
instincts by thinking through each attack before writing a single SPL query.
