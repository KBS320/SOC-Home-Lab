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

## The 30 Techniques — Grouped by ATT&CK Tactic

I ran these in attack order (the **Run #** column preserves that sequence), but
they are grouped here by their actual MITRE ATT&CK tactic — the way a SIEM's
coverage map would show them.

### Discovery (14) — Learn the environment

*The attacker just got in. First move: figure out where they are, who they are, and what is worth taking.*

| Run # | What I Simulated                            | MITRE ID  | Writeup |
| ----- | ------------------------------------------- | --------- | ------- |
| 1  | Whoami — who am I logged in as?             | T1033     | [View →](detections/T1033-whoami.md) |
| 2  | Systeminfo — what machine is this?          | T1082     | [View →](detections/T1082-system-info.md) |
| 3  | Tasklist — what processes are running?      | T1057     | [View →](detections/T1057-process-discovery.md) |
| 4  | Ipconfig — what network am I on?            | T1016     | [View →](detections/T1016-network-config.md) |
| 5  | Netstat — who is this machine talking to?   | T1049     | [View →](detections/T1049-network-connections.md) |
| 6  | Net user — what accounts exist?             | T1087.001 | [View →](detections/T1087-local-account-discovery.md) |
| 7  | Net localgroup — who has admin rights?      | T1069.001 | [View →](detections/T1069-local-group-discovery.md) |
| 8  | Net share — what shared folders exist?      | T1135     | [View →](detections/T1135-network-share-discovery.md) |
| 9  | Dir/tree — what files are on this machine?  | T1083     | [View →](detections/T1083-file-directory-discovery.md) |
| 10 | Reg query — what is hiding in the registry? | T1012     | [View →](detections/T1012-query-registry.md) |
| 20 | System time queried                         | T1124     | [View →](detections/T1124-system-time-discovery.md) |
| 26 | Password policy dumped                      | T1201     | [View →](detections/T1201-password-policy.md) |
| 27 | Security software identified                | T1518.001 | [View →](detections/T1518-001-security-software.md) |
| 28 | USB and peripheral devices enumerated       | T1120     | [View →](detections/T1120-peripheral-devices.md) |

### Execution (2) — Run malicious code

*Time to run something that shouldn't be running.*

| Run # | What I Simulated             | MITRE ID  | Writeup |
| ----- | ---------------------------- | --------- | ------- |
| 11 | PowerShell encoded commands  | T1059.001 | [View →](detections/T1059-001-powershell.md) |
| 12 | CMD and batch file execution | T1059.003 | [View →](detections/T1059-003-cmd-shell.md) |

### Persistence (3) — Stay on the machine

*If the machine reboots, the attacker comes back automatically.*

| Run # | What I Simulated                             | MITRE ID  | Writeup |
| ----- | -------------------------------------------- | --------- | ------- |
| 13 | Scheduled task created at startup            | T1053.005 | [View →](detections/T1053-005-scheduled-task.md) |
| 14 | Registry run key added for persistence       | T1547.001 | [View →](detections/T1547-001-registry-run-key.md) |
| 29 | BITS job used for silent background download | T1197     | [View →](detections/T1197-bits-jobs.md) |

### Defense Evasion (4) — Hide from security tools

*Cover the tracks. Make it look like nothing happened.*

| Run # | What I Simulated                      | MITRE ID  | Writeup |
| ----- | -------------------------------------- | --------- | ------- |
| 16 | Rundll32 used to run malicious code   | T1218.011 | [View →](detections/T1218-011-rundll32.md) |
| 17 | Evidence deleted from disk            | T1070.004 | [View →](detections/T1070-004-file-deletion.md) |
| 18 | Command history cleared               | T1070.003 | [View →](detections/T1070-003-clear-history.md) |
| 19 | Registry modified to disable security | T1112     | [View →](detections/T1112-modify-registry.md) |

### Command and Control (1) — Pull tooling in from outside

*The attacker needs their own tools on the box.*

| Run # | What I Simulated                 | MITRE ID | Writeup |
| ----- | -------------------------------- | -------- | ------- |
| 15 | Remote tool downloaded to target | T1105    | [View →](detections/T1105-ingress-tool-transfer.md) |

### Collection (3) — Gather what's worth stealing

*Grab the data and package it for the trip out.*

| Run # | What I Simulated                   | MITRE ID  | Writeup |
| ----- | ---------------------------------- | --------- | ------- |
| 21 | Screenshot taken of active desktop | T1113     | [View →](detections/T1113-screen-capture.md) |
| 22 | Clipboard contents stolen          | T1115     | [View →](detections/T1115-clipboard-data.md) |
| 23 | Files archived into a zip          | T1560.001 | [View →](detections/T1560-001-archive-data.md) |

### Exfiltration (1) — Get the data out

*Everything before this was setup. This is the theft.*

| Run # | What I Simulated                 | MITRE ID | Writeup |
| ----- | -------------------------------- | -------- | ------- |
| 24 | Data exfiltrated over C2 channel | T1041    | [View →](detections/T1041-exfiltration-c2.md) |

### Impact (2) — Damage and destroy

*The final stage. A quiet intrusion becomes a business emergency.*

| Run # | What I Simulated                        | MITRE ID | Writeup |
| ----- | --------------------------------------- | -------- | ------- |
| 25 | Files encrypted — ransomware simulation | T1486    | [View →](detections/T1486-ransomware-encryption.md) |
| 30 | System shutdown to destroy evidence     | T1529    | [View →](detections/T1529-system-shutdown.md) |

**Not covered yet:** Credential Access and Lateral Movement — the natural next phase for this lab.

---

## Detection Writeups

Each technique has its own writeup in the `/detections` folder with:

- What the attack does and why attackers use it
- The exact Atomic Red Team command used
- The raw Splunk event captured
- The SPL query that detected it
- False positive analysis and tuning guidance
- A screenshot of the Splunk alert firing

→ [Browse all detection writeups](detections/README.md)

---

## Tools and Stack

- **Splunk** — SIEM, log ingestion, search and alerting
- **Sysmon** — Deep Windows event logging (SwiftOnSecurity config)
- **Atomic Red Team** — Open-source attack simulation mapped to MITRE ATT&CK
- **VirtualBox** — Virtualization
- **PowerShell** — Attack execution on Windows target

---

## Second Lab — Wazuh / Suricata / ELK Stack Deployment

The Splunk lab above is about **detection content**. This second lab is about
**pipeline engineering** — standing up an open-source SIEM and network IDS end to
end, the kind of stack a lot of SOCs run instead of Splunk.

The goal here was not detection depth. It was proving I could build the plumbing:
a fully TLS-encrypted Suricata → Wazuh → Filebeat → Elasticsearch → Kibana chain
from scratch, and confirm traffic flowing all the way through to a live signature hit.

| Component    | Details                                                        |
| ------------- | -------------------------------------------------------------- |
| SIEM          | Wazuh Manager 4.5.4                                            |
| Log pipeline  | Suricata → Wazuh → Filebeat → Elasticsearch → Kibana (full TLS) |
| NIDS          | Suricata 6.0.4 (51,851 ET Open signatures)                      |
| Host          | Ubuntu 22.04 on VirtualBox, 192.168.56.103                      |

**Verified working:** full TLS confirmed at every hop, 245 events ingested, and a
live Suricata signature fired end to end into Kibana (GPL ATTACK_RESPONSE id check
returned root — Rule 86601, informational severity). Custom detection content is
the next phase, starting with the T1055 process-injection rules in
[`wazuh-lab/local_rules.xml`](wazuh-lab/local_rules.xml).

→ [Full writeup and dashboard screenshots](wazuh-lab/README.md)

---

## Background

8+ years working hands-on with security tools across financial institutions
including TD Bank and Fiserv. Proficient in Splunk, CrowdStrike, Cortex XSOAR,
and Prisma Cloud. CompTIA CySA+ certified.

This lab was built to go beyond tool familiarity — to develop real detection
instincts by thinking through each attack before writing a single SPL query.
