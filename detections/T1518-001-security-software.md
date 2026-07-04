# T1518.001 — Security Software Discovery

**Tactic:** Discovery  **Technique:** T1518.001  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

Before deploying malware or attempting evasion, an attacker checks what security
tooling is already running — antivirus, EDR, firewall status, and monitoring
agents like Sysmon. This lets them tailor their approach: pick techniques known to
bypass a specific product, disable what they can, or abort on a heavily-monitored
host. Notably, this test explicitly hunts for **Sysmon itself** — the attacker
looking for the very logging that's catching them.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1518.001 -TestNumbers 1

Test #1 runs a broad, chained defensive-recon sweep covering several angles at
once:
- **Firewall** — `netsh advfirewall show allprofiles`, `firewall dump`, `show currentprofile`, `firewall show rule name=all`, `firewall show state`, `firewall show config`
- **Windows Defender** — `sc query windefend`
- **Sysmon self-check** — `Get-Process ... Sysmon`, `Get-Service ... *sysm*`, `Get-CimInstance Win32_Service -Filter 'Description = ''System Monitor service'''`
- **AV/EDR product hunt** — `tasklist | findstr /i` for `virus`, `cb` (Carbon Black), `defender`, `cylance`, `mc` (McAfee)

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired **24 times**, capturing the entire
sweep:
- User: `WINDOWS\khaled`
- Parent CommandLine (first event) contains the full chain — every `netsh`,
  `sc query windefend`, the three PowerShell Sysmon checks, and each
  `tasklist | findstr` AV lookup, all joined with `&` under one `cmd.exe`
- The remaining events are the individual children: `netsh.exe`, `sc.exe`,
  `powershell.exe`, `tasklist.exe`, and `findstr.exe`
- Parent chain: `powershell.exe` → `cmd.exe` → each discovery tool

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "netsh"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

This query keys on `netsh`, which surfaces the firewall-discovery portion. But the
much stronger signal is the **shape of the whole event**: one `cmd.exe` parent
firing 24 discovery children in seconds, including `findstr` explicitly searching
process names for `cylance`, `defender`, `mc`, and `cb`. Searching running
processes for named security-vendor strings has essentially no legitimate purpose
— it's an attacker taking inventory of the defenses. The **Sysmon self-check**
(`Get-Service *sysm*`, `Description = 'System Monitor service'`) is an especially
high-value indicator: the attacker is probing for the exact monitoring that logged
this event.

## False Positives / Tuning

Individual pieces (`netsh`, `sc query`, `tasklist`) are noisy alone. The
high-fidelity detections here are the specific ones with no benign explanation:
`findstr`/`Where-Object` filtering for AV/EDR vendor names (`cylance`, `carbon
black`, `mcafee`, `defender`, `sentinelone`, `crowdstrike`), and process/service
enumeration targeting `Sysmon`. Also alert on the **volume + burst** pattern —
one parent spawning many discovery children in a short window is itself
suspicious regardless of the individual commands. Tune out legitimate security
software that self-references, and prioritize sweeps that immediately precede
defense-evasion (T1112) or impact (T1486) activity.

## Result

Splunk detected the complete security-software discovery sweep across 24
process-creation events — firewall enumeration, Defender status, a Sysmon
self-check, and a targeted `tasklist`/`findstr` hunt for AV/EDR product names. The
logs give full visibility into a multi-step defensive-recon attempt, including the
attacker's search for the very monitoring that recorded it.

## Screenshots

**Attack executed on Windows 11 target (security software discovery sweep):**
<img width="865" alt="T1518.001 security software discovery on Windows 11" src="https://github.com/user-attachments/assets/22abad50-e120-4b42-bdf5-35a418eb8ed3" />

**Detection in Splunk — 24 events (part 1 of 3): firewall enumeration:**
<img width="1915" alt="T1518.001 detection in Splunk part 1 firewall checks" src="https://github.com/user-attachments/assets/7c0896d3-86f7-4a20-a821-b68b1cc43848" />

**Detection in Splunk — (part 2 of 3): Defender, Sysmon self-check, AV hunt:**
<img width="1911" alt="T1518.001 detection in Splunk part 2 Defender and Sysmon checks" src="https://github.com/user-attachments/assets/766a3a30-094a-4594-a478-7c9121b0e48a" />

**Detection in Splunk — (part 3 of 3): tasklist/findstr AV product name scan:**
<img width="1907" alt="T1518.001 detection in Splunk part 3 tasklist findstr AV names" src="https://github.com/user-attachments/assets/54ccef53-49a7-48ad-9023-7d5e13bcd81a" />
