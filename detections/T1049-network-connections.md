# T1049 — System Network Connections Discovery (netstat)

**Tactic:** Discovery  **Technique:** T1049  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker enumerates active network connections on the machine — what
external IPs it's talking to, which ports are open, and what services are
listening. Paired with session-discovery commands, this reveals the machine's
network exposure and points to other systems the attacker can pivot to.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1049 -TestNumbers 1

The test chains three connection/session-discovery commands through `cmd.exe`:
`netstat -ano`, `net use`, and `net sessions`. Each spawns its own process, so a
single test produces multiple Sysmon events.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 4 times — the parent `cmd.exe` plus
each chained tool:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c netstat -ano & net use & net sessions 2>nul`
- Child processes: `NETSTAT.EXE` (`netstat -ano`), `net.exe` (`net use`),
  `net.exe` (`net sessions`)
- All spawned by `C:\Windows\System32\cmd.exe`, itself launched by
  `powershell.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "netstat"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query matches any Sysmon event containing the string `netstat`, then
rex-extracts the key fields from raw XML. `netstat` alone is low-fidelity — it's
a normal troubleshooting tool. The stronger signal is the **parent `cmd.exe`
running netstat alongside `net use` and `net sessions` in one burst**: that
combination is connection + share + session enumeration, a classic pre-lateral-
movement recon sweep rather than an admin checking one thing.

## False Positives / Tuning

`netstat` and `net` commands run during legitimate admin and troubleshooting
work, so on their own they're noisy. Tune by keying on the *pattern*: one parent
(`cmd.exe`/`powershell.exe`) spawning multiple network/session-discovery children
(`netstat`, `net use`, `net sessions`, `net view`) inside a short window. A lone
`netstat` rarely warrants an alert; the chained sweep does.

## Result

Splunk detected the full connection-discovery chain — 4 process-creation events
from one `cmd.exe` parent — capturing each command line and confirming the
attacker enumerated active connections, mapped shares, and listed sessions in a
single automated sweep.

## Screenshots

**Attack executed on Windows 11 target:**
<img width="1002" alt="T1049 netstat discovery test executed on Windows 11" src="https://github.com/user-attachments/assets/49e5ac74-b291-4752-9531-1e08b3f0aea4" />

**Detection in Splunk — 4 events from one cmd.exe parent:**
<img width="1910" alt="T1049 detection in Splunk showing netstat, net use, net sessions" src="https://github.com/user-attachments/assets/12613e85-d138-4e81-8f8e-f7c7027daa82" />
