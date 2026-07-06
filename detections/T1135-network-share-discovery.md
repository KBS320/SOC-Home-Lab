# T1135 — Network Share Discovery (net view)

**Tactic:** Discovery  **Technique:** T1135  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker enumerates network shares to find file shares they can access —
mapped drives, admin shares (C$, ADMIN$), and shared folders on the local machine
or across the network. Shares are prime targets: they often hold sensitive
documents, credentials, and backups, and they're a common path for lateral
movement and data staging before exfiltration. Ransomware groups routinely run
share discovery to find everything worth encrypting.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1135 -TestNumbers 4

Test #4 ("Network Share Discovery command prompt") runs `net view \\localhost`
to list the shares available on the machine.

Note: I initially tested the PowerShell variants (`Get-SmbShare`, Test #5) and the
`net share` variant, but those either ran in-session (no new process spawned) or
were filtered by the Sysmon config, so they produced no process-creation event.
Test #4 (`net view` via cmd) spawns a distinct `net.exe` process and logs cleanly
— a good reminder that the *same technique* can be visible or invisible to a
detection depending on exactly how it's executed.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 2 times:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c net view \\localhost`
- Child process: `net.exe` running `net view \\localhost`
- Parent chain: `powershell.exe` → `cmd.exe` → `net.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "net view"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on `net view`, which surfaces `net.exe` being used to enumerate
shares. On its own this is medium-fidelity — `net view` has some legitimate admin
use, but it's also a staple of the discovery phase. The stronger signal is
context: `net view` spawned from a script host (`powershell.exe` → `cmd.exe`)
rather than typed interactively, and especially `net view` appearing alongside
other discovery commands (`net share`, `net use`, `net user`) in a short burst.

An important lesson from building this detection: **share discovery via native
tools is a known detection blind spot.** PowerShell cmdlets like `Get-SmbShare`
run *in-session* and spawn no new process, so Sysmon Event ID 1 misses them
entirely. To catch those variants you need **PowerShell Script Block Logging
(Event ID 4104)** in addition to Sysmon process creation. Relying on process
creation alone would leave the PowerShell path invisible.

## False Positives / Tuning

`net view` and `net share` appear in legitimate admin and troubleshooting work,
so they're noisy alone. Tune by: keying on a non-interactive parent, correlating
share discovery with other discovery commands from the same parent in a short
window, or flagging it when it precedes lateral movement (`net use` to a remote
share) or mass file access. For full coverage, pair Sysmon process-creation
detection with Script Block Logging (Event 4104) so the PowerShell variants
(`Get-SmbShare`, PowerView `Invoke-ShareFinder`) are also caught.

## Result

Splunk detected the share-discovery activity across 2 process-creation events,
capturing the `powershell.exe` → `cmd.exe` → `net.exe` chain and the full
`net view \\localhost` command. Testing also surfaced a real detection gap: the
PowerShell-based share-discovery variants generate no process-creation event and
require Script Block Logging to catch — a useful finding about the limits of
process-creation-only monitoring.

## Screenshots

**Attack executed on Windows 11 target (net view share discovery):**
<img width="1000" height="127" alt="T1135-windows png" src="https://github.com/user-attachments/assets/1807e447-ddb3-4c89-b9b6-93ff399743a5" />

**Detection in Splunk — 2 events, powershell → cmd → net view chain:**
<img width="1912" height="1026" alt="T1135-splunk png" src="https://github.com/user-attachments/assets/eafbfeca-b327-4898-8955-910cd73b3337" />
