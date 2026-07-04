# T1124 — System Time Discovery

**Tactic:** Discovery  **Technique:** T1124  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker queries the system time and timezone of the machine. This tells them
the target's local business hours, so they can schedule the most destructive
actions — ransomware deployment, mass deletion — for nights or weekends when no
one is watching. Timezone data also helps correlate activity across machines in
different regions and can be used to evade time-based defenses.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1124 -TestNumbers 1

Test #1 ("System Time Discovery") queries both the current time and the timezone
through `cmd.exe`:
`net time \\localhost & w32tm /tz`
(`net time` returns the current time; `w32tm /tz` returns the timezone and bias.)

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 2 times:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c net time \\localhost & w32tm /tz`
- Child process: `net.exe` (`net time \\localhost`)
- Parent chain: `powershell.exe` → `cmd.exe` → `net.exe` / `w32tm.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "w32tm"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on `w32tm`, the Windows time utility. On its own, time discovery is
low-fidelity — `w32tm` and `net time` have legitimate diagnostic uses. What makes
it worth capturing is context: system-time discovery rarely happens in isolation
during an intrusion. It usually sits inside a broader discovery burst (alongside
`systeminfo`, `whoami`, `ipconfig`) and, in ransomware playbooks, appears shortly
before the destructive stage as the attacker figures out the local off-hours
window. It's a supporting indicator, not a standalone alert.

## False Positives / Tuning

`w32tm` and `net time` run during legitimate time-sync troubleshooting, so alone
they're noisy. Tune by correlating time discovery with other discovery commands
from the same parent in a short window, or by flagging it when it precedes
high-impact activity (mass file changes, service stops, shutdown) on the same
host. To broaden coverage, also match `net time` and `Get-Date` / `[TimeZoneInfo]`
in PowerShell. The value of this detection is as a *sequence* signal — one more
data point in a discovery chain, or an early warning ahead of impact.

## Result

Splunk detected the system-time discovery across 2 process-creation events,
capturing both the `net time` and `w32tm /tz` queries. The log confirms the
attacker enumerated the machine's local time and timezone — reconnaissance that
often precedes the timing of a destructive action.

## Screenshots

**Attack executed on Windows 11 target (system time and timezone query):**
<img width="938" alt="T1124 system time discovery on Windows 11" src="https://github.com/user-attachments/assets/6bc9100c-6217-43a8-9c6e-e2f8dee838ca" />

**Detection in Splunk — 2 events, net time and w32tm timezone query:**
<img width="1907" alt="T1124 detection in Splunk showing system time discovery" src="https://github.com/user-attachments/assets/8e1d4ca9-42df-426a-abf7-36bf6c1f00a3" />
