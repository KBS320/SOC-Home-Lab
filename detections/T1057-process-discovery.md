# T1057 — Process Discovery (tasklist)

**Tactic:** Discovery  **Technique:** T1057  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker runs `tasklist` to enumerate every process running on the machine.
This is how they spot security tooling — antivirus, EDR agents, monitoring
services — running in the background, and it reveals what software is active. If
they identify a defensive process, the next move is often to try to kill or
evade it before continuing.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows Server target (192.168.56.102):

    Invoke-AtomicTest T1057 -TestNumbers 2

Test #2 runs `tasklist` through `cmd.exe` to list all running processes with
their PID, session, and memory usage.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 5 times:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c tasklist`
- Four `tasklist.exe` child processes spawned by `C:\Windows\System32\cmd.exe`,
  itself launched from `powershell.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "tasklist"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query matches any Sysmon event containing the string `tasklist`, then
rex-extracts the key fields. `tasklist` alone is low-fidelity — admins and
scripts run it routinely. The stronger signal is the **ParentImage chain**:
`powershell.exe` → `cmd.exe` → `tasklist`, i.e. process enumeration driven by a
script rather than typed interactively. It becomes more suspicious still when
followed by a process *kill* (`taskkill`, `Stop-Process`) targeting a security
tool — the classic "enumerate then disable defenses" sequence.

## False Positives / Tuning

`tasklist` runs during legitimate troubleshooting, inventory scripts, and
monitoring, so it's noisy on its own. Tune by keying on a non-interactive parent
(`powershell.exe`/`cmd.exe` from an automated process), or by correlating
`tasklist` with a subsequent `taskkill`/`Stop-Process` against a known AV/EDR
image name in a short window. Process discovery immediately followed by an
attempt to terminate a defensive process is the pattern worth alerting on.

## Result

Splunk detected the process-discovery run — 5 process-creation events from the
`cmd.exe` parent — capturing the command line and parent chain, and confirming
the attacker enumerated all running processes on the target.

## Screenshots

**Attack executed on Windows Server target (tasklist process enumeration):**
<img width="997" alt="T1057 tasklist executed on Windows Server" src="https://github.com/user-attachments/assets/f0bf328a-8141-4a8c-a29b-64e7b979d1ac" />

**Detection in Splunk — 5 events from the tasklist run:**
<img width="1912" alt="T1057 detection in Splunk showing tasklist process discovery" src="https://github.com/user-attachments/assets/ccbb24a4-85df-4228-962a-51602d2672ba" />
