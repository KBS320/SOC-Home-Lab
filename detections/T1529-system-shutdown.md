# T1529 — System Shutdown/Reboot

**Tactic:** Impact  **Technique:** T1529  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

An attacker forces a system to shut down or reboot, usually as a final step —
to trigger a ransomware payload's boot-time execution, to disrupt availability and
business operations, or to destroy evidence by clearing volatile memory and active
processes before investigators can capture them. As an Impact technique, it's the
attacker deliberately causing harm rather than just moving through the environment.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1529 -TestNumbers 1

Test #1 runs the built-in Windows `shutdown` command to force an immediate
shutdown: `shutdown /s /t 1` (`/s` = shut down, `/t 1` = 1-second timer).

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired once:
- Image: `C:\Windows\System32\cmd.exe`
- User: `WINDOWS\khaled`
- CommandLine: `cmd.exe /c shutdown /s /t 1`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

The attack was also visually confirmed — the Windows VM displayed a "Shutting
down" screen immediately after execution, giving direct visual proof of the
successful action alongside the log-based detection.

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "shutdown"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on `shutdown`. What makes it actionable isn't the command alone —
it's the context: `shutdown /s` or `/r` with a **short or zero timer** (`/t 1`,
`/t 0`), the `/f` force flag, and a **script-host parent** (`powershell.exe` →
`cmd.exe`) rather than a user clicking Start → Shut down. Automated, forced,
immediate shutdowns from a shell are the pattern; a scheduled reboot for patching
looks very different. Because this is process-creation, you catch the command in
the brief window before the machine goes down — the last log the host writes.

## False Positives / Tuning

Legitimate shutdowns and reboots happen constantly (patching, maintenance, users),
so don't alert on `shutdown` alone. Prioritize: forced/immediate shutdowns
(`/f`, `/t 0`, `/t 1`) from a non-interactive parent, shutdowns that follow other
suspicious activity on the same host (ransomware indicators, mass file changes,
log clearing), and `shutdown /r` paired with a newly-created boot persistence
mechanism (which would execute a payload on reboot). Also watch the API/tooling
equivalents — `Stop-Computer`, `Restart-Computer`, and `InitiateSystemShutdown`.

## Result

Splunk detected the shutdown command in a single, clean process-creation event,
preserving the full command line and the `powershell.exe` → `cmd.exe` chain — and
the VM visibly shutting down immediately afterward confirmed the action end to
end. This shows that even a system-destroying command is captured in the last
moment before the host goes offline.

## Screenshots

**Attack executed on Windows 11 target (VM shutting down after `shutdown /s /t 1`):**
<img width="945" alt="T1529 system shutdown on Windows 11 VM" src="https://github.com/user-attachments/assets/b764d0ae-d3b1-48d8-92b5-0097bf28277d" />

**Detection in Splunk — shutdown command captured in one event:**
<img width="1913" alt="T1529 detection in Splunk showing shutdown command" src="https://github.com/user-attachments/assets/f7e32f0f-c6e7-480a-810e-bac859cd6cac" />
