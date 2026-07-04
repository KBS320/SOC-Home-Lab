# T1053.005 — Scheduled Task (schtasks)

**Tactic:** Persistence  **Technique:** T1053.005  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker creates a scheduled task that automatically runs their code when
the machine starts or when a user logs on. This is how attackers survive reboots
— even if the machine restarts, their payload runs again automatically. It's one
of the most common persistence techniques in real intrusions, and running a task
`/ru system` means the payload executes with SYSTEM privileges.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1053.005 -TestNumbers 1

The test creates **two** scheduled tasks, both launching `cmd.exe /c calc.exe`
as the payload:
- `T1053_005_OnLogon` — trigger `/sc onlogon` (runs when a user logs on)
- `T1053_005_OnStartup` — trigger `/sc onstart /ru system` (runs at boot as SYSTEM)

Both were created successfully (exit code 0).

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 3 times:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe" & schtasks /create /tn "T1053_005_OnStartup" /sc onstart /ru system /tr "cmd.exe /c calc.exe"`
- Two child `schtasks.exe` processes — one per task created
- All spawned by `C:\Windows\System32\cmd.exe`, launched from `powershell.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "schtasks" "create"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on `schtasks` together with `create` — the signature of a task
being registered rather than queried or run. Unlike the Discovery techniques,
this is medium-to-high fidelity on its own: task *creation* is far less frequent
than task execution. The strongest escalators visible in the command line are
`/sc onstart` combined with `/ru system` (a boot-persistent SYSTEM task) and a
`/tr` target that launches `cmd.exe` or `powershell.exe` — hallmarks of a
persistence mechanism, not a routine admin job.

## False Positives / Tuning

Legitimate software and admins create scheduled tasks (updaters, backups,
maintenance). To separate benign from malicious, flag: tasks whose `/tr` target
is a shell (`cmd.exe`, `powershell.exe`) or a binary in a temp/user directory,
tasks created with `/ru system`, and — the strongest tell — a `schtasks /create`
whose ParentImage is `cmd.exe` or `powershell.exe` spawned by a non-interactive
process. Trusted installers usually create tasks from their own signed binaries,
not from an interactive shell chain.

## Result

Splunk detected both persistence tasks in a single sweep — 3 process-creation
events capturing the parent command and two `schtasks.exe` creations. The logs
preserved the full task definitions, including the SYSTEM-level startup trigger
and the `cmd.exe /c calc.exe` payload, giving a responder everything needed to
identify and remove the persistence.

## Screenshots

**Attack executed on Windows 11 target (both tasks created successfully):**
<img width="1002" alt="T1053.005 scheduled task creation on Windows 11" src="https://github.com/user-attachments/assets/c0df8d11-4a3d-4e7e-9482-4ef71831c4ff" />

**Detection in Splunk — 3 events, two schtasks /create operations:**
<img width="1915" alt="T1053.005 detection in Splunk showing two scheduled tasks created" src="https://github.com/user-attachments/assets/43fe3dd0-6a1b-42c3-aabf-b46c59e463c7" />
