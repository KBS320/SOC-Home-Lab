# T1033 — System Owner/User Discovery (whoami)

**Tactic:** Discovery  **Technique:** T1033  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker runs `whoami` to find out which account they're operating under on
the compromised machine. This tells them their privilege level — regular user,
local admin, or SYSTEM. It's almost always one of the first commands run after
gaining access, and it's often followed immediately by other identity-discovery
tools (`wmic useraccount`, `quser`, `qwinsta`) to map who else is logged on.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows Server target (192.168.56.102):

    Invoke-AtomicTest T1033 -TestNumbers 1

The test runs `whoami` first, then chains several other user-discovery commands
through `cmd.exe`: `wmic useraccount get /ALL`, `quser`, and `qwinsta`. On this
Windows Server build, `wmic`, `quser`, and `qwinsta` were not installed, so those
sub-commands returned "not recognized" and the test exited with code 1 — but the
`whoami` portion ran successfully and every attempted command was still logged.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 6 times across the test:
- User: `WINDOWS\khaled`
- Direct execution: `whoami.exe` spawned by `powershell.exe`
- Chained command via `cmd.exe`:
  `cmd.exe /C whoami & wmic useraccount get /ALL & quser /SERVER:"localhost" & quser & qwinsta.exe /server:localhost ...`
- Follow-on: `cmd.exe /C whoami`, and `qwinsta /server:localhost | findstr "Active Disc"`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "whoami"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query matches any Sysmon event containing the string `whoami`, then uses
`rex` to pull Image, CommandLine, ParentImage, and User from the raw XML. A lone
`whoami` is extremely common and low-fidelity on its own. The stronger signal
here is the **ParentImage chain**: `powershell.exe` → `cmd.exe` → `whoami`, plus
the same parent attempting `wmic`, `quser`, and `qwinsta` in one burst. That
pattern — scripted identity discovery, not an admin typing one command — is what
makes this worth investigating.

## False Positives / Tuning

`whoami` runs constantly during legitimate admin work and login scripts, so
alerting on it alone would flood the SOC. Tune by: keying on a non-interactive
parent (`powershell.exe` or `cmd.exe` from an automated process), or correlating
`whoami` with other identity-discovery commands (`wmic useraccount`, `quser`,
`qwinsta`, `net user`) from the same parent inside a short window. The failed
`wmic`/`quser`/`qwinsta` attempts are themselves a useful tell — real attackers
often probe for tools that may not be present.

## Result

Splunk detected the full identity-discovery sequence — 6 process-creation events
from the `whoami` run and its chained `cmd.exe` commands. Even the sub-commands
that failed ("not recognized", exit code 1) left a clear forensic trail,
demonstrating that failed attacker actions are still fully visible in logs.

## Screenshots

**Attack executed on Windows Server target (whoami runs; wmic/quser/qwinsta not present):**
<img width="982" alt="T1033 whoami test executed on Windows Server" src="https://github.com/user-attachments/assets/205f9119-a52d-4f60-a2ed-e1eda45d745c" />

**Detection in Splunk — 6 events from the whoami discovery chain:**
<img width="1913" alt="T1033 detection in Splunk showing whoami discovery chain" src="https://github.com/user-attachments/assets/0b0f602a-55d9-43f0-ac01-9a0bc6efe168" />
