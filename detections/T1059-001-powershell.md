# T1059.001 — PowerShell Encoded Commands

**Tactic:** Execution  **Technique:** T1059.001  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker runs PowerShell with a Base64-encoded command (`-EncodedCommand` /
`-e`) to hide what's actually being executed. Encoding obscures the real command
from casual log review and simple keyword blocks. It's one of the most common
techniques used by malware and ransomware in the wild, because PowerShell is
built into every Windows machine and trusted by the OS.

## How I Simulated It

Tool: Manual PowerShell execution
Note: Atomic Red Team Test 1 (Mimikatz) was blocked by Windows Defender, so a
manual Base64-encoded PowerShell command was run instead to demonstrate the
encoding technique cleanly.

Command executed on the Windows target (192.168.56.102):

    powershell -e aQBwAGMAbwBuAGYAZwA=

Decoded (UTF-16LE Base64), this resolves to `ipconfg` — a benign stand-in
payload. The point of the demo is the *encoded execution*, not the payload
itself: an attacker would swap in any command here, and it would look identical
in the logs.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired once:
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `WINDOWS\khaled`
- CommandLine: `powershell.exe -e aQBwAGMAbwBuAGYAZwA=`
- ParentImage: `powershell.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "powershell" "-e"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on `powershell` together with the `-e` flag — the short form of
`-EncodedCommand`. This is high-value because there's rarely a legitimate reason
for interactive admins to launch PowerShell with a Base64 blob; encoded execution
is strongly associated with malware and offensive tooling. The Base64 payload
itself sits right in the captured CommandLine, so an analyst can decode it
straight from the log to see what the attacker actually intended to run.

## False Positives / Tuning

Some legitimate management tools and installers use `-EncodedCommand`, so it's
not zero-noise. Reduce false positives by matching the flag variants precisely
(`-e`, `-en`, `-enc`, `-EncodedCommand`), flagging encoded commands from an
unusual parent (Office apps, `wscript`, `mshta`), and — the high-fidelity move —
decoding the Base64 at search time and alerting on suspicious decoded content
(`IEX`, `DownloadString`, `FromBase64String`, `-nop -w hidden`). An encoded
command that decodes to a download-and-execute is far more actionable than the
flag alone.

## Result

Splunk detected the encoded PowerShell execution in a single process-creation
event, capturing the full `-e` command line including the Base64 payload — which
can be decoded directly from the log to reveal the underlying command.

## Screenshots

**Attack executed on Windows target (encoded PowerShell command):**
<img width="1002" alt="T1059.001 encoded PowerShell command executed" src="https://github.com/user-attachments/assets/8c355721-362e-4049-8ac9-c5aa04813d88" />

**Detection in Splunk — encoded PowerShell captured in one event:**
<img width="1915" alt="T1059.001 detection in Splunk showing encoded PowerShell" src="https://github.com/user-attachments/assets/79f947c8-f796-456c-82f7-54b29d87d49a" />
