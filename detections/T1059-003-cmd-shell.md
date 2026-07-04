# T1059.003 — Windows Command Shell (cmd.exe)

**Tactic:** Execution  **Technique:** T1059.003  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker uses `cmd.exe` and batch scripts to run commands on the target. CMD
is built into every Windows system and trusted by the OS, so attackers use it to
blend in with normal activity while executing their attack chain — often
launching a `.bat` payload dropped elsewhere on disk.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows Server target (192.168.56.102):

    Invoke-AtomicTest T1059.003 -TestNumbers 1

Test #1 ("Create and Execute Batch Script") attempts to launch a batch payload
from the ExternalPayloads folder via `Start-Process`. In this run the payload
file (`T1059.003_script.bat`) was not staged, so `Start-Process` failed with
"the system cannot find the file specified." The launch *attempt* was still
generated and logged — the same forensic trail an attacker leaves when a payload
is missing, blocked, or already cleaned up.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 3 times:
- User: `WINDOWS\khaled`
- CommandLine (key portion):
  `powershell.exe & {Start-Process "C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1059.003_script.bat"}`
- Image / ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "T1059"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

This search string (`T1059`) matched the test's own payload path for the lab
demo. In production you wouldn't hunt on the technique ID — you'd key on the real
behavioral signature: `Start-Process` (or a `cmd.exe` parent) launching a `.bat`
file from an unusual location such as a temp, Downloads, or a `..`-traversal
path. The tell here is a script host (`powershell.exe`) spawning a batch payload
outside normal software directories — legitimate apps rarely run `.bat` files
that way.

## False Positives / Tuning

`cmd.exe` and batch execution are extremely common in normal operations, so a
broad `cmd.exe /c` match floods the SOC. The higher-fidelity approach: alert on
batch/script execution from suspicious paths (temp dirs, user profile,
`ExternalPayloads`, `..` traversal), on a script host launching `.bat`/`.cmd`
with an unusual parent, or on the failure itself — repeated "file not found"
launch attempts can indicate a broken or partially-cleaned intrusion. Baseline
your environment's legitimate batch jobs first so those can be excluded.

## Result

Splunk captured the batch-execution attempt across 3 process-creation events even
though the payload file was missing and `Start-Process` failed. This demonstrates
that failed or blocked execution attempts still leave a clear, searchable trail
in process-creation logs — often the first sign that something tried to run.

## Screenshots

**Attack executed on Windows Server target (batch payload not found, Start-Process fails):**
<img width="1002" alt="T1059.003 batch script execution attempt on Windows Server" src="https://github.com/user-attachments/assets/bac60d28-5a3d-4935-801a-42af5059bce3" />

**Detection in Splunk — 3 events from the batch execution attempt:**
<img width="1912" alt="T1059.003 detection in Splunk showing batch script launch attempt" src="https://github.com/user-attachments/assets/4f719f60-6fe6-4291-bce4-0137f1121d2d" />
