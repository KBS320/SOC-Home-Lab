# T1070.003 — Clear Command History

**Tactic:** Defense Evasion  **Technique:** T1070.003  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker deletes the PowerShell command-history file to erase the record of
what they ran on the machine. PowerShell's PSReadLine module saves every command
to a history file on disk (`ConsoleHost_history.txt`); removing that file is like
wiping fingerprints off a crime scene, making it much harder for incident
responders to reconstruct the attacker's actions.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1070.003 -TestNumbers 12

Test #12 ("Clear PowerShell History by Deleting History File") deletes the
PSReadLine history file by resolving its path and removing it:
`Remove-Item (Get-PSReadlineOption).HistorySavePath`.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired once:
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `WINDOWS\khaled`
- CommandLine: `powershell.exe & {Remove-Item (Get-PSReadlineOption).HistorySavePath}`
- ParentImage: `powershell.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "HistorySavePath"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on `HistorySavePath` — the property that resolves the PSReadLine
history file location. This is high-fidelity: there is almost no legitimate
reason to programmatically resolve and delete the history file. Combined with
`Remove-Item`, `Clear-History`, or `Set-PSReadlineOption -HistorySaveStyle
SaveNothing`, it's a strong anti-forensics signal. Because the intent is to
destroy evidence, catching it depends on logging the command *before* the history
is wiped — which Sysmon process-creation does, since the command itself is the
event.

## False Positives / Tuning

Almost none by design — deleting the history file isn't part of normal admin
work. Broaden coverage rather than tighten it: also alert on `Clear-History`,
`Set-PSReadlineOption -HistorySaveStyle SaveNothing`, and direct
`Remove-Item`/`del` targeting `ConsoleHost_history.txt`. Treat any of these as a
high-priority anti-forensics indicator, and pivot on the same user/host to see
what activity they were trying to hide immediately beforehand.

## Result

Splunk captured the history-deletion command in a single process-creation event
— the command line was logged the instant the process launched, before the
history file was removed. This shows that even anti-forensics actions leave a
trail when process-creation logging is in place, and gives a responder a pivot
point to investigate what the attacker was covering up.

## Screenshots

**Attack executed on Windows 11 target (delete PowerShell history file):**
<img width="947" alt="T1070.003 clear PowerShell history on Windows 11" src="https://github.com/user-attachments/assets/43b9c821-bc44-49a0-bbb3-85e59ca1da1a" />

**Detection in Splunk — history-file deletion captured in one event:**
<img width="1917" alt="T1070.003 detection in Splunk showing history file deletion" src="https://github.com/user-attachments/assets/0fa3e6ab-b030-4026-a4c5-bcca44a20d9d" />
