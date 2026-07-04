# T1070.004 — File Deletion (erase evidence)

**Tactic:** Defense Evasion  **Technique:** T1070.004  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

After completing their objective, the attacker deletes files they created or
dropped during the intrusion — malware, scripts, staged data, tool output — to
remove evidence and slow down forensic investigation. Deleting these artifacts
makes it harder for incident responders to reconstruct what happened and what was
taken.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows Server target (192.168.56.102):

    Invoke-AtomicTest T1070.004 -TestNumbers 4 -GetPrereqs
    Invoke-AtomicTest T1070.004 -TestNumbers 4

Test #4 ("Delete a single file — Windows cmd") first stages a test file in the
temp directory via `-GetPrereqs`, then deletes it with a forced `del`:
`cmd.exe /c del /f %temp%\deleteme_T1551.004`.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired, capturing the deletion command as it
launched:
- Image: `C:\Windows\System32\cmd.exe`
- User: `WINDOWS\khaled`
- CommandLine: `cmd.exe /c del /f %temp%\deleteme_T1551.004`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "del" OR "Remove-Item"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

This detection captures the deletion *command* at process creation
(`del` via `cmd.exe`, or `Remove-Item` via PowerShell) rather than relying solely
on Sysmon's File Delete event (Event ID 23), which requires that event type to be
enabled in the Sysmon config. Catching the command line is valuable because it
preserves *what* was deleted and *how* (`/f` force flag, target path) even if the
File Delete event isn't logged. The `%temp%` target here is a classic
anti-forensics location — attackers stage and then wipe from temp directories.

## False Positives / Tuning

`del` and `Remove-Item` run constantly in normal operations, so a bare match is
very noisy — this is the lowest-fidelity query in the set on its own. Tune hard:
scope to deletions in suspicious paths (temp, Downloads, ProgramData, user
profile), forced deletions (`del /f /q`, `Remove-Item -Force -Recurse`), a
non-interactive parent (`powershell.exe`/`cmd.exe` from automation), or deletion
of known artifact types (`.exe`, `.ps1`, `.bat`, log files). Best used as a
pivot after another alert fires — "what did they delete on the way out" — rather
than as a standalone trigger. If available, enabling Sysmon Event ID 23 gives a
cleaner, dedicated file-deletion signal to correlate against.

## Result

Splunk captured the file-deletion command at process creation, preserving the
full command line — the forced `del` and the `%temp%` target path — even without
relying on a dedicated File Delete event. This shows the deletion attempt and
exactly which artifact the attacker was trying to erase.

## Screenshots

**Attack executed on Windows Server target (stage file, then force-delete from temp):**
<img width="953" alt="T1070.004 file deletion executed on Windows Server" src="https://github.com/user-attachments/assets/c566ce55-20ee-4bed-a9d5-62005ba7252f" />

**Detection in Splunk — deletion command captured at process creation:**
<img width="1913" alt="T1070.004 detection in Splunk showing del command" src="https://github.com/user-attachments/assets/126cb50a-3716-4a26-a5e3-a66d49d28802" />
