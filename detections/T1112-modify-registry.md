# T1112 — Modify Registry

**Tactic:** Defense Evasion  **Technique:** T1112  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker modifies the Windows registry to change system behavior in their
favor — disabling security features, weakening settings, or hiding artifacts.
Registry edits are a versatile evasion tool: the same `reg add` mechanism used
here to hide file extensions is the one attackers use to disable Defender, weaken
UAC, or plant persistence. Small registry tweaks can quietly reshape how the
system behaves and what a user or defender can see.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1112 -TestNumbers 1

Test #1 ("Modify Registry of Current User Profile — cmd") sets the `HideFileExt`
value so Windows Explorer hides known file extensions — a common trick to make a
malicious `invoice.pdf.exe` look like a harmless `invoice.pdf`:
`reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /t REG_DWORD /v HideFileExt /d 1 /f`
The operation completed successfully (exit code 0).

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 2 times:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /t REG_DWORD /v HideFileExt /d 1 /f`
- Child process: `reg.exe` executing the `reg add ...HideFileExt /d 1 /f`
- Parent chain: `powershell.exe` → `cmd.exe` → `reg.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "reg add" "Advanced"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

This query catches the registry change at the command level — `reg add` targeting
the Explorer `Advanced` key — rather than relying solely on Sysmon's Registry
Value Set event (Event ID 13). Catching the `reg add` command preserves the full
edit (`/v HideFileExt /d 1 /f`) so an analyst can see exactly what was changed and
why. The `HideFileExt = 1` change specifically is a known evasion enabler: it
makes double-extension malware look legitimate. In production you'd broaden the
same logic to alert on `reg add` against known-sensitive keys (Defender policy,
UAC, Run keys, firewall).

## False Positives / Tuning

Users and software legitimately change Explorer preferences, so `HideFileExt`
alone is low-severity. The higher-value detections use the same `reg add` pattern
against security-relevant keys: `...Windows Defender\DisableAntiSpyware`,
`...Policies\System\EnableLUA` (UAC), `...CurrentVersion\Run` (persistence), and
firewall policy keys. Prioritize registry edits made by `reg.exe` spawned from a
script host (`powershell.exe`/`cmd.exe`) over interactive UI changes, and pair
this with Event ID 13 monitoring for a second, complementary view of the same
change.

## Result

Splunk captured the registry modification across 2 process-creation events,
preserving the full `reg add` command and the exact value changed
(`HideFileExt = 1`). This shows the evasion edit clearly at the command level,
independent of whether the dedicated Registry Value Set event was enabled.

## Screenshots

**Attack executed on Windows 11 target (registry modification via reg add):**
<img width="937" alt="T1112 registry modification on Windows 11" src="https://github.com/user-attachments/assets/7f290611-7f24-4812-bffa-0f93274a9151" />

**Detection in Splunk — 2 events, reg add to Explorer Advanced key:**
<img width="1912" alt="T1112 detection in Splunk showing reg add HideFileExt" src="https://github.com/user-attachments/assets/c8f5bfa2-7016-44a7-a5a2-844f51b0d90a" />
