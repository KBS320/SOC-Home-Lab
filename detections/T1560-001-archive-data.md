# T1560.001 — Archive Collected Data (makecab)

**Tactic:** Collection  **Technique:** T1560.001  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

Before exfiltrating stolen data, the attacker compresses and archives what they
collected into a single file. This serves two purposes: it shrinks the data for a
faster, quieter transfer, and it can help slip past data-loss-prevention tools
that scan individual files but miss packed archives. Archiving is the final
staging step before data leaves the network — the bridge between Collection and
Exfiltration.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1560.001 -TestNumbers 11

Note: Test #1 (WinRAR-based) requires WinRAR, which wasn't installed in this lab.
Test #11 achieves the same technique using `makecab.exe` — a built-in Windows
utility — to compress a file into a cabinet archive. Notably, the file being
archived here is `sam.hiv`: a copy of the **SAM registry hive**, which holds local
password hashes. Archiving the SAM is a classic pre-exfil move for offline
credential cracking.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 2 times:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c makecab.exe C:\Temp\sam.hiv C:\Temp\art.zip`
- Child process: `makecab.exe` compressing `C:\Temp\sam.hiv` into `C:\Temp\art.zip`
- Parent chain: `powershell.exe` → `cmd.exe` → `makecab.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "makecab"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on `makecab`, a legitimate but frequently-abused LOLBin for
compressing data. Two things raise the signal here: the parent chain
(`powershell.exe` → `cmd.exe` → `makecab.exe`, i.e. scripted rather than an
installer using it) and — most tellingly — *what* is being archived. Compressing
`sam.hiv` (the SAM hive) is a strong indicator on its own, since there's no benign
reason to cab-compress a password-hash database. In production you'd cover the
whole archiving family: `makecab`, `Compress-Archive`, `tar.exe`, and third-party
tools (`7z`, `rar`), especially when the source is a sensitive file or the output
lands in a staging directory.

## False Positives / Tuning

`makecab` and `Compress-Archive` have legitimate uses (log bundling, packaging),
so don't alert on the tool alone. Prioritize: sensitive source files (registry
hives, credential stores, document repositories), output written to temp/staging
directories, a non-interactive parent, and — the strongest signal — archiving that
sits between a Collection event (T1113 screenshot, T1120 hardware inventory, mass
file reads) and an Exfiltration event (T1041) on the same host in a short window.
That Collection → Archive → Exfil sequence is the pattern worth alerting on, not
any single compress command.

## Result

Splunk detected the archive-creation activity across 2 process-creation events,
capturing `makecab.exe` compressing `sam.hiv` into `art.zip`. The log preserves
both the tool and the sensitive source file, confirming the attacker staged a copy
of the SAM hive for exfiltration — the archiving step that bridges collection and
data theft.

## Screenshots

**Attack executed on Windows 11 target (makecab archiving the SAM hive):**
<img width="942" alt="T1560.001 archive collected data via makecab on Windows 11" src="https://github.com/user-attachments/assets/f8b48291-f6a8-4b49-8c52-b301a21e3aa3" />

**Detection in Splunk — 2 events, makecab compressing sam.hiv to art.zip:**
<img width="1913" alt="T1560.001 detection in Splunk showing makecab archive creation" src="https://github.com/user-attachments/assets/00f7d221-47bb-43be-b62a-67c0aa944db1" />
