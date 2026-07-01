# T1201 — Password Policy Discovery

## What This Attack Does

The attacker queries the domain or local password policy to understand
the password rules in place — minimum length, complexity requirements,
lockout thresholds. Knowing that accounts lock out after 5 failed attempts
tells the attacker to be careful with brute force. Knowing passwords only
need to be 6 characters tells them the passwords are probably weak and
worth cracking.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1201 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\net.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: net accounts

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*net.exe" CommandLine="*accounts*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected password policy enumeration.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
