# T1547.001 — Registry Run Keys (reg run key)

## What This Attack Does

The attacker adds an entry to the Windows registry Run key so their
malicious program launches automatically every time any user logs in.
The Run key is designed to start legitimate programs at login, but
attackers abuse it to ensure their malware always comes back after
a reboot or logout. This is one of the oldest and most reliable
persistence tricks in the attacker playbook.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1547.001 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 13 (Registry Value Set) fired showing:
- TargetObject: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
- Details: malicious.exe
- User: WINDOWS-SERVER\Administrator

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
| table _time, ComputerName, User, TargetObject, Details

## Result

Splunk successfully detected registry run key modification.
Alert fired within seconds of the registry change on the target.

## Screenshot

[Splunk alert screenshot — to be added]
