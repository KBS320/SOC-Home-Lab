# T1112 — Modify Registry (disable security)

## What This Attack Does

The attacker modifies Windows registry settings to disable security
features like Windows Defender, UAC, or firewall rules. By tampering
with the registry they can turn off the very tools designed to catch
them, making their subsequent actions much harder to detect. This is
a critical step before deploying ransomware or other destructive tools.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1112 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 13 (Registry Value Set) fired showing:
- TargetObject: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware
- Details: 1
- User: WINDOWS-SERVER\Administrator

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=13 TargetObject="*Windows Defender*"
| table _time, ComputerName, User, TargetObject, Details

## Result

Splunk successfully detected registry modification targeting security tools.
Alert fired within seconds of the registry change on the target.

## Screenshot

[Splunk alert screenshot — to be added]
