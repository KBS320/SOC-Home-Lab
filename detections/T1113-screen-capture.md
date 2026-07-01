# T1113 — Screen Capture

## What This Attack Does

The attacker takes screenshots of the victim's desktop to see exactly
what the user is doing — open documents, emails, browser sessions,
internal applications, and sensitive data displayed on screen.
This is a powerful surveillance technique that captures information
that might not exist anywhere in files on disk, like a banking portal
open in a browser or a password manager unlocked on screen.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1113 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: powershell.exe Add-Type -Assembly System.Windows.Forms screenshot

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 CommandLine="*screenshot*" OR CommandLine="*Screen.PrimaryScreen*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected screen capture activity.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
