# T1057 — Process Discovery (tasklist)

## What This Attack Does

The attacker runs tasklist to see every process currently running on the
machine. This helps them identify security tools like antivirus or EDR
agents running in the background, and also shows them what software is
installed and active. If they spot a security tool they will try to
kill it before moving further.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1057 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\tasklist.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: tasklist

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*tasklist.exe"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected tasklist execution.
Alert fired within seconds of the command running on the target.

## Screenshot

[Splunk alert screenshot — to be added]
