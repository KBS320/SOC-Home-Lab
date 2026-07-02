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

<img width="1007" height="313" alt="T1057-windows png" src="https://github.com/user-attachments/assets/f0c57f68-30c9-4dfb-ae10-2920b08c9688" />
<img width="1917" height="932" alt="T1057-splunk" src="https://github.com/user-attachments/assets/6dfaffec-4ecb-4e23-8818-531738be8b70" />


