# T1059.003 — Windows Command Shell (cmd.exe)

## What This Attack Does

The attacker uses cmd.exe and batch files to run malicious commands on
the target machine. CMD is built into every Windows system and is
trusted by the operating system, making it a perfect tool for attackers
to blend in with normal activity while executing their attack chain.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1059.003 -TestNumbers 1

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: C:\Windows\System32\cmd.exe
- User: WINDOWS-SERVER\Administrator
- CommandLine: cmd.exe /c whoami && ipconfig

## SPL Detection Query

index=* source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
EventCode=1 Image="*cmd.exe" CommandLine="*/c*"
| table _time, ComputerName, User, CommandLine, ParentImage

## Result

Splunk successfully detected cmd.exe execution with suspicious flags.
Alert fired within seconds of the command running on the target.

## Screenshot

<img width="1002" height="282" alt="T1059-003-windows png" src="https://github.com/user-attachments/assets/bac60d28-5a3d-4935-801a-42af5059bce3" />
<img width="1912" height="1021" alt="T1059-003-splunk png" src="https://github.com/user-attachments/assets/4f719f60-6fe6-4291-bce4-0137f1121d2d" />

