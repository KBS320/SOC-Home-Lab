# T1529 — System Shutdown/Reboot

## What This Attack Does

An attacker forces a system to shut down or reboot, typically as a
final step in an attack — for example, to trigger a ransomware
payload's boot-time execution, to disrupt business operations and
availability, or to cover tracks by clearing volatile memory and
active processes before investigators can capture them.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1529 -TestNumbers 1

This test runs the built-in Windows `shutdown` command to force an
immediate system shutdown.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: `C:\Windows\System32\cmd.exe`
- User: `WINDOWS\khaled`
- CommandLine: `"cmd.exe" /c shutdown /s /t 1`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

The command itself was also visually confirmed — the Windows VM
displayed a "Shutting down" screen immediately after execution,
providing direct visual proof of a successful attack alongside the
log-based detection.

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "shutdown"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Result

Splunk successfully detected the shutdown command in a single, clean
process creation event, with the full command line and process chain
preserved — confirmed further by the VM visibly shutting down
immediately after execution.

## Screenshot

<img width="945" height="991" alt="T1529-windows png" src="https://github.com/user-attachments/assets/b764d0ae-d3b1-48d8-92b5-0097bf28277d" />
<img width="1913" height="1027" alt="T1529-splunk png" src="https://github.com/user-attachments/assets/f7e32f0f-c6e7-480a-810e-bac859cd6cac" />
