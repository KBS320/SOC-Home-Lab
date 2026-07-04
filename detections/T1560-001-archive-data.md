# T1560.001 — Archive Collected Data (zip files)

## What This Attack Does

Before exfiltrating stolen data, the attacker compresses and archives
all the files they collected into a zip or archive file. This serves
two purposes — it makes the data smaller and faster to transfer, and
it can also help bypass data loss prevention tools that scan individual
files but might miss packed archives. This is the final preparation
step before the data leaves the network.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target: Invoke-AtomicTest T1560.001 -TestNumbers 11

Note: Test #1 (WinRAR-based) requires WinRAR to be installed, which
wasn't available in this lab environment due to no internet access on
the Windows host. Used Test #11 instead, which relies on `makecab.exe` —
a built-in Windows utility — to achieve the same technique.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing:
- Image: `C:\Windows\System32\cmd.exe`
- User: `WINDOWS\khaled`
- CommandLine: `"cmd.exe" /c makecab.exe C:\Temp\sam.hiv C:\Temp\art.zip`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

A second event shows `makecab.exe` launching as its own process.

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

## Result

Splunk successfully detected the archive creation activity via
`makecab.exe`, captured as a child process of `cmd.exe`, itself spawned
from `powershell.exe`.

## Screenshot

<img width="942" height="478" alt="T1560 001-windows png" src="https://github.com/user-attachments/assets/f8b48291-f6a8-4b49-8c52-b301a21e3aa3" />
<img width="1913" height="1028" alt="T1560 001-splunk png" src="https://github.com/user-attachments/assets/00f7d221-47bb-43be-b62a-67c0aa944db1" />


