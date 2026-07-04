# T1518.001 — Security Software Discovery

## What This Attack Does

Before deploying malware or attempting to evade detection, an
attacker checks what security tools are already running on the
system — antivirus, EDR, firewall status, and monitoring agents.
This lets them tailor their approach: choosing techniques known to
bypass specific security products, or aborting the attack on a
heavily-monitored machine to avoid detection.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1518.001 -TestNumbers 1

This test runs a chained discovery sweep covering multiple angles at
once: firewall status and configuration (via `netsh advfirewall`),
Windows Defender service status (via `sc query windefend`), a check
for the Sysmon process itself, and a `tasklist` scan piped through
`findstr` specifically searching for known AV/EDR product names
("virus," "cb," "defender," "cylance," "mc").

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 24 times, capturing the
full discovery chain. The first event shows the entire attack in one
command line:
- Image: `C:\Windows\System32\cmd.exe`
- User: `WINDOWS\khaled`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- CommandLine (full chain):
  `netsh.exe advfirewall show allprofiles`
  `netsh.exe advfirewall firewall dump`
  `netsh.exe advfirewall show currentprofile`
  `netsh.exe advfirewall firewall show rule name=all`
  `netsh.exe firewall show state`
  `netsh.exe firewall show config`
  `sc query windefend`
  `powershell.exe /c "Get-Process | Where-Object { $_.ProcessName -eq 'Sysmon' }"`
  `powershell.exe /c "Get-Service | where-object {$_.DisplayName -like '*sysm*'}"`
  `powershell.exe /c "Get-CimInstance Win32_Service -Filter 'Description = ''System Monitor service'''"`
  `tasklist.exe | findstr /i virus`
  `tasklist.exe | findstr /i cb`
  `tasklist.exe | findstr /i defender`
  `tasklist.exe | findstr /i cylance`
  `tasklist.exe | findstr /i mc`
  `tasklist.exe | findstr /i "virus cb defender cylance mc"`

The remaining 23 events show each `netsh.exe` call spawning as its
own child process of `cmd.exe`.

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "netsh"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Result

Splunk successfully detected the complete security software discovery
sweep across 24 process creation events, capturing the full chain of
firewall checks, Defender status queries, a Sysmon self-check, and a
targeted `tasklist`/`findstr` scan for known AV/EDR product names —
demonstrating full visibility into a multi-step defensive-evasion
reconnaissance attempt.

## Screenshot

<img width="865" height="113" alt="T1518-windows png" src="https://github.com/user-attachments/assets/22abad50-e120-4b42-bdf5-35a418eb8ed3" />
<img width="1915" height="1020" alt="T1518-splunk(1) png" src="https://github.com/user-attachments/assets/7c0896d3-86f7-4a20-a821-b68b1cc43848" />
<img width="1911" height="1030" alt="T1518-splunk(2) png" src="https://github.com/user-attachments/assets/766a3a30-094a-4594-a478-7c9121b0e48a" />
<img width="1907" height="1028" alt="T1518-splunk(3) png" src="https://github.com/user-attachments/assets/54ccef53-49a7-48ad-9023-7d5e13bcd81a" />
