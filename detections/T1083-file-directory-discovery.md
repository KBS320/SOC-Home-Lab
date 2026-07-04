# T1083 — File and Directory Discovery (Get-ChildItem)

**Tactic:** Discovery  **Technique:** T1083  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker walks the file system to map out what files and folders exist —
hunting for sensitive documents, config files, credentials, databases, or
anything worth stealing. A recursive listing gives them a full inventory of the
machine's data in one shot, which they use to decide what to collect and
exfiltrate.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1083 -TestNumbers 2

Test #2 ("File and Directory Discovery — PowerShell") performs a recursive
directory walk using three equivalent PowerShell commands:
`ls -recurse`, `get-childitem -recurse`, and `gci -recurse`
(`ls` and `gci` are both aliases for `Get-ChildItem`).

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired once, capturing the full script block:
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `WINDOWS\khaled`
- CommandLine: `powershell.exe & {ls -recurse; get-childitem -recurse; gci -recurse}`
- ParentImage: `powershell.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "Get-ChildItem"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query matches `Get-ChildItem` in the command line. An important tuning point
lives right here: `Get-ChildItem` has aliases (`gci`, `ls`, `dir` inside
PowerShell), so a query keyed only on the full cmdlet name would **miss** the
`ls -recurse` and `gci -recurse` forms — yet this single event contains all
three. In practice you'd search for the aliases too. The stronger behavioral
signal isn't the cmdlet itself but the `-recurse` flag combined with a broad
starting path: a full recursive tree walk is enumeration, not someone listing one
folder.

## False Positives / Tuning

Directory listing is one of the most common operations on any system, so this is
low-fidelity on its own. Tune by keying on recursion over broad scopes
(`-recurse` from `C:\`, user profile, or network shares), listings piped to a
file (staging for exfil), or a non-interactive parent. Cover the alias set —
`Get-ChildItem`, `gci`, `ls`, and cmd's `dir /s` — so an attacker can't evade the
rule just by using a shorter alias. A single folder listing is noise; a
recursive sweep of the whole drive is worth a look.

## Result

Splunk detected the recursive file-and-directory enumeration in a single
process-creation event, capturing all three alias forms of the command. The log
confirms the attacker performed a full recursive walk of the file system to
inventory available data on the target.

## Screenshots

**Attack executed on Windows 11 target (recursive directory walk):**
<img width="997" alt="T1083 recursive directory discovery on Windows 11" src="https://github.com/user-attachments/assets/c4268dc5-26e1-451e-a459-7a0e3800b572" />

**Detection in Splunk — Get-ChildItem recursive walk captured in one event:**
<img width="1917" alt="T1083 detection in Splunk showing recursive Get-ChildItem" src="https://github.com/user-attachments/assets/3d063238-2ae8-4227-beac-902eb5c55425" />
