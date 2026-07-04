# T1115 — Clipboard Data

**Tactic:** Collection  **Technique:** T1115  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker captures whatever is in the clipboard. People copy and paste
passwords, API keys, card numbers, internal URLs, and sensitive text all day, so
the clipboard is a rich, low-effort source of secrets. Because clipboard access
never touches a file on disk, it's hard to catch with file-monitoring alone —
process and command-line logging is where it shows up.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1115 -TestNumbers 1

Test #1 ("Utilize Clipboard to store or execute commands from") uses the built-in
`clip.exe` utility to move data through the clipboard — piping directory output
*into* the clipboard and reading text back *out* of it:
`dir | clip & echo "T1115" > %temp%\T1115.txt & clip < %temp%\T1115.txt`

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired 2 times:
- User: `WINDOWS\khaled`
- Parent CommandLine: `cmd.exe /c dir | clip & echo "T1115" > %temp%\T1115.txt & clip < %temp%\T1115.txt`
- Child process: `cmd.exe` running the `dir` piped to `clip`
- Parent chain: `powershell.exe` → `cmd.exe` → `clip.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "clip"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query matches `clip`, catching use of the built-in `clip.exe` clipboard
utility. The interesting behavior here is data being *piped into* `clip`
(`dir | clip`) and *read back out* (`clip < file`) — using the clipboard as a
staging channel. Note the query is broad: matching the bare string `clip` will
also hit unrelated words containing "clip", so in production you'd tighten to
`clip.exe`, `Get-Clipboard`, or `[System.Windows.Forms.Clipboard]` to reduce
noise. The higher-value signal is clipboard access from a non-interactive script
host rather than a user pressing Ctrl+C/V.

## False Positives / Tuning

`clip.exe` and `Get-Clipboard` have some legitimate use in scripting, and a broad
`clip` match is noisy. Tighten by matching `clip.exe`, `Get-Clipboard`, or the
.NET `Clipboard` class specifically, and prioritize clipboard access where the
parent is `powershell.exe`/`cmd.exe` from automation, or where clipboard content
is redirected to a file (staging for exfil). A user copying text is normal; a
script harvesting the clipboard to a temp file is not.

## Result

Splunk detected the clipboard activity across 2 process-creation events,
capturing the full pipe-through-clipboard command. The log shows the attacker
routing data into and out of the clipboard and staging it to a temp file
(`%temp%\T1115.txt`) — clipboard harvesting that leaves no obvious file-copy
trail but is fully visible at the command-line level.

## Screenshots

**Attack executed on Windows 11 target (clipboard data via clip.exe):**
<img width="946" alt="T1115 clipboard data capture on Windows 11" src="https://github.com/user-attachments/assets/6ca254b5-f140-4162-9bf9-3a783b358693" />

**Detection in Splunk — 2 events, data piped through clip.exe to temp file:**
<img width="1915" alt="T1115 detection in Splunk showing clipboard data staging" src="https://github.com/user-attachments/assets/f0d21231-e5d3-4da2-8bdd-c69ffa694c9b" />
