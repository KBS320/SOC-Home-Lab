# T1113 — Screen Capture

**Tactic:** Collection  **Technique:** T1113  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

The attacker captures screenshots of the victim's desktop to see exactly what the
user is doing — open documents, emails, browser sessions, internal apps, and
sensitive data on screen. It's a powerful surveillance technique because it grabs
information that may exist nowhere on disk: a banking portal open in a browser, a
password manager unlocked, an internal dashboard. The captured image is typically
saved locally and then staged for exfiltration.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1113 -TestNumbers 8

Test #8 ("Windows Screen Capture — CopyFromScreen") uses PowerShell and the
.NET `System.Windows.Forms` library to capture the full virtual screen into a
bitmap and save it to disk:
`$graphic.CopyFromScreen(...)` then `$bitmap.Save("$env:TEMP\T1113.png")`.

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired once, capturing the full capture
script:
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `WINDOWS\khaled`
- CommandLine (key portions):
  `Add-Type -AssemblyName System.Windows.Forms`,
  `$graphic.CopyFromScreen($screen.Left, $screen.Top, 0, 0, $bitmap.Size)`,
  `$bitmap.Save("$env:TEMP\T1113.png")`
- ParentImage: `powershell.exe`

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "CopyFromScreen"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

The query keys on `CopyFromScreen` — the specific .NET method that copies pixels
off the display into a bitmap. This is high-fidelity: there is essentially no
legitimate interactive reason for a PowerShell session to call `CopyFromScreen`
and save an image. Related indicators worth covering are `System.Windows.Forms` /
`System.Drawing` being loaded via `Add-Type`, and a `.Save(...)` writing a `.png`
to a temp path. Because the entire capture routine lands in one process-creation
event, the command line alone shows both the capture and the output file path.

## False Positives / Tuning

Almost none from `CopyFromScreen` in a PowerShell command line — legitimate apps
that screenshot do it in compiled code, not ad-hoc PowerShell. Broaden coverage
rather than tighten: also flag `[System.Drawing.Bitmap]`, `PrintWindow`,
`BitBlt`, and screenshot utilities spawned by unusual parents. Enrich by pulling
the output path from the command line (here, `$env:TEMP\T1113.png`) — a saved
image in a temp directory is a strong staging indicator, and correlating it with
a later archive (T1560) or exfil (T1041) event confirms the collection-to-exfil
chain.

## Result

Splunk detected the screen-capture activity in a single process-creation event,
capturing the full PowerShell routine — the `CopyFromScreen` call and the
`.Save()` to `$env:TEMP\T1113.png`. The log reveals both the surveillance action
and exactly where the captured image was written on disk.

## Screenshots

**Attack executed on Windows 11 target (PowerShell screen capture):**
<img width="940" alt="T1113 screen capture executed on Windows 11" src="https://github.com/user-attachments/assets/b552aa33-5519-44ba-a56b-98e87d305d0c" />

**Detection in Splunk — CopyFromScreen capture routine in one event:**
<img width="1913" alt="T1113 detection in Splunk showing CopyFromScreen screen capture" src="https://github.com/user-attachments/assets/b9157166-2f79-44ee-97d3-404cf64a354e" />
