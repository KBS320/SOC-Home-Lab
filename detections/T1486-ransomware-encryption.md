# T1486 — Data Encrypted for Impact (Akira Ransomware Simulation)

**Tactic:** Impact  **Technique:** T1486  **Log Source:** Sysmon (XmlWinEventLog) — Process Creation

## What This Attack Does

Ransomware encrypts a victim's files to make them inaccessible, then demands
payment for a decryption key. Modern ransomware groups also drop a ransom note
explaining the demand and how to contact the attackers — usually with threats
about leaked data or destroyed backups to pressure fast payment. This is the
Impact stage: the point where a quiet intrusion becomes a business emergency.

## How I Simulated It

Tool: Atomic Red Team
Command executed on the Windows 11 target (192.168.56.102):

    Invoke-AtomicTest T1486 -TestNumbers 10

Note: Tests #1–9 are Linux/macOS-only or require third-party encryption tools
(GPG4Win, DiskCryptor) not installed in this lab. Test #10 simulates the **Akira**
ransomware strain and runs natively on Windows using built-in PowerShell — no
extra tooling required.

The test writes files filled with random bytes and a `.akira` extension
(`c:\test.<n>.akira`), simulating encrypted files, and writes an Akira-style
ransom note to the desktop (`akira_readme.txt`).

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired once, capturing the entire attack
script in a single event:
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `WINDOWS\khaled`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- CommandLine (key portions):
  - Encryption sim: `1..100 | ForEach-Object { $out = new-object byte[] 1073741; (new-object Random).NextBytes($out); [IO.File]::WriteAllBytes("c:\test.$_.akira", $out) }`
  - Ransom note: repeated `echo "..." >> $env:Userprofile\Desktop\akira_readme.txt` lines writing the full Akira note, including the `.onion` contact link

The single event captures both stages: the byte-writes producing `.akira` files
and the complete ransom note being written line by line.

## SPL Detection Query

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" "akira_readme"
| rex field=_raw "Name='Image'>(?P<Image>[^<]+)"
| rex field=_raw "Name='CommandLine'>(?P<CommandLine>[^<]+)"
| rex field=_raw "Name='ParentImage'>(?P<ParentImage>[^<]+)"
| rex field=_raw "Name='User'>(?P<User>[^<]+)"
| rex field=_raw "Name='UtcTime'>(?P<UtcTime>[^<]+)"
| table UtcTime, User, Image, CommandLine, ParentImage
```

## Detection Logic

This query keys on `akira_readme` — the ransom-note filename, which is a specific,
high-fidelity indicator tied to the Akira strain. Because the whole attack landed
in one process-creation event, the command line alone reveals both halves: the
`WriteAllBytes` loop creating `.akira` files and the ransom-note text. In a real
environment you'd detect ransomware on **behavior**, not one note name: mass file
writes/renames to a uniform new extension in a short window, `WriteAllBytes` /
`Set-Content` loops over many files, ransom-note filenames (`*_readme.txt`,
`*.onion` references), and shadow-copy deletion (`vssadmin delete shadows`). The
note name is the easy catch; the write-volume pattern is the durable one.

## False Positives / Tuning

Near-zero false positives on the `akira_readme` / `.akira` indicators themselves —
no legitimate process creates those. The behavioral detections need tuning: a
threshold on file-modification volume (e.g. >N files changed to the same new
extension per minute per host), which requires file-monitoring (Sysmon Event ID 11)
alongside process creation. Pair this with detections for shadow-copy deletion and
backup tampering, since real ransomware destroys recovery options right before or
after encryption. Given the impact, these should be your highest-severity,
fastest-notify rules.

## Result

Splunk detected the full ransomware simulation in a single process-creation
event, capturing both the file-corruption logic (random bytes written with a
`.akira` extension) and the complete ransom note written to disk. One log entry
gave full visibility into both phases of the attack — the encryption behavior and
the extortion message, including the `.onion` contact.

## Screenshots

**Attack executed on Windows 11 target (Akira ransomware simulation):**
<img width="870" alt="T1486 Akira ransomware simulation on Windows 11" src="https://github.com/user-attachments/assets/9429ec0d-059c-420c-80da-9285242e060e" />

**Detection in Splunk — full attack (file writes + ransom note) in one event:**
<img width="1913" alt="T1486 detection in Splunk showing Akira ransomware and ransom note" src="https://github.com/user-attachments/assets/80e13a50-5259-4b5b-9fe3-f0dc17627b51" />
