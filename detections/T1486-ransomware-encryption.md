# T1486 — Data Encrypted for Impact (Akira Ransomware Simulation)

## What This Attack Does

Ransomware encrypts files on a victim's system to make them
inaccessible, then demands payment in exchange for a decryption key.
Beyond just encrypting data, many modern ransomware groups also drop
a ransom note explaining the demand and providing instructions for
contacting the attackers — often including threats about leaked data
or destroyed backups to pressure the victim into paying quickly.

## How I Simulated It

Tool: Atomic Red Team
Command executed on Windows Server target: 

Invoke-AtomicTest T1486 -TestNumbers 10

Note: Tests #1–9 in this technique are Linux/macOS-only or require
third-party encryption tools (GPG4Win, DiskCryptor) that weren't
available in this lab. Test #10 simulates the Akira ransomware
strain and runs natively on Windows using built-in PowerShell —
no additional tools required.

This test drops 100 files containing random byte content with a
`.akira` extension to `C:\`, simulating encrypted files, and writes
an Akira-style ransom note to the desktop (`akira_readme.txt`).

## What Splunk Captured

Sysmon Event ID 1 (Process Creation) fired showing the complete
attack script in a single event:
- Image: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- User: `WINDOWS\khaled`
- ParentImage: `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- CommandLine (key portions):
  `(new-object Random).NextBytes($out); [IO.File]::WriteAllBytes(\"c:\test.$_.akira\", $out)`
  `echo \"Whatever who you are and what your title is if you're reading this it means the internal infrastructure of your company is fully or partially dead...\" >> $env:Userprofile\Desktop\akira_readme.txt`

The single event captures both stages of the simulated attack: the
file-encryption-style byte writes with the `.akira` extension, and
the full ransom note being written line by line.

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

## Result

Splunk successfully detected the full ransomware simulation in a
single process creation event, capturing both the file-corruption
logic (random bytes written with a `.akira` extension) and the
ransom note text being written to disk — giving complete visibility
into both phases of the attack from one log entry.

## Screenshot

<img width="870" height="268" alt="T1486-windows png" src="https://github.com/user-attachments/assets/9429ec0d-059c-420c-80da-9285242e060e" />
<img width="1913" height="1028" alt="T1486-splunk png" src="https://github.com/user-attachments/assets/80e13a50-5259-4b5b-9fe3-f0dc17627b51" />
