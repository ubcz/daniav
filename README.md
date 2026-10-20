# DaniAV 2.0

Full-system Windows security scanner and monitor. Every detection has a name
(for example `HEUR:Disguised.DoubleExtension`, `Ransom.Behavior.ShadowCopyDelete`,
`HackTool.Win32.Mimikatz`) so you can see exactly what matched and why.

Repository: https://github.com/ubcz/daniav

## Run

Double click `DaniAV_V1.bat` (installs `psutil` and `pypresence` if missing), or:

    python DaniAV_V1.py

For the best coverage use **menu option A** (restart as Administrator).

## What it scans

**Files (quick scan or every fixed drive in full scan)**
- Multi-threaded, with a progress line, Ctrl+C keeps results so far
- Known-bad SHA256 list (built-in EICAR + your own `hashes.txt`, see Import)
- Byte signatures: Mimikatz, coin miners (stratum pools, XMRig), ransom note text,
  Meterpreter indicators, browser/wallet stealer markers, keylogger and process-injection API combos
- Disguised files: PE executables renamed to .jpg/.pdf/.txt etc, double extensions
  (`invoice.pdf.exe`), right-to-left override tricks
- Script behaviour rules for .ps1 .bat .cmd .vbs .js .hta .wsf .py: encoded PowerShell,
  downloaders, certutil/mshta/regsvr32/bitsadmin abuse, shadow-copy deletion, Defender
  tampering, AMSI bypass, reverse shells
- Unsigned and packed (high entropy) executables in Temp, Public, Recycle Bin, ProgramData and AppData roots
- Ransomware file extensions and note file names
- Unchanged clean files are cached, so re-scans are fast

**System**
- Running processes: known-bad names, masquerading (fake svchost, look-alike names), running
  from Temp / Recycle Bin / Public, Office spawning shells, malicious command lines, plus the
  executable file itself
- Persistence: Run/RunOnce (HKCU + HKLM + 32-bit), Winlogon Shell/Userinit, IFEO debuggers,
  AppInit_DLLs, Startup folders, Windows services, scheduled tasks, WMI event consumers
- Network: suspicious remote ports, listening backdoor ports, LOLBins talking to the internet
- Hosts file blocking security/update domains
- Windows Defender health: real-time off, old signatures, suspicious exclusions

## Menu

    1  Quick scan
    2  FULL scan (all fixed drives, optional removable)
    3  Custom scan (folder or drive)
    4  System check only
    5  Continuous protection
    6  Windows Defender (update, quick, full, folder, threat list)
    7  Full scan + Defender full scan
    8  Quarantine manager (restore / delete)
    9  Reports and log
    S  Startup on/off      D  Discord      I  Import hash list      A  Restart as Administrator

After a scan you can review detections: `Q n` quarantine a file, `K n` stop a process,
`D n` details, `A` quarantine all high/critical files, `R` open the HTML report.
Reports (HTML + JSON) are saved in `%LOCALAPPDATA%\DaniAV\Reports`.

## Command line

    python DaniAV_V1.py --quick
    python DaniAV_V1.py --full [--removable] [--deep] [--with-defender]
    python DaniAV_V1.py --scan D:\Games --scan E:\
    python DaniAV_V1.py --system
    python DaniAV_V1.py --watch [--no-startup] [--no-rpc]
    python DaniAV_V1.py --defender-update
    python DaniAV_V1.py --import-hashes hashes.txt
    python DaniAV_V1.py --list-quarantine

Other flags: `--no-update`, `--threads N`, `--no-cache`, `--auto-quarantine`, `--no-report`, `--elevate`, `--quiet`.

## Hash list

`%LOCALAPPDATA%\DaniAV\signatures\hashes.txt`, one SHA256 per line, optional name after a comma:

    275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f,EICAR-Test-File

Import a feed (for example a MalwareBazaar SHA256 export) with `--import-hashes` or menu `I`.

## Environment

- `DANIAV_SCAN_DELAY` watch interval in seconds (default 30)
- `DANIAV_THREADS` worker threads
- `DANIAV_EXCLUDE` semicolon-separated paths to skip
- `DANIAV_DISCORD_CLIENT_ID`, `DANIAV_RPC_INTERVAL`, `DANIAV_GITHUB_URL` for Discord Rich Presence

## Safety

DaniAV has a small signature set plus heuristics. It is **not** a replacement for Windows
Defender or a commercial engine, which is why it integrates with Defender (menu 6 and 7).
Detections are indicators to review, and heuristic hits on your own tools (game-hacking tools,
debuggers, packers, installers) are expected. Nothing is deleted or killed unless you choose it,
or pass `--auto-quarantine`. Quarantine moves files to `%LOCALAPPDATA%\DaniAV\Quarantine`
as inert `.quar` files and can be restored. Core Windows files are never moved or stopped.
DaniAV skips its own folder so its rules do not flag itself.

## License

MIT
