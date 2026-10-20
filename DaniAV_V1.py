"""
DaniAV 2.0 - Windows security scanner and monitor.

Full-disk multi-threaded file scanner with named detections, process /
persistence / service / scheduled-task / WMI / network / hosts-file checks,
Windows Defender integration, quarantine manager, HTML + JSON reports and
optional Discord Rich Presence.

Detections are indicators. DaniAV never deletes or kills anything on its own
unless you explicitly ask it to (--auto-quarantine or the review menu).
"""
from __future__ import annotations

import argparse
import ctypes
import datetime
import hashlib
import html
import ipaddress
import json
import logging
import math
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import base64
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import winreg
except ImportError:  # non-Windows (only used for testing the engine)
    winreg = None

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

APP_NAME = "DaniAV"
VERSION = "2.0.0"
DEFAULT_SCAN_DELAY = 30
DEFAULT_RPC_INTERVAL = 15
DEFAULT_GITHUB_URL = "https://github.com/ubcz/daniav"
UPDATE_BASE_URL = "https://raw.githubusercontent.com/ubcz/daniav/main/"
UPDATE_FILES = ["DaniAV_V1.py", "requirements.txt", "DaniAV_V1.bat", "README.md"]
UPDATE_TIMEOUT = 10

MAX_CONTENT_BYTES = 16 * 1024 * 1024      # bytes read for signature matching
HASH_LIMIT_BYTES = 256 * 1024 * 1024      # biggest file we still hash
SCRIPT_TEXT_LIMIT = 4 * 1024 * 1024       # biggest script text we regex
ENTROPY_SAMPLE = 1024 * 1024
HIGH_ENTROPY = 7.3
PROGRESS_INTERVAL = 0.5
CACHE_FLUSH_EVERY = 2000
QUICK_DEPTH_LOCAL = 4

USER_HOME = Path(os.environ.get("USERPROFILE", str(Path.home())))
LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", str(USER_HOME / "AppData" / "Local")))
APPDATA = Path(os.environ.get("APPDATA", str(USER_HOME / "AppData" / "Roaming")))
PROGRAM_DATA = Path(os.environ.get("ProgramData", r"C:\ProgramData"))
SYSTEM_ROOT = Path(os.environ.get("SystemRoot", r"C:\Windows"))
PUBLIC_DIR = Path(os.environ.get("PUBLIC", r"C:\Users\Public"))
TEMP_DIR = Path(os.environ.get("TEMP", str(LOCALAPPDATA / "Temp")))

DATA_DIR = LOCALAPPDATA / APP_NAME
LOG_FILE = DATA_DIR / "daniav.log"
QUARANTINE_DIR = DATA_DIR / "Quarantine"
REPORT_DIR = DATA_DIR / "Reports"
SIG_DIR = DATA_DIR / "signatures"
USER_HASH_FILE = SIG_DIR / "hashes.txt"
CACHE_FILE = DATA_DIR / "scan_cache.sqlite"
MANIFEST_FILE = QUARANTINE_DIR / "manifest.json"
LOCK_NAME = "DaniAV_V1_SingleInstance"
OWN_DIR = Path(__file__).resolve().parent

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEV_COLOR = {"info": "36", "low": "32", "medium": "33", "high": "31", "critical": "1;37;41"}

SCRIPT_EXTS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
               ".wsf", ".wsh", ".hta", ".sct", ".py", ".pyw"}
EXEC_EXTS = {".exe", ".dll", ".scr", ".sys", ".com", ".pif", ".cpl", ".ocx", ".drv", ".msi", ".jar"}
MACRO_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xlam", ".xlsb"}
HIGH_RISK_EXTENSIONS = {".vbs", ".vbe", ".wsf", ".wsh", ".jse", ".hta", ".scr", ".pif"}
DISGUISE_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".pdf", ".txt", ".doc",
                 ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".mp3", ".mp4", ".avi", ".rtf",
                 ".log", ".ini", ".csv", ".json", ".xml", ".webp"}
RANSOM_EXTS = {".wncry", ".wcry", ".wnry", ".locky", ".cerber", ".zepto", ".crypted",
               ".encrypted", ".lockbit", ".ryk", ".akira", ".blackcat", ".hive", ".conti",
               ".djvu", ".stop", ".medusalocker", ".crylock", ".royal"}
RANSOM_NOTES = {"readme_to_decrypt.txt", "how_to_decrypt_files.txt", "how_to_recover_files.txt",
                "@please_read_me@.txt", "@wanadecryptor@.exe", "decrypt_instructions.html",
                "restore-my-files.txt", "readme.hta", "recover-files.txt", "_readme.txt.locked",
                "!!!read_me!!!.txt", "your_files_are_encrypted.txt"}

DOUBLE_EXT_RE = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|gif|mp3|mp4|zip|rar|rtf|csv)\s*\."
    r"(?:exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|ps1)$")

KNOWN_BAD_PROCESSES: Dict[str, Tuple[str, str]] = {
    "xmrig.exe": ("RiskTool.CoinMiner.XMRig", "high"),
    "xmr-stak.exe": ("RiskTool.CoinMiner.XMRStak", "high"),
    "lolminer.exe": ("RiskTool.CoinMiner.lolMiner", "high"),
    "nbminer.exe": ("RiskTool.CoinMiner.NBMiner", "high"),
    "t-rex.exe": ("RiskTool.CoinMiner.TRex", "high"),
    "phoenixminer.exe": ("RiskTool.CoinMiner.PhoenixMiner", "high"),
    "ethminer.exe": ("RiskTool.CoinMiner.Ethminer", "high"),
    "cgminer.exe": ("RiskTool.CoinMiner.CGMiner", "high"),
    "bfgminer.exe": ("RiskTool.CoinMiner.BFGMiner", "high"),
    "minerd.exe": ("RiskTool.CoinMiner.Minerd", "high"),
    "mimikatz.exe": ("HackTool.Win32.Mimikatz", "critical"),
    "lazagne.exe": ("HackTool.Win32.LaZagne", "high"),
    "pwdump.exe": ("HackTool.Win32.PwDump", "high"),
    "fgdump.exe": ("HackTool.Win32.FgDump", "high"),
    "gsecdump.exe": ("HackTool.Win32.GsecDump", "high"),
    "wce.exe": ("HackTool.Win32.WCE", "high"),
    "njrat.exe": ("Backdoor.MSIL.NjRAT", "critical"),
    "asyncrat.exe": ("Backdoor.MSIL.AsyncRAT", "critical"),
    "remcos.exe": ("Backdoor.Win32.Remcos", "critical"),
    "quasarrat.exe": ("Backdoor.MSIL.Quasar", "critical"),
    "nanocore.exe": ("Backdoor.MSIL.NanoCore", "critical"),
    "darkcomet.exe": ("Backdoor.Win32.DarkComet", "critical"),
    "orcus.exe": ("Backdoor.MSIL.Orcus", "critical"),
    "xworm.exe": ("Backdoor.MSIL.XWorm", "critical"),
    "warzone.exe": ("Backdoor.Win32.WarzoneRAT", "critical"),
    "netwire.exe": ("Backdoor.Win32.NetWire", "critical"),
    "blackshades.exe": ("Backdoor.Win32.Blackshades", "critical"),
    "poisonivy.exe": ("Backdoor.Win32.PoisonIvy", "critical"),
    "gh0st.exe": ("Backdoor.Win32.Gh0st", "critical"),
    "agenttesla.exe": ("Trojan-PSW.MSIL.AgentTesla", "critical"),
    "redline.exe": ("Trojan-PSW.MSIL.RedLine", "critical"),
    "lumma.exe": ("Trojan-PSW.Win32.Lumma", "critical"),
    "nc.exe": ("RiskTool.Win32.Netcat", "medium"),
    "ncat.exe": ("RiskTool.Win32.Ncat", "medium"),
    "psexesvc.exe": ("RiskTool.Win32.PsExecService", "medium"),
}

MASQUERADE_EXPECTED = {
    "svchost.exe": "system32", "lsass.exe": "system32", "csrss.exe": "system32",
    "wininit.exe": "system32", "winlogon.exe": "system32", "services.exe": "system32",
    "smss.exe": "system32", "spoolsv.exe": "system32", "taskhostw.exe": "system32",
    "dllhost.exe": "system32", "conhost.exe": "system32", "runtimebroker.exe": "system32",
    "searchindexer.exe": "system32", "explorer.exe": "windir",
}
LOOKALIKE_TARGETS = ["svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
                     "explorer.exe", "smss.exe", "spoolsv.exe", "taskmgr.exe", "wininit.exe"]
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe"}
SHELL_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe",
                  "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe", "bitsadmin.exe"}
LOLBIN_NET = {"mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe"}

SUSPICIOUS_REMOTE_PORTS = {1337, 4444, 4445, 5554, 6667, 8888, 9001, 9050, 12345, 31337, 54321, 3333, 14444}
SUSPICIOUS_PORTS = {1337, 4444, 4445, 5555, 7777, 8888, 9001, 31337, 12345}

SECURITY_HOST_FRAGMENTS = (
    "virustotal", "kaspersky", "avast", "avg.com", "malwarebytes", "eset.", "bitdefender",
    "norton", "mcafee", "sophos", "trendmicro", "symantec", "drweb", "avira", "windowsupdate",
    "update.microsoft", "defender", "microsoft.com", "virusscan", "clamav", "emsisoft",
)

BUILTIN_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
}

# (name, severity, [regexes that must ALL match], also_applies_to_command_lines)
SCRIPT_RULES = [
    ("HEUR:Script.PowerShell.EncodedCommand", "high",
     [r"powershell|pwsh", r"(?:^|\s)-(?:e|ec|enc|encodedcommand)\s+[a-z0-9+/=]{30,}"], True),
    ("HEUR:Script.Obfuscated.Base64Exec", "high",
     [r"frombase64string", r"\biex\b|invoke-expression"], True),
    ("HEUR:Downloader.Script.PowerShell", "high",
     [r"downloadstring|downloadfile|net\.webclient|invoke-webrequest|start-bitstransfer|\biwr\s",
      r"\biex\b|invoke-expression|start-process|invoke-item|\.exe"], True),
    ("HEUR:Script.PowerShell.HiddenBypass", "medium",
     [r"-w(?:indowstyle)?\s+hidden", r"-nop(?:rofile)?\b|-ep\s+bypass|-executionpolicy\s+bypass"], True),
    ("HEUR:LOLBin.Certutil.Abuse", "high", [r"certutil", r"-urlcache|-decode|-urlfetch"], True),
    ("HEUR:LOLBin.Bitsadmin.Transfer", "medium", [r"bitsadmin", r"/transfer"], True),
    ("HEUR:LOLBin.Mshta.Remote", "high", [r"mshta", r"https?://|javascript:|vbscript:"], True),
    ("HEUR:LOLBin.Regsvr32.Squiblydoo", "high", [r"regsvr32", r"/i:https?://|scrobj\.dll"], True),
    ("Ransom.Behavior.ShadowCopyDelete", "critical",
     [r"vssadmin[^\n]{0,40}delete\s+shadows|wmic[^\n]{0,60}shadowcopy[^\n]{0,20}delete|"
      r"wbadmin[^\n]{0,20}delete\s+(?:catalog|backup)|bcdedit[^\n]{0,60}recoveryenabled\s+no"], True),
    ("HEUR:Tamper.Defender.Disable", "high",
     [r"set-mppreference[^\n]{0,80}-disable\w+\s+\$?(?:true|1)|add-mppreference[^\n]{0,40}-exclusion|"
      r"disableantispyware|disablerealtimemonitoring"], True),
    ("HEUR:Tamper.Firewall.Disable", "medium", [r"netsh\s+advfirewall\s+set\s+\w+\s+state\s+off"], True),
    ("HEUR:Script.AMSIBypass", "high", [r"amsiutils|amsiinitfailed|amsicontext"], True),
    ("HEUR:Persistence.ScheduledTask.Create", "medium",
     [r"schtasks[^\n]{0,20}/create", r"appdata|\\temp\\|powershell|mshta|wscript|cscript"], False),
    ("HEUR:Downloader.JS.ActiveX", "high",
     [r"activexobject|createobject", r"adodb\.stream|msxml2\.xmlhttp|winhttp", r"wscript\.shell|\.run\(|\.exec\("], False),
    ("HEUR:Script.JS.Packer", "medium", [r"eval\s*\(\s*(?:unescape|function\s*\(p,a,c,k,e)"], False),
    ("HEUR:Script.VBS.ObfuscatedChr", "low", [r"(?:chr\s*\(\s*\d+\s*\)\s*&\s*){12,}"], False),
    ("HEUR:Backdoor.PowerShell.ReverseShell", "high",
     [r"new-object\s+system\.net\.sockets\.tcpclient", r"getstream\(\)", r"\biex\b|invoke-expression|\.read\("], False),
]
COMPILED_RULES = [(n, s, [re.compile(r, re.I) for r in rx], cmd) for n, s, rx, cmd in SCRIPT_RULES]

# (name, severity, [lowercase byte patterns], min matches, scope: any | pe | pe-risky)
BYTE_SIGS = [
    ("EICAR-Test-File", "critical", [b"eicar-standard-antivirus-test-file"], 1, "any"),
    ("HackTool.Win32.Mimikatz", "critical", [b"sekurlsa::logonpasswords", b"gentilkiwi"], 1, "pe"),
    ("RiskTool.CoinMiner.StratumPool", "high",
     [b"stratum+tcp://", b"stratum+ssl://", b"stratum2+tcp://"], 1, "any"),
    ("RiskTool.CoinMiner.XMRig", "high", [b"--donate-level", b"xmrig", b"randomx"], 2, "any"),
    ("Ransom.NoteText", "high",
     [b"your files have been encrypted", b"all your files are encrypted", b"to decrypt your files",
      b"send bitcoin", b"decryption key"], 2, "any"),
    ("HEUR:Spyware.Keylogger.APIs", "medium",
     [b"getasynckeystate", b"setwindowshookex", b"getkeyboardstate", b"getrawinputdata"], 2, "pe-risky"),
    ("HEUR:Trojan.Injector.APIs", "medium",
     [b"virtualallocex", b"writeprocessmemory", b"createremotethread", b"ntunmapviewofsection",
      b"queueuserapc", b"setthreadcontext"], 3, "pe-risky"),
    ("HEUR:PSW.Stealer.BrowserData", "high",
     [b"leveldb", b"login data", b"wallet.dat", b"web data", b"logins.json", b"cookies.sqlite",
      b"discord", b"metamask"], 4, "pe-risky"),
    ("HEUR:Backdoor.Meterpreter.Indicator", "high",
     [b"metsrv", b"reflectiveloader", b"stdapi_"], 2, "pe"),
]

rpc = None
rpc_enabled = False
rpc_started = int(time.time())
rpc_last_update = 0.0
rpc_last_connect_attempt = 0.0
single_instance_handle = None
USE_COLOR = False
HASH_DB: Dict[str, str] = dict(BUILTIN_HASHES)
log = logging.getLogger(APP_NAME)
psutil = None
Presence = None
InvalidPipe = Exception


def get_env_int(name, default, minimum, maximum):
    value = os.getenv(name, "").strip()
    if not value:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return max(minimum, min(parsed, maximum))


SCAN_DELAY = get_env_int("DANIAV_SCAN_DELAY", DEFAULT_SCAN_DELAY, 15, 3600)
RPC_INTERVAL = get_env_int("DANIAV_RPC_INTERVAL", DEFAULT_RPC_INTERVAL, 15, 3600)
THREADS = get_env_int("DANIAV_THREADS", min(16, (os.cpu_count() or 4) * 2), 1, 64)
DISCORD_CLIENT_ID = os.getenv("DANIAV_DISCORD_CLIENT_ID", "").strip()
GITHUB_URL = os.getenv("DANIAV_GITHUB_URL", DEFAULT_GITHUB_URL).strip()
USER_EXCLUDES = [p for p in os.getenv("DANIAV_EXCLUDE", "").split(";") if p.strip()]

BANNER = r"""
██████╗  █████╗ ███╗   ██╗██╗ █████╗ ██╗   ██╗
██╔══██╗██╔══██╗████╗  ██║██║██╔══██╗██║   ██║
██║  ██║███████║██╔██╗ ██║██║███████║██║   ██║
██║  ██║██╔══██║██║╚██╗██║██║██╔══██║╚██╗ ██╔╝
██████╔╝██║  ██║██║ ╚████║██║██║  ██║ ╚████╔╝
╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝  ╚═══╝
"""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Alert:
    kind: str
    name: str                 # named detection, e.g. HEUR:Disguised.DoubleExtension
    detail: str = ""
    path: str = ""
    pid: Optional[int] = None
    severity: str = "medium"
    sha256: str = ""
    action: str = "review"

    @property
    def title(self):
        return self.name

    def key(self):
        return f"{self.kind}|{self.name}|{self.path or self.detail}|{self.pid or ''}"

    def display(self):
        suffix = f" | {self.detail}" if self.detail else ""
        return f"{self.name}{suffix}"

    def to_dict(self):
        return {"kind": self.kind, "name": self.name, "severity": self.severity,
                "detail": self.detail, "path": self.path, "pid": self.pid, "sha256": self.sha256}


@dataclass
class ScanOptions:
    deep: bool = False
    removable: bool = False
    threads: int = THREADS
    use_cache: bool = True
    auto_quarantine: bool = False
    write_report: bool = True
    interactive: bool = True
    quiet: bool = False


@dataclass
class ScanStats:
    mode: str
    started_at: datetime.datetime
    elapsed: float = 0.0
    processes_checked: int = 0
    files_checked: int = 0
    files_cached: int = 0
    bytes_read: int = 0
    startup_entries_checked: int = 0
    services_checked: int = 0
    tasks_checked: int = 0
    connections_checked: int = 0
    errors: int = 0
    cancelled: bool = False
    targets: List[str] = field(default_factory=list)
    alerts: List[Alert] = field(default_factory=list)
    _keys: set = field(default_factory=set, repr=False)

    @property
    def alert_count(self):
        return len(self.alerts)

    def add(self, alert: Alert):
        if alert.key() in self._keys:
            return False
        self._keys.add(alert.key())
        self.alerts.append(alert)
        log.warning("[%s] %s | %s %s", alert.severity.upper(), alert.name, alert.detail, alert.path)
        return True

    def sorted_alerts(self):
        return sorted(self.alerts, key=lambda a: (-SEV_RANK.get(a.severity, 0), a.name, a.path))


# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------

def init_environment():
    global psutil, Presence, InvalidPipe
    for directory in (DATA_DIR, QUARANTINE_DIR, REPORT_DIR, SIG_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        filename=str(LOG_FILE), level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S",
    )

    psutil = ensure_package("psutil")
    if psutil is None:
        raise SystemExit("psutil is required. Run: pip install psutil")

    module = ensure_package("pypresence")
    if module is not None:
        Presence = module.Presence
        InvalidPipe = getattr(module, "InvalidPipe", Exception)

    if sys.stdout is None or sys.stderr is None:  # pythonw / hidden startup
        sink = open(os.devnull, "w", encoding="utf-8")
        sys.stdout = sys.stdout or sink
        sys.stderr = sys.stderr or sink
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    load_hash_db()


def ensure_package(name):
    try:
        return __import__(name)
    except ImportError:
        pass
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", name, "-q"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return __import__(name)
    except Exception as exc:
        log.warning("Could not install %s: %s", name, exc)
        return None


def enable_ansi():
    global USE_COLOR
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            USE_COLOR = bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        USE_COLOR = False


def paint(text, code):
    return f"\x1b[{code}m{text}\x1b[0m" if USE_COLOR else text


def sev_tag(severity):
    return paint(f"[{severity.upper():8}]", SEV_COLOR.get(severity, "0"))


def nc(path):
    return os.path.normcase(os.path.normpath(str(path)))


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(extra_args=None):
    args = [str(Path(__file__).resolve())] + (extra_args or [])
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, subprocess.list2cmdline(args), None, 1)
        return ret > 32
    except Exception:
        return False


def acquire_single_instance():
    global single_instance_handle
    kernel32 = ctypes.windll.kernel32
    kernel32.SetLastError(0)
    handle = kernel32.CreateMutexW(None, False, LOCK_NAME)
    if not handle:
        return False
    if kernel32.GetLastError() == 183:
        kernel32.CloseHandle(handle)
        return False
    single_instance_handle = handle
    return True


def release_single_instance():
    global single_instance_handle
    if single_instance_handle:
        try:
            ctypes.windll.kernel32.ReleaseMutex(single_instance_handle)
            ctypes.windll.kernel32.CloseHandle(single_instance_handle)
        except Exception:
            pass
        single_instance_handle = None


def clear_screen():
    os.system("cls")


def header(rpc_state="OFFLINE"):
    clear_screen()
    print(BANNER)
    print(f"  {APP_NAME}  |  V{VERSION}  |  {'ADMIN' if is_admin() else 'standard user'}")
    print("  Full-system Windows security scanner")
    print(f"  Discord Rich Presence: {rpc_state}  |  Threads: {THREADS}")
    print("=" * 76)


def pause():
    try:
        input("\n  Press ENTER to continue")
    except EOFError:
        pass


def ask(prompt, default=""):
    try:
        value = input(prompt).strip()
    except EOFError:
        return default
    return value or default


def yes(prompt, default=False):
    answer = ask(f"{prompt} [{'Y/n' if default else 'y/N'}] ", "y" if default else "n").lower()
    return answer.startswith("y")


# ---------------------------------------------------------------------------
# Signature database
# ---------------------------------------------------------------------------

def load_hash_db():
    HASH_DB.clear()
    HASH_DB.update(BUILTIN_HASHES)
    if not USER_HASH_FILE.exists():
        return
    try:
        for raw in USER_HASH_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in re.split(r"[,\s;]+", line, maxsplit=1)]
            digest = parts[0].lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest):
                HASH_DB[digest] = parts[1] if len(parts) > 1 and parts[1] else "Imported"
    except OSError as exc:
        log.warning("Could not read hash list: %s", exc)


def import_hashes(source):
    path = Path(source)
    if not path.is_file():
        return 0, "file not found"
    existing = set()
    if USER_HASH_FILE.exists():
        existing = {l.split(",")[0].strip().lower() for l in
                    USER_HASH_FILE.read_text(encoding="utf-8", errors="ignore").splitlines()}
    added = 0
    with USER_HASH_FILE.open("a", encoding="utf-8") as out:
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in re.split(r"[,\s;]+", line, maxsplit=1)]
            digest = parts[0].lower()
            if re.fullmatch(r"[0-9a-f]{64}", digest) and digest not in existing:
                label = parts[1] if len(parts) > 1 and parts[1] else "Imported"
                out.write(f"{digest},{label}\n")
                existing.add(digest)
                added += 1
    load_hash_db()
    return added, ""


def sha256_file(path: Path):
    try:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


# ---------------------------------------------------------------------------
# File analysis
# ---------------------------------------------------------------------------

def _zone_prefixes():
    return [
        ("temp", nc(TEMP_DIR)), ("temp", nc(LOCALAPPDATA / "Temp")), ("temp", nc(SYSTEM_ROOT / "Temp")),
        ("downloads", nc(USER_HOME / "Downloads")), ("public", nc(PUBLIC_DIR)),
    ]


ZONE_PREFIXES = _zone_prefixes()
ZONE_ROOT_DIRS = {
    nc(APPDATA): "appdata-root", nc(LOCALAPPDATA): "appdata-root", nc(PROGRAM_DATA): "programdata-root",
}


def risky_zone(path):
    """Return the name of the risky location a path lives in, or ''."""
    if not path:
        return ""
    p = nc(path)
    if "$recycle.bin" in p:
        return "recycle"
    for name, prefix in ZONE_PREFIXES:
        if p == prefix or p.startswith(prefix + os.sep):
            return name
    return ZONE_ROOT_DIRS.get(os.path.dirname(p), "")


def shannon_entropy(data: bytes):
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def pe_info(data: bytes):
    """(is_valid_pe, has_authenticode_blob). The blob is not verified."""
    if data[:2] != b"MZ" or len(data) < 64:
        return False, False
    lfanew = int.from_bytes(data[60:64], "little")
    if lfanew <= 0 or lfanew + 24 > len(data) or data[lfanew:lfanew + 4] != b"PE\x00\x00":
        return False, False
    opt = lfanew + 24
    if opt + 2 > len(data):
        return True, False
    magic = int.from_bytes(data[opt:opt + 2], "little")
    dd_offset = opt + (96 if magic == 0x10B else 112)
    sec = dd_offset + 4 * 8
    if sec + 8 > len(data):
        return True, False
    return True, int.from_bytes(data[sec + 4:sec + 8], "little") > 0


def decode_script(data: bytes):
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", errors="ignore")
    return data.decode("utf-8", errors="ignore")


def match_script_rules(text: str, command_line=False):
    hits = []
    low = text.lower()
    for name, severity, regexes, for_cmd in COMPILED_RULES:
        if command_line and not for_cmd:
            continue
        if all(rx.search(low) for rx in regexes):
            hits.append((name, severity))
    return hits


def inspect_file(path: str, size: int = -1, min_report="info") -> List[Alert]:
    """Analyse one file. Never raises."""
    alerts: List[Alert] = []
    try:
        base = os.path.basename(path)
        low = base.lower()
        ext = os.path.splitext(low)[1]
        zone = risky_zone(path)

        def add(name, severity, detail, sha=""):
            alerts.append(Alert("file", name, detail, path=path, severity=severity, sha256=sha))

        # ---- name based -----------------------------------------------------
        if "\u202e" in base:
            add("HEUR:Disguised.RTLOverride", "high", "right-to-left override character in file name")
        if DOUBLE_EXT_RE.search(low.rstrip()):
            add("HEUR:Disguised.DoubleExtension", "high", "document/media extension hiding an executable one")
        if ext in RANSOM_EXTS:
            add("Ransom.EncryptedFileExtension", "medium", f"ransomware-style extension {ext}")
        if low in RANSOM_NOTES:
            add("Ransom.NoteFile", "high", "known ransom note file name")
        if ext in HIGH_RISK_EXTENSIONS:
            add(f"HEUR:Script.HighRisk.{ext[1:].upper()}", "medium" if zone else "low",
                f"{ext} file{' in ' + zone if zone else ''}")
        if ext in MACRO_EXTS and zone in ("downloads", "temp", "public", "recycle"):
            add("HEUR:Doc.MacroEnabled", "low", f"macro-enabled document in {zone}")

        if size < 0:
            size = os.stat(path).st_size
        if size == 0:
            return alerts

        # ---- content based --------------------------------------------------
        with open(path, "rb") as handle:
            head = handle.read(4096)
            if b"eicar-standard-antivirus-test-file" in head.lower():
                add("EICAR-Test-File", "critical", "EICAR antivirus test string")
                return alerts

            maybe_pe = head[:2] == b"MZ"
            want_content = maybe_pe or ext in SCRIPT_EXTS or ext in EXEC_EXTS or bool(zone)
            if not want_content:
                return alerts

            handle.seek(0)
            data = handle.read(MAX_CONTENT_BYTES)
            sha = hashlib.sha256(data)
            if size > MAX_CONTENT_BYTES and size <= HASH_LIMIT_BYTES:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    sha.update(chunk)
                digest = sha.hexdigest()
            elif size <= MAX_CONTENT_BYTES:
                digest = sha.hexdigest()
            else:
                digest = ""

        is_pe, has_sig = pe_info(data)
        lowered = data.lower()

        if digest and digest in HASH_DB:
            add(f"Malware.KnownHash.{HASH_DB[digest]}", "critical", "SHA256 matches signature database", digest)

        if is_pe and ext in DISGUISE_EXTS:
            add("HEUR:Disguised.PEExecutable", "high", f"Windows executable disguised as {ext}", digest)

        for name, severity, patterns, minimum, scope in BYTE_SIGS:
            if scope == "pe" and not is_pe:
                continue
            if scope == "pe-risky" and not ((is_pe and not has_sig and zone) or (ext in SCRIPT_EXTS and zone)):
                continue
            found = sum(1 for pat in patterns if pat in lowered)
            if found >= minimum:
                add(name, severity, f"{found} signature marker(s) matched", digest)

        if is_pe and not has_sig and zone:
            entropy = shannon_entropy(data[:ENTROPY_SAMPLE])
            packed = entropy >= HIGH_ENTROPY
            if zone in ("public", "recycle", "programdata-root", "appdata-root"):
                add("HEUR:Trojan.PackedUnsigned" if packed else "HEUR:Suspicious.UnsignedPEInRiskyZone",
                    "high" if packed else "medium",
                    f"unsigned executable in {zone}" + (f", entropy {entropy:.2f}" if packed else ""), digest)
            elif zone == "temp":
                add("HEUR:Trojan.PackedUnsigned" if packed else "HEUR:Suspicious.UnsignedPEInTemp",
                    "medium" if packed else "low",
                    "unsigned executable in Temp" + (f", entropy {entropy:.2f}" if packed else ""), digest)
            elif zone == "downloads" and packed:
                add("HEUR:Packed.UnsignedHighEntropy", "low",
                    f"unsigned packed-looking executable in Downloads, entropy {entropy:.2f}", digest)

        if ext in SCRIPT_EXTS and not is_pe:
            text = decode_script(data[:SCRIPT_TEXT_LIMIT])
            for name, severity in match_script_rules(text):
                add(name, severity, "script content matches behaviour rule", digest)
    except (OSError, PermissionError):
        return alerts
    except Exception as exc:  # keep the scanner alive
        log.debug("inspect_file failed for %s: %s", path, exc)
    return alerts


# ---------------------------------------------------------------------------
# Scan cache (skip unchanged clean files on re-scan)
# ---------------------------------------------------------------------------

class ScanCache:
    def __init__(self, enabled=True):
        self.enabled = enabled
        self.conn = None
        self.pending = []
        self.stamp = f"{VERSION}:{len(HASH_DB)}:{len(SCRIPT_RULES)}:{len(BYTE_SIGS)}"
        if not enabled:
            return
        try:
            self.conn = sqlite3.connect(str(CACHE_FILE))
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=OFF")
            self.conn.execute("CREATE TABLE IF NOT EXISTS clean "
                              "(path TEXT PRIMARY KEY, size INTEGER, mtime INTEGER, sig TEXT)")
            self.conn.commit()
        except sqlite3.Error as exc:
            log.warning("Cache disabled: %s", exc)
            self.conn = None
            self.enabled = False

    def is_clean(self, path, size, mtime):
        if not self.conn:
            return False
        try:
            row = self.conn.execute("SELECT size, mtime, sig FROM clean WHERE path=?", (path,)).fetchone()
        except sqlite3.Error:
            return False
        return bool(row) and row[0] == size and row[1] == mtime and row[2] == self.stamp

    def mark(self, path, size, mtime):
        if not self.conn:
            return
        self.pending.append((path, size, mtime, self.stamp))
        if len(self.pending) >= CACHE_FLUSH_EVERY:
            self.flush()

    def flush(self):
        if not self.conn or not self.pending:
            return
        try:
            self.conn.executemany("INSERT OR REPLACE INTO clean VALUES (?,?,?,?)", self.pending)
            self.conn.commit()
        except sqlite3.Error as exc:
            log.warning("Cache write failed: %s", exc)
        self.pending = []

    def close(self):
        self.flush()
        if self.conn:
            self.conn.close()
            self.conn = None


# ---------------------------------------------------------------------------
# File walker
# ---------------------------------------------------------------------------

FILE_ATTRIBUTE_REPARSE_POINT = 0x400
CLOUD_PLACEHOLDER_ATTRS = 0x1000 | 0x40000 | 0x400000  # offline / recall on open / recall on data access
QUICK_SKIP_NAMES = {"cache", "code cache", "gpucache", "cache2", "shadercache", "dawncache",
                    "node_modules", ".git", "__pycache__"}
ALWAYS_SKIP_NAMES = {"system volume information"}
DEEP_ONLY_SKIP_NAMES = {"$windows.~bt", "$windows.~ws"}


def skip_prefixes(deep):
    prefixes = [nc(DATA_DIR), nc(OWN_DIR)]
    prefixes += [nc(p) for p in USER_EXCLUDES]
    if not deep:
        prefixes += [nc(SYSTEM_ROOT / "WinSxS"), nc(SYSTEM_ROOT / "servicing"),
                     nc(SYSTEM_ROOT / "assembly"), nc(SYSTEM_ROOT / "Installer")]
    return prefixes


def walk_files(roots, stop, opts, quick, stats):
    prefixes = skip_prefixes(opts.deep)
    for root, max_depth in roots:
        stack = [(str(root), 0)]
        while stack:
            if stop.is_set():
                return
            current, depth = stack.pop()
            current_nc = nc(current)
            if any(current_nc == p or current_nc.startswith(p + os.sep) for p in prefixes):
                continue
            try:
                iterator = os.scandir(current)
            except OSError:
                stats.errors += 1
                continue
            with iterator:
                while True:
                    try:
                        entry = next(iterator)
                    except StopIteration:
                        break
                    except OSError:
                        stats.errors += 1
                        break
                    try:
                        st = entry.stat(follow_symlinks=False)
                        attrs = getattr(st, "st_file_attributes", 0)
                        if entry.is_dir(follow_symlinks=False):
                            if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                                continue
                            name = entry.name.lower()
                            if name in ALWAYS_SKIP_NAMES:
                                continue
                            if not opts.deep and name in DEEP_ONLY_SKIP_NAMES:
                                continue
                            if quick and name in QUICK_SKIP_NAMES:
                                continue
                            if max_depth is None or depth < max_depth:
                                stack.append((entry.path, depth + 1))
                        elif entry.is_file(follow_symlinks=False):
                            if attrs & CLOUD_PLACEHOLDER_ATTRS:
                                continue
                            yield entry.path, st.st_size, st.st_mtime_ns
                    except OSError:
                        stats.errors += 1


def fixed_drives(include_removable):
    roots = []
    try:
        for part in psutil.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            if "cdrom" in opts or "remote" in opts:
                continue
            if "removable" in opts and not include_removable:
                continue
            roots.append((Path(part.mountpoint), None))
    except Exception as exc:
        log.warning("Drive enumeration failed: %s", exc)
    if not roots:
        roots.append((Path(os.environ.get("SystemDrive", "C:") + "\\"), None))
    return roots


def quick_targets():
    startup_user = APPDATA / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup_all = PROGRAM_DATA / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp"
    candidates = [
        (USER_HOME / "Downloads", None), (USER_HOME / "Desktop", None), (TEMP_DIR, None),
        (SYSTEM_ROOT / "Temp", None), (PUBLIC_DIR, None), (APPDATA, None),
        (LOCALAPPDATA, QUICK_DEPTH_LOCAL), (PROGRAM_DATA, 3), (startup_user, None), (startup_all, None),
        (USER_HOME / "Documents", 2),
    ]
    seen, result = set(), []
    for path, depth in candidates:
        key = nc(path)
        if key not in seen and path.exists():
            seen.add(key)
            result.append((path, depth))
    return result


# ---------------------------------------------------------------------------
# File scan
# ---------------------------------------------------------------------------

def fmt_int(value):
    return f"{value:,}"


def render_progress(stats, started, current_path, quiet):
    if quiet:
        return
    elapsed = max(time.monotonic() - started, 0.001)
    rate = stats.files_checked / elapsed
    width = shutil.get_terminal_size((100, 20)).columns
    line = (f"  files {fmt_int(stats.files_checked)} (+{fmt_int(stats.files_cached)} cached) | "
            f"{rate:,.0f}/s | alerts {stats.alert_count} | {current_path}")
    sys.stdout.write("\r" + line[:width - 2].ljust(width - 2))
    sys.stdout.flush()


def scan_files(stats, roots, opts, stop, quick):
    cache = ScanCache(opts.use_cache)
    pool = ThreadPoolExecutor(max_workers=max(1, opts.threads))
    inflight = {}
    started = time.monotonic()
    last_draw = 0.0
    current = ""
    max_inflight = max(4, opts.threads * 6)

    def drain(done_set):
        for future in done_set:
            path, size, mtime = inflight.pop(future)
            try:
                alerts = future.result()
            except Exception:
                stats.errors += 1
                continue
            stats.files_checked += 1
            stats.bytes_read += max(size, 0)
            if alerts:
                for alert in alerts:
                    stats.add(alert)
            else:
                cache.mark(path, size, mtime)

    try:
        for path, size, mtime in walk_files(roots, stop, opts, quick, stats):
            current = path
            if cache.is_clean(path, size, mtime):
                stats.files_cached += 1
            else:
                inflight[pool.submit(inspect_file, path, size)] = (path, size, mtime)
                if len(inflight) >= max_inflight:
                    done, _ = wait(list(inflight), return_when=FIRST_COMPLETED)
                    drain(done)
            now = time.monotonic()
            if now - last_draw >= PROGRESS_INTERVAL:
                last_draw = now
                render_progress(stats, started, current, opts.quiet)
                rpc_update("Scanning files", f"{fmt_int(stats.files_checked)} files checked", stats.alert_count)
        if inflight:
            done, _ = wait(list(inflight))
            drain(done)
    except KeyboardInterrupt:
        stop.set()
        stats.cancelled = True
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
        cache.close()
        if not opts.quiet:
            sys.stdout.write("\r" + " " * (shutil.get_terminal_size((100, 20)).columns - 2) + "\r")


# ---------------------------------------------------------------------------
# Process analysis
# ---------------------------------------------------------------------------

def levenshtein(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def scan_processes(stats, stop):
    info: Dict[int, dict] = {}
    my_pid = os.getpid()
    scanned_exes = set()
    procs = []
    for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline"], ad_value=None):
        info[proc.info["pid"]] = {"name": proc.info.get("name"), "exe": proc.info.get("exe")}
        procs.append(proc)

    for proc in procs:
        if stop.is_set():
            break
        try:
            pid = proc.info["pid"]
            if pid in (0, 4, my_pid) or proc.info.get("ppid") == my_pid:
                continue
            stats.processes_checked += 1
            name = proc.info.get("name") or ""
            name_l = name.lower()
            exe = proc.info.get("exe") or ""
            exe_nc = nc(exe) if exe else ""
            cmd = " ".join(proc.info.get("cmdline") or [])
            label = f"{name} | PID {pid}" + (f" | {exe}" if exe else "")

            def add(sig, severity, detail=None, path=""):
                stats.add(Alert("process", sig, detail or label, path=path, pid=pid, severity=severity))

            if name_l in KNOWN_BAD_PROCESSES:
                sig, sev = KNOWN_BAD_PROCESSES[name_l]
                add(sig, sev)

            if exe and name_l in MASQUERADE_EXPECTED:
                expected = (nc(SYSTEM_ROOT / "explorer.exe") if MASQUERADE_EXPECTED[name_l] == "windir"
                            else None)
                legit = (exe_nc == expected) if expected else (
                    exe_nc.startswith(nc(SYSTEM_ROOT / "System32") + os.sep)
                    or exe_nc.startswith(nc(SYSTEM_ROOT / "SysWOW64") + os.sep))
                if not legit:
                    add(f"HEUR:Masquerade.{name_l.replace('.exe', '').title()}", "critical",
                        f"{name} running from an unexpected location | PID {pid} | {exe}", exe)
            elif name_l.endswith(".exe") and name_l not in LOOKALIKE_TARGETS:
                for target in LOOKALIKE_TARGETS:
                    if abs(len(target) - len(name_l)) <= 1 and levenshtein(name_l, target) == 1:
                        add("HEUR:Masquerade.LookAlikeName", "high", f"{name} resembles {target} | PID {pid} | {exe}", exe)
                        break

            zone = risky_zone(exe) if exe else ""
            if zone in ("recycle", "public", "programdata-root", "appdata-root"):
                add("HEUR:Process.RunningFromRiskyPath", "medium", f"{label} (zone: {zone})", exe)
            elif zone == "temp":
                add("HEUR:Process.RunningFromTemp", "low", f"{label} (zone: temp)", exe)

            if cmd:
                for rule, sev in match_script_rules(cmd, command_line=True):
                    add(rule, sev, f"{label} | cmd: {cmd[:160]}", exe)

            parent = info.get(proc.info.get("ppid") or -1, {})
            if (parent.get("name") or "").lower() in OFFICE_PARENTS and name_l in SHELL_CHILDREN:
                add("HEUR:Behavior.OfficeSpawnsShell", "high",
                    f"{parent.get('name')} spawned {name} | PID {pid}", exe)

            if exe and exe_nc not in scanned_exes and not exe_nc.startswith(nc(SYSTEM_ROOT) + os.sep):
                scanned_exes.add(exe_nc)
                for alert in inspect_file(exe):
                    alert.kind = "process"
                    alert.pid = pid
                    stats.add(alert)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return info


# ---------------------------------------------------------------------------
# Persistence: registry, startup folders, services, tasks, WMI, hosts, Defender
# ---------------------------------------------------------------------------

_TARGET_RE = re.compile(r'^\s*"?([^"]+?\.(?:exe|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|com|dll|cpl|msi|lnk))"?', re.I)
TRUSTED_PREFIXES = None


def trusted_prefixes():
    global TRUSTED_PREFIXES
    if TRUSTED_PREFIXES is None:
        TRUSTED_PREFIXES = [nc(SYSTEM_ROOT)] + [
            nc(os.environ[v]) for v in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432") if os.environ.get(v)]
    return TRUSTED_PREFIXES


def extract_target(command):
    cmd = os.path.expandvars((command or "").strip())
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 0 else cmd[1:]
    match = _TARGET_RE.match(cmd)
    return match.group(1) if match else (cmd.split(" ")[0] if cmd else "")


def evaluate_command(stats, kind, source, name, command):
    """Shared analysis for anything that auto-runs a command."""
    command = command or ""
    target = extract_target(command)
    label = f"{source} | {name} | {command[:200]}"

    def add(sig, severity, path=""):
        stats.add(Alert(kind, sig, label, path=path, severity=severity))

    for rule, sev in match_script_rules(command, command_line=True):
        add(f"HEUR:Persistence.{rule.split(':', 1)[-1]}", "high" if SEV_RANK[sev] >= 3 else sev)

    zone = risky_zone(target) if os.path.isabs(target) else ""
    if zone in ("temp", "public", "recycle", "programdata-root", "appdata-root"):
        add("HEUR:Persistence.AutorunFromRiskyPath", "high" if zone in ("recycle", "public", "temp") else "medium",
            target)

    lower = command.lower()
    if re.search(r"(powershell|pwsh|mshta|wscript|cscript|cmd(?:\.exe)?\s+/c)", lower) and (
            re.search(r"https?://", lower) or "appdata" in lower or "\\temp\\" in lower):
        add("HEUR:Persistence.LOLBinCommand", "high")

    if target and os.path.isabs(target) and os.path.isfile(target):
        tn = nc(target)
        if not any(tn.startswith(p + os.sep) for p in trusted_prefixes()):
            for alert in inspect_file(target):
                alert.kind = kind
                alert.detail = f"{label} -> {alert.detail}"
                stats.add(alert)


def reg_values(hive, subkey, view=0):
    values = []
    if winreg is None:
        return values
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view) as key:
            index = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, index)
                    values.append((name, value))
                    index += 1
                except OSError:
                    break
    except OSError:
        pass
    return values


def reg_subkeys(hive, subkey):
    names = []
    if winreg is None:
        return names
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            index = 0
            while True:
                try:
                    names.append(winreg.EnumKey(key, index))
                    index += 1
                except OSError:
                    break
    except OSError:
        pass
    return names


def scan_registry_persistence(stats):
    if winreg is None:
        return
    hklm, hkcu = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER
    run_locations = [
        (hkcu, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (hkcu, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (hkcu, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKCU Policies Run"),
        (hklm, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (hklm, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (hklm, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "HKLM Policies Run"),
        (hklm, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)"),
        (hklm, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce (32-bit)"),
    ]
    for hive, subkey, label in run_locations:
        for name, value in reg_values(hive, subkey):
            stats.startup_entries_checked += 1
            if name.lower() == APP_NAME.lower():
                continue
            evaluate_command(stats, "startup", label, name, str(value))

    winlogon = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    for hive, tag in ((hklm, "HKLM"), (hkcu, "HKCU")):
        values = dict((n.lower(), v) for n, v in reg_values(hive, winlogon))
        stats.startup_entries_checked += 1
        shell = str(values.get("shell", "explorer.exe")).strip().lower()
        if shell and shell != "explorer.exe":
            stats.add(Alert("startup", "HEUR:Persistence.Winlogon.ShellHijack",
                            f"{tag} Winlogon Shell = {values.get('shell')}", severity="high"))
        userinit = str(values.get("userinit", "")).strip().lower().rstrip(",")
        if userinit and userinit != nc(SYSTEM_ROOT / "System32" / "userinit.exe").rstrip(","):
            stats.add(Alert("startup", "HEUR:Persistence.Winlogon.UserinitHijack",
                            f"{tag} Winlogon Userinit = {values.get('userinit')}", severity="high"))

    ifeo = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    for sub in reg_subkeys(hklm, ifeo):
        stats.startup_entries_checked += 1
        for name, value in reg_values(hklm, ifeo + "\\" + sub):
            if name.lower() == "debugger" and str(value).strip():
                stats.add(Alert("startup", "HEUR:Persistence.IFEO.Debugger",
                                f"{sub} -> {value}", severity="high"))

    for view_tag, view in (("64-bit", 0), ("32-bit", getattr(winreg, "KEY_WOW64_32KEY", 0))):
        windows_key = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
        for name, value in reg_values(hklm, windows_key, view):
            if name.lower() == "appinit_dlls" and str(value).strip():
                stats.add(Alert("startup", "HEUR:Persistence.AppInitDLLs",
                                f"{view_tag} AppInit_DLLs = {value}", severity="high"))


def scan_startup_folders(stats):
    folders = [
        APPDATA / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        PROGRAM_DATA / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "StartUp",
    ]
    for folder in folders:
        try:
            entries = list(folder.iterdir())
        except OSError:
            continue
        for item in entries:
            if item.name.lower() == "desktop.ini" or not item.is_file():
                continue
            stats.startup_entries_checked += 1
            ext = item.suffix.lower()
            if ext in SCRIPT_EXTS or ext in EXEC_EXTS:
                stats.add(Alert("startup", "HEUR:Persistence.StartupFolder.Executable",
                                f"{item}", path=str(item), severity="medium"))
            for alert in inspect_file(str(item)):
                alert.kind = "startup"
                stats.add(alert)


def scan_services(stats):
    if not hasattr(psutil, "win_service_iter"):
        return
    try:
        services = list(psutil.win_service_iter())
    except Exception as exc:
        log.warning("Service enumeration failed: %s", exc)
        return
    for service in services:
        try:
            data = service.as_dict()
        except Exception:
            continue
        stats.services_checked += 1
        evaluate_command(stats, "service", "Service", f"{data.get('name')} ({data.get('display_name')})",
                         data.get("binpath") or "")


def ps_encoded(script):
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def run_powershell(script, timeout=90):
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return None
    try:
        result = subprocess.run(
            [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-EncodedCommand", ps_encoded(script)],
            capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        return result.stdout.decode("utf-8", errors="replace").strip()
    except (subprocess.TimeoutExpired, OSError) as exc:
        log.warning("PowerShell call failed: %s", exc)
        return None


SYSTEM_QUERY_PS = r"""
$ErrorActionPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
$tasks=@(Get-ScheduledTask | ForEach-Object { $t=$_; foreach($a in $t.Actions){ if($a.Execute){ [pscustomobject]@{Task=($t.TaskPath+$t.TaskName);Exec=$a.Execute;Args=$a.Arguments} } } })
$wmi=@(Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer | Select-Object Name,@{n='Class';e={$_.CimClass.CimClassName}},CommandLineTemplate,ExecutablePath,ScriptText)
$mp=Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,AntivirusSignatureAge,AMServiceEnabled
$pref=Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess
[pscustomobject]@{tasks=$tasks;wmi=$wmi;mp=$mp;pref=$pref} | ConvertTo-Json -Depth 4 -Compress
"""


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def scan_windows_queries(stats):
    """Scheduled tasks, WMI persistence and Defender health in one PowerShell call."""
    raw = run_powershell(SYSTEM_QUERY_PS)
    if not raw:
        return
    try:
        data = json.loads(raw[raw.find("{"):])
    except (ValueError, TypeError):
        log.warning("Could not parse system query output")
        return

    for task in as_list(data.get("tasks")):
        stats.tasks_checked += 1
        command = f"{task.get('Exec') or ''} {task.get('Args') or ''}".strip()
        evaluate_command(stats, "task", "Scheduled task", task.get("Task") or "?", command)

    for consumer in as_list(data.get("wmi")):
        cls = consumer.get("Class") or ""
        if cls in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
            detail = consumer.get("CommandLineTemplate") or consumer.get("ExecutablePath") or \
                (consumer.get("ScriptText") or "")[:160]
            stats.add(Alert("startup", "HEUR:Persistence.WMI.EventConsumer",
                            f"{cls} | {consumer.get('Name')} | {detail}", severity="high"))

    status = data.get("mp") or {}
    if status:
        if status.get("RealTimeProtectionEnabled") is False:
            stats.add(Alert("system", "System.Defender.RealtimeProtectionOff",
                            "Windows Defender real-time protection is off (fine only if another AV is active)",
                            severity="medium"))
        for field_name in ("AntivirusEnabled", "AntispywareEnabled", "BehaviorMonitorEnabled", "IoavProtectionEnabled"):
            if status.get(field_name) is False:
                stats.add(Alert("system", f"System.Defender.{field_name}Off",
                                f"{field_name} is disabled", severity="low"))
        age = status.get("AntivirusSignatureAge")
        if isinstance(age, int) and age > 7:
            stats.add(Alert("system", "System.Defender.SignaturesOutdated",
                            f"Defender signatures are {age} days old", severity="low"))

    pref = data.get("pref") or {}
    for path in as_list(pref.get("ExclusionPath")):
        if not isinstance(path, str) or path.lower().startswith("n/a"):
            continue
        root_like = len(path.rstrip("\\/")) <= 3
        whole_profile = "\\users\\" in path.lower() and path.lower().rstrip("\\").count("\\") <= 2
        if root_like or risky_zone(path) or whole_profile:
            stats.add(Alert("system", "HEUR:Tamper.Defender.Exclusion",
                            f"Defender excludes {path} from scanning", severity="high"))
    for ext in as_list(pref.get("ExclusionExtension")):
        if isinstance(ext, str) and ext.lower().lstrip(".") in ("exe", "dll", "scr", "ps1", "bat", "cmd", "vbs", "js"):
            stats.add(Alert("system", "HEUR:Tamper.Defender.ExtensionExclusion",
                            f"Defender excludes *.{ext.lstrip('.')} files", severity="high"))


def scan_hosts_file(stats):
    hosts = SYSTEM_ROOT / "System32" / "drivers" / "etc" / "hosts"
    try:
        lines = hosts.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        for host in parts[1:]:
            if any(fragment in host.lower() for fragment in SECURITY_HOST_FRAGMENTS):
                stats.add(Alert("system", "HEUR:Tamper.HostsFile.SecurityDomain",
                                f"{parts[0]} {host}", path=str(hosts), severity="high"))


# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

def is_public_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def scan_network(stats, proc_info):
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        log.warning("Network scan visibility is limited without elevation")
        return

    for conn in connections:
        stats.connections_checked += 1
        raddr, laddr = conn.raddr, conn.laddr
        rip = raddr.ip if raddr else ""
        rport = raddr.port if raddr else None
        lport = laddr.port if laddr else None
        pid = conn.pid
        meta = proc_info.get(pid) or {}
        pname = (meta.get("name") or "").lower()
        pexe = meta.get("exe") or ""
        who = f"{meta.get('name') or 'unknown'} | PID {pid or 'unknown'}"
        established = conn.status == psutil.CONN_ESTABLISHED
        public = is_public_ip(rip)

        if established and public and rport in SUSPICIOUS_REMOTE_PORTS:
            stats.add(Alert("network", "HEUR:Network.SuspiciousRemotePort",
                            f"{who} -> {rip}:{rport}", pid=pid, severity="medium", path=pexe))
        if conn.status == psutil.CONN_LISTEN and lport in SUSPICIOUS_PORTS:
            stats.add(Alert("network", "HEUR:Network.SuspiciousListeningPort",
                            f"{who} listening on {lport}", pid=pid, severity="low", path=pexe))
        if established and public and pname in LOLBIN_NET:
            stats.add(Alert("network", "HEUR:Network.LOLBinOutbound",
                            f"{who} -> {rip}:{rport}", pid=pid, severity="high", path=pexe))
        if established and public and pexe and risky_zone(pexe) in ("recycle", "public"):
            stats.add(Alert("network", "HEUR:Network.RiskyPathProcessOutbound",
                            f"{who} -> {rip}:{rport}", pid=pid, severity="medium", path=pexe))


# ---------------------------------------------------------------------------
# Scan orchestration
# ---------------------------------------------------------------------------

def run_system_checks(stats, stop, light=False):
    """light = cheap checks only (used between full checks in watch mode)."""
    info = scan_processes(stats, stop)
    if stop.is_set():
        return
    scan_registry_persistence(stats)
    scan_startup_folders(stats)
    if not light:
        scan_services(stats)
        scan_windows_queries(stats)
        scan_hosts_file(stats)
    scan_network(stats, info)


def run_scan(mode, opts, paths=None, stop=None, announce=True, light=False):
    """mode: quick | full | custom | system"""
    stop = stop or threading.Event()
    stats = ScanStats(mode=mode, started_at=datetime.datetime.now())
    t0 = time.monotonic()

    if mode in ("quick", "full", "custom", "system"):
        if announce and not opts.quiet:
            print(f"  [1/2] Checking processes, persistence, services, tasks, network ...")
        rpc_update("Checking system", "Processes, startup, network", 0, force=True)
        try:
            run_system_checks(stats, stop, light)
        except KeyboardInterrupt:
            stop.set()
            stats.cancelled = True

    if mode != "system" and not stop.is_set():
        if mode == "quick":
            roots = quick_targets()
        elif mode == "full":
            roots = fixed_drives(opts.removable)
        else:
            roots = [(Path(p), None) for p in (paths or []) if Path(p).exists()]
        stats.targets = [str(r[0]) for r in roots]
        if announce and not opts.quiet:
            print(f"  [2/2] Scanning files in: {', '.join(stats.targets) or 'nothing'}")
            print("        Ctrl+C cancels and keeps results so far")
        scan_files(stats, roots, opts, stop, quick=(mode == "quick"))

    stats.elapsed = time.monotonic() - t0
    stats.cancelled = stats.cancelled or stop.is_set()
    return stats


# ---------------------------------------------------------------------------
# Output / reports
# ---------------------------------------------------------------------------

def print_stats(stats, limit=60):
    print()
    print("=" * 76)
    print(f"  Scan {'cancelled' if stats.cancelled else 'complete'}  ({stats.mode})")
    print(f"  Processes checked:       {fmt_int(stats.processes_checked)}")
    print(f"  Files checked:           {fmt_int(stats.files_checked)}  (+{fmt_int(stats.files_cached)} unchanged, skipped)")
    print(f"  Data read:               {stats.bytes_read / (1024 ** 3):.2f} GiB seen")
    print(f"  Startup entries checked: {fmt_int(stats.startup_entries_checked)}")
    print(f"  Services / tasks:        {fmt_int(stats.services_checked)} / {fmt_int(stats.tasks_checked)}")
    print(f"  Connections checked:     {fmt_int(stats.connections_checked)}")
    print(f"  Unreadable items:        {fmt_int(stats.errors)}")
    print(f"  Alerts:                  {stats.alert_count}")
    print(f"  Duration:                {stats.elapsed:.1f}s")
    print("=" * 76)

    if not stats.alerts:
        print("  STATUS: CLEAN")
        print("  No signatures or heuristics matched.")
        if not is_admin():
            print("  Tip: run as Administrator for full process, service and registry visibility.")
        return

    counts = Counter(a.severity for a in stats.alerts)
    summary = "  ".join(f"{sev}:{counts[sev]}" for sev in ("critical", "high", "medium", "low", "info") if counts[sev])
    print(f"  STATUS: REVIEW NEEDED   ({summary})")
    print()
    for index, alert in enumerate(stats.sorted_alerts()[:limit], 1):
        print(f"  {index:03d} {sev_tag(alert.severity)} {alert.name}")
        where = alert.path or alert.detail
        print(f"        {where[:150]}")
        if alert.path and alert.detail:
            print(f"        {alert.detail[:150]}")
    if len(stats.alerts) > limit:
        print(f"  ... and {len(stats.alerts) - limit} more (see report)")


def write_report(stats):
    stamp = stats.started_at.strftime("%Y%m%d_%H%M%S")
    json_path = REPORT_DIR / f"scan_{stamp}.json"
    html_path = REPORT_DIR / f"scan_{stamp}.html"
    alerts = stats.sorted_alerts()
    payload = {
        "app": APP_NAME, "version": VERSION, "mode": stats.mode,
        "started": stats.started_at.isoformat(timespec="seconds"), "seconds": round(stats.elapsed, 2),
        "targets": stats.targets, "cancelled": stats.cancelled,
        "counts": {"processes": stats.processes_checked, "files": stats.files_checked,
                   "files_unchanged": stats.files_cached, "startup": stats.startup_entries_checked,
                   "services": stats.services_checked, "tasks": stats.tasks_checked,
                   "connections": stats.connections_checked, "errors": stats.errors},
        "alerts": [a.to_dict() for a in alerts],
    }
    json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    colors = {"critical": "#b00020", "high": "#e53935", "medium": "#f9a825", "low": "#43a047", "info": "#039be5"}
    rows = "".join(
        f"<tr><td style='color:#fff;background:{colors.get(a.severity, '#888')}'>{html.escape(a.severity.upper())}</td>"
        f"<td>{html.escape(a.name)}</td><td>{html.escape(a.kind)}</td>"
        f"<td>{html.escape(a.path or '')}</td><td>{html.escape(a.detail)}</td>"
        f"<td><code>{html.escape(a.sha256[:16])}</code></td></tr>" for a in alerts)
    page = f"""<!doctype html><meta charset=utf-8><title>DaniAV report {stamp}</title>
<style>body{{font:14px system-ui;margin:24px;background:#111;color:#eee}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #333;padding:6px 8px;text-align:left;vertical-align:top;word-break:break-all}}th{{background:#222}}
code{{color:#9cf}}</style>
<h1>DaniAV {VERSION} scan report</h1>
<p>Mode {html.escape(stats.mode)} | started {stats.started_at:%Y-%m-%d %H:%M:%S} | {stats.elapsed:.1f}s |
files {stats.files_checked:,} | processes {stats.processes_checked} | alerts {stats.alert_count}
{' | CANCELLED' if stats.cancelled else ''}</p>
<p>Targets: {html.escape(', '.join(stats.targets) or 'system checks only')}</p>
<table><tr><th>Severity</th><th>Detection</th><th>Type</th><th>Path</th><th>Detail</th><th>SHA256</th></tr>
{rows or '<tr><td colspan=6>No detections</td></tr>'}</table>"""
    html_path.write_text(page, encoding="utf-8")
    return html_path, json_path


def open_path(path: Path):
    try:
        os.startfile(str(path))
    except (OSError, AttributeError) as exc:
        print(f"  Could not open path: {exc}")


# ---------------------------------------------------------------------------
# Quarantine and response actions
# ---------------------------------------------------------------------------

def load_manifest():
    try:
        return json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []


def save_manifest(entries):
    MANIFEST_FILE.write_text(json.dumps(entries, indent=2), encoding="utf-8")


def quarantine_file(path_text, detection="manual"):
    path = Path(path_text)
    if not path.exists() or not path.is_file():
        return False, "File no longer exists"
    if nc(path).startswith(nc(SYSTEM_ROOT / "System32") + os.sep) or nc(path).startswith(nc(SYSTEM_ROOT / "WinSxS") + os.sep):
        return False, "Refusing to move a core Windows file - use Windows Defender or sfc /scannow instead"
    try:
        digest = sha256_file(path) or ""
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        stored = QUARANTINE_DIR / f"{stamp}_{path.name}.quar"
        shutil.move(str(path), str(stored))
        entries = load_manifest()
        entries.append({"id": stamp, "original": str(path), "stored": str(stored), "sha256": digest,
                        "detection": detection, "time": datetime.datetime.now().isoformat(timespec="seconds")})
        save_manifest(entries)
        log.warning("Quarantined %s -> %s (%s)", path, stored, detection)
        return True, str(stored)
    except (OSError, PermissionError) as exc:
        return False, str(exc)


def restore_quarantined(entry_id):
    entries = load_manifest()
    for entry in entries:
        if entry["id"] == entry_id:
            target = Path(entry["original"])
            if target.exists():
                return False, "Original location already has a file"
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(entry["stored"], str(target))
            except OSError as exc:
                return False, str(exc)
            save_manifest([e for e in entries if e["id"] != entry_id])
            return True, str(target)
    return False, "Entry not found"


def delete_quarantined(entry_id):
    entries = load_manifest()
    for entry in entries:
        if entry["id"] == entry_id:
            try:
                Path(entry["stored"]).unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                return False, str(exc)
            save_manifest([e for e in entries if e["id"] != entry_id])
            return True, "Deleted permanently"
    return False, "Entry not found"


def kill_process(pid):
    try:
        proc = psutil.Process(pid)
        name = proc.name().lower()
        if name in ("system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "lsass.exe", "services.exe"):
            return False, "Refusing to stop a core Windows process"
        proc.terminate()
        try:
            proc.wait(3)
        except psutil.TimeoutExpired:
            proc.kill()
        log.warning("Terminated PID %s (%s)", pid, name)
        return True, f"Terminated {name}"
    except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
        return False, str(exc)


def quarantine_manager():
    while True:
        entries = load_manifest()
        header("READY" if rpc_enabled else "OFFLINE")
        print("  Quarantine\n")
        if not entries:
            print("  Empty.")
        for index, entry in enumerate(entries, 1):
            print(f"  {index:02d}  {entry['time']}  {entry['detection']}")
            print(f"      {entry['original']}")
        print("\n  R n = restore   D n = delete forever   O = open folder   ENTER = back")
        choice = ask("  > ").lower()
        if not choice:
            return
        if choice == "o":
            open_path(QUARANTINE_DIR)
            continue
        parts = choice.split()
        if len(parts) == 2 and parts[1].isdigit() and 1 <= int(parts[1]) <= len(entries):
            entry = entries[int(parts[1]) - 1]
            if parts[0] == "r":
                ok, msg = restore_quarantined(entry["id"])
            elif parts[0] == "d" and yes(f"  Permanently delete {entry['original']}?"):
                ok, msg = delete_quarantined(entry["id"])
            else:
                continue
            print(f"  {'OK' if ok else 'FAILED'}: {msg}")
            pause()


def auto_quarantine(stats):
    moved = 0
    for alert in stats.sorted_alerts():
        if alert.kind in ("file", "process") and alert.path and SEV_RANK[alert.severity] >= SEV_RANK["high"]:
            if alert.pid:
                kill_process(alert.pid)
                time.sleep(0.3)
            ok, msg = quarantine_file(alert.path, alert.name)
            if ok:
                moved += 1
                alert.action = "quarantined"
    return moved


def review_alerts(stats, report_path=None):
    if not stats.alerts or not sys.stdin or not sys.stdin.isatty():
        return
    ordered = stats.sorted_alerts()
    while True:
        print("\n  Actions:  Q n = quarantine file   K n = kill process   D n = details")
        print("            A = quarantine all high/critical files   R = open report   ENTER = done")
        choice = ask("  > ").lower()
        if not choice:
            return
        if choice == "r" and report_path:
            open_path(report_path)
            continue
        if choice == "a":
            if yes("  Quarantine every high/critical file and stop its process?"):
                print(f"  Quarantined {auto_quarantine(stats)} file(s)")
            continue
        parts = choice.split()
        if len(parts) == 2 and parts[1].isdigit() and 1 <= int(parts[1]) <= len(ordered):
            alert = ordered[int(parts[1]) - 1]
            if parts[0] == "d":
                for k, v in alert.to_dict().items():
                    print(f"    {k:9}: {v}")
            elif parts[0] == "q" and alert.path:
                if yes(f"  Quarantine {alert.path}?"):
                    ok, msg = quarantine_file(alert.path, alert.name)
                    print(f"  {'Quarantined to ' if ok else 'FAILED: '}{msg}")
            elif parts[0] == "k" and alert.pid:
                if yes(f"  Terminate PID {alert.pid}?"):
                    ok, msg = kill_process(alert.pid)
                    print(f"  {'OK: ' if ok else 'FAILED: '}{msg}")
            else:
                print("  Nothing to do for that alert/action")


# ---------------------------------------------------------------------------
# Windows Defender integration
# ---------------------------------------------------------------------------

def find_mpcmdrun():
    platform = PROGRAM_DATA / "Microsoft" / "Windows Defender" / "Platform"
    candidates = []
    try:
        for folder in sorted(platform.iterdir(), key=lambda p: p.name, reverse=True):
            candidates.append(folder / "MpCmdRun.exe")
    except OSError:
        pass
    for var in ("ProgramFiles", "ProgramW6432"):
        if os.environ.get(var):
            candidates.append(Path(os.environ[var]) / "Windows Defender" / "MpCmdRun.exe")
    return next((c for c in candidates if c.exists()), None)


def defender_run(args, show=True):
    exe = find_mpcmdrun()
    if exe is None:
        return False, "Windows Defender command line tool was not found"
    tail = []
    try:
        proc = subprocess.Popen([str(exe)] + args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, errors="replace", creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            for line in proc.stdout:
                line = line.rstrip()
                tail.append(line)
                if show and line:
                    print("   ", line)
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            return False, "Cancelled"
        return proc.returncode == 0, "\n".join(tail[-30:])
    except OSError as exc:
        return False, str(exc)


def defender_update():
    return defender_run(["-SignatureUpdate"])


def defender_scan(kind="quick", path=None, remediate=True):
    args = ["-Scan", "-ScanType", {"quick": "1", "full": "2", "custom": "3"}[kind]]
    if kind == "custom" and path:
        args += ["-File", str(path)]
    if not remediate:
        args.append("-DisableRemediation")
    return defender_run(args)


def defender_threats():
    raw = run_powershell(
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
        "Get-MpThreat | Select-Object ThreatName,SeverityID,IsActive,Resources | ConvertTo-Json -Depth 3 -Compress")
    if not raw:
        return []
    try:
        return as_list(json.loads(raw))
    except ValueError:
        return []


def defender_menu():
    while True:
        header("READY" if rpc_enabled else "OFFLINE")
        print("  Windows Defender\n")
        print("  1  Update signatures")
        print("  2  Quick scan")
        print("  3  Full scan (whole PC, can take hours)")
        print("  4  Scan a folder / file")
        print("  5  Show detected threats")
        print("  0  Back\n")
        choice = ask("  > ")
        if choice == "0" or not choice:
            return
        if choice == "1":
            ok, _ = defender_update()
            print("  Result:", "SUCCESS" if ok else "FAILED")
        elif choice in ("2", "3", "4"):
            remediate = yes("  Let Defender remove/quarantine what it finds?", default=False)
            if choice == "4":
                target = ask("  Path: ").strip('"')
                ok, _ = defender_scan("custom", target, remediate)
            else:
                ok, _ = defender_scan("quick" if choice == "2" else "full", None, remediate)
            print("  Result:", "NO THREATS / FINISHED" if ok else "THREATS FOUND, FAILED OR CANCELLED (see above)")
        elif choice == "5":
            threats = defender_threats()
            if not threats:
                print("  No threats recorded.")
            for t in threats:
                print(f"  {t.get('ThreatName')} | active={t.get('IsActive')} | {t.get('Resources')}")
        pause()


# ---------------------------------------------------------------------------
# Discord Rich Presence
# ---------------------------------------------------------------------------

def rpc_configured():
    return Presence is not None and DISCORD_CLIENT_ID.isdigit() and 5 <= len(DISCORD_CLIENT_ID) <= 20


def rpc_connect(force=False):
    global rpc, rpc_enabled, rpc_last_connect_attempt
    now = time.monotonic()
    if not force and now - rpc_last_connect_attempt < 30:
        return False
    rpc_last_connect_attempt = now
    if not rpc_configured():
        rpc_enabled = False
        rpc = None
        return False
    try:
        rpc = Presence(DISCORD_CLIENT_ID)
        rpc.connect()
        rpc_enabled = True
        log.info("Discord Rich Presence connected")
        return True
    except Exception as exc:
        rpc = None
        rpc_enabled = False
        log.warning("Discord Rich Presence unavailable: %s", exc)
        return False


def rpc_close():
    global rpc, rpc_enabled
    if rpc is not None:
        try:
            rpc.close()
        except Exception:
            pass
    rpc = None
    rpc_enabled = False


def rpc_update(details, state, alert_count=0, force=False):
    global rpc_last_update
    if not rpc_configured():
        return False
    if not rpc_enabled or rpc is None:
        if not rpc_connect():
            return False
    now = time.monotonic()
    if not force and now - rpc_last_update < RPC_INTERVAL:
        return False
    rpc_last_update = now
    status_text = "System clean" if alert_count == 0 else f"{alert_count} alert(s)"
    try:
        rpc.update(details=details[:128], state=state[:128], start=rpc_started,
                   large_text=f"{APP_NAME} V{VERSION}", small_text=status_text[:128],
                   buttons=[{"label": "DaniAV on GitHub", "url": GITHUB_URL}])
        return True
    except InvalidPipe:
        log.warning("Discord IPC disconnected")
        rpc_close()
        if rpc_connect(force=True):
            return rpc_update(details, state, alert_count, force=True)
        return False
    except Exception as exc:
        log.warning("Discord activity update failed: %s", exc)
        return False


def rpc_test():
    if not rpc_configured() or not rpc_connect(force=True):
        return False
    return rpc_update("DaniAV is online", "Discord Rich Presence test", 0, force=True)


def explain_discord():
    print("\n  Discord setup")
    print("  1. Create a Discord application")
    print("  2. Copy its Application ID")
    print("  3. Set DANIAV_DISCORD_CLIENT_ID to that ID")
    print("  4. Keep the Discord desktop client running")
    print("  5. Start DaniAV again\n")
    print("  Optional repository button: set DANIAV_GITHUB_URL")


# ---------------------------------------------------------------------------
# Startup registration
# ---------------------------------------------------------------------------

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def register_startup():
    if winreg is None:
        return False
    executable = Path(sys.executable).resolve()
    pythonw = executable.with_name("pythonw.exe")
    runner = pythonw if pythonw.exists() else executable
    script = Path(__file__).resolve()
    command = f'"{runner}" "{script}" --watch --no-startup --quiet'
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, command)
        log.info("Startup entry registered")
        return True
    except OSError as exc:
        log.warning("Startup registration failed: %s", exc)
        return False


def remove_startup():
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, APP_NAME)
        log.info("Startup entry removed")
        return True
    except FileNotFoundError:
        return True
    except OSError as exc:
        log.warning("Startup removal failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Self-update from GitHub
# ---------------------------------------------------------------------------

def parse_version(text):
    match = re.search(r'^VERSION\s*=\s*"(\d+(?:\.\d+)*)"', text, re.M)
    return tuple(int(x) for x in match.group(1).split(".")) if match else None


def fetch_text(name):
    request = urllib.request.Request(UPDATE_BASE_URL + name, headers={"User-Agent": f"{APP_NAME}/{VERSION}"})
    with urllib.request.urlopen(request, timeout=UPDATE_TIMEOUT) as response:
        return response.read()


def check_for_update(quiet=False):
    """Download the newest release from GitHub and replace local files.
    Returns True if files were updated (caller should restart)."""
    def say(msg):
        if not quiet:
            print(f"  [update] {msg}")

    try:
        remote_main = fetch_text(UPDATE_FILES[0])
    except Exception as exc:
        say(f"could not reach GitHub, continuing with local version ({exc.__class__.__name__})")
        return False

    remote_ver = parse_version(remote_main.decode("utf-8", errors="ignore"))
    local_ver = parse_version(f'VERSION = "{VERSION}"')
    if not remote_ver or remote_ver <= local_ver:
        say(f"up to date (v{VERSION})")
        return False

    say(f"new version v{'.'.join(map(str, remote_ver))} found, updating from {DEFAULT_GITHUB_URL}")
    try:
        compile(remote_main, "DaniAV_V1.py", "exec")  # refuse anything that is not valid Python
    except SyntaxError:
        say("downloaded file failed validation, update skipped")
        return False

    payload = {UPDATE_FILES[0]: remote_main}
    for name in UPDATE_FILES[1:]:
        try:
            payload[name] = fetch_text(name)
        except Exception:
            pass  # optional files

    script = Path(__file__).resolve()
    backup_dir = script.parent / ".daniav_backup"
    written = []
    try:
        backup_dir.mkdir(exist_ok=True)
        for name, content in payload.items():
            target = script.parent / name
            if target.exists():
                shutil.copy2(target, backup_dir / name)
            tmp = target.with_name(target.name + ".new")
            tmp.write_bytes(content)
            os.replace(tmp, target)
            written.append(name)
    except OSError as exc:
        say(f"update failed ({exc}), restoring previous files")
        for name in written:
            try:
                shutil.copy2(backup_dir / name, script.parent / name)
            except OSError:
                pass
        return False

    say(f"updated {', '.join(written)} (previous copy kept in {backup_dir.name})")
    return True


def restart_self():
    env = dict(os.environ, DANIAV_UPDATED="1")
    try:
        subprocess.Popen([sys.executable, str(Path(__file__).resolve())] + sys.argv[1:], env=env)
        return True
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

def finish_scan(stats, opts):
    if opts.auto_quarantine:
        moved = auto_quarantine(stats)
        if moved and not opts.quiet:
            print(f"  Auto-quarantined {moved} file(s)")
    report = None
    if opts.write_report:
        try:
            report, _ = write_report(stats)
        except OSError as exc:
            log.warning("Report failed: %s", exc)
    if not opts.quiet:
        print_stats(stats)
        if report:
            print(f"\n  Report: {report}")
    rpc_update("System clean" if not stats.alerts else f"{stats.alert_count} alert(s)",
               f"{stats.mode.title()} scan complete", stats.alert_count, force=True)
    if opts.interactive and not opts.quiet:
        review_alerts(stats, report)
    return stats


def do_scan(mode, opts, paths=None):
    rpc_connect(force=True)
    rpc_update("Scanning your PC", f"{mode.title()} scan", 0, force=True)
    if mode == "full" and not is_admin() and not opts.quiet:
        print("  Not running as Administrator: protected folders, other users' profiles and some")
        print("  services will be skipped. Use menu option A to restart elevated.\n")
    stats = run_scan(mode, opts, paths)
    return finish_scan(stats, opts)


def run_watch(register, opts):
    startup_ok = register_startup() if register else True
    rpc_connect(force=True)
    seen = set()
    cycle = 0
    stop = threading.Event()
    if not opts.quiet:
        header("READY" if rpc_enabled else "OFFLINE")
        print(f"  Continuous protection | startup: {'ENABLED' if startup_ok else 'off'} | interval {SCAN_DELAY}s")
        print("  Ctrl+C stops DaniAV\n")
    try:
        while True:
            cycle += 1
            rpc_update("DaniAV is protecting your PC", f"Security cycle {cycle}", 0, force=True)
            quiet_opts = ScanOptions(**{**opts.__dict__, "quiet": True})
            stats = run_scan("quick", quiet_opts, announce=False, light=(cycle % 10 != 1))
            new = [a for a in stats.sorted_alerts() if a.key() not in seen]
            seen.update(a.key() for a in new)
            if opts.auto_quarantine:
                auto_quarantine(stats)
            if not opts.quiet:
                stamp = datetime.datetime.now().strftime("%H:%M:%S")
                print(f"  [{stamp}] cycle {cycle}: {fmt_int(stats.files_checked)} new/changed files, "
                      f"{stats.processes_checked} processes, {len(new)} new alert(s), {stats.alert_count} total")
                for alert in new:
                    print(f"      {sev_tag(alert.severity)} {alert.name} | {(alert.path or alert.detail)[:110]}")
                if any(SEV_RANK[a.severity] >= 3 for a in new):
                    try:
                        ctypes.windll.user32.MessageBeep(0x30)
                    except Exception:
                        pass
            rpc_update("System clean" if not stats.alerts else f"{stats.alert_count} alert(s)",
                       f"Cycle {cycle} complete", stats.alert_count, force=True)
            if stop.wait(SCAN_DELAY):
                break
    except KeyboardInterrupt:
        pass


def custom_scan_prompt(opts):
    target = ask("  Folder or drive to scan: ").strip('"')
    if not target or not Path(target).exists():
        print("  Path not found")
        return
    do_scan("custom", opts, [target])


def interactive_menu(opts):
    while True:
        header("READY" if rpc_enabled else "OFFLINE")
        print("  1  Quick scan          (system checks + user/temp/startup/download folders)")
        print("  2  FULL scan           (system checks + every fixed drive)")
        print("  3  Custom scan         (pick a folder or drive)")
        print("  4  System check only   (processes, startup, services, tasks, WMI, hosts, network)")
        print("  5  Continuous protection")
        print("  6  Windows Defender    (update / quick / full / threats)")
        print("  7  Full scan + Defender full scan")
        print("  8  Quarantine manager")
        print("  9  Reports and log")
        print("  S  Startup on/off      D  Discord         I  Import hash list")
        print("  A  Restart as Administrator")
        print("  0  Exit")
        print()
        choice = ask("  DaniAV > ").lower()

        if choice == "1":
            do_scan("quick", opts)
            pause()
        elif choice == "2":
            opts.removable = yes("  Include removable drives?", default=False)
            do_scan("full", opts)
            pause()
        elif choice == "3":
            custom_scan_prompt(opts)
            pause()
        elif choice == "4":
            do_scan("system", opts)
            pause()
        elif choice == "5":
            run_watch(register=False, opts=opts)
        elif choice == "6":
            defender_menu()
        elif choice == "7":
            do_scan("full", opts)
            print("\n  Starting Windows Defender full scan ...")
            defender_scan("full", None, yes("  Let Defender remove what it finds?"))
            pause()
        elif choice == "8":
            quarantine_manager()
        elif choice == "9":
            print(f"\n  Reports: {REPORT_DIR}\n  Log:     {LOG_FILE}")
            if yes("  Open reports folder?", default=True):
                open_path(REPORT_DIR)
        elif choice == "s":
            if yes("  Enable startup protection? (No = disable)", default=True):
                print("  Startup:", "ENABLED" if register_startup() else "FAILED")
            else:
                print("  Startup:", "DISABLED" if remove_startup() else "FAILED")
            pause()
        elif choice == "d":
            print("  Discord test:", "OK" if rpc_test() else "NOT CONFIGURED / FAILED")
            explain_discord()
            pause()
        elif choice == "i":
            source = ask("  Path to a file of SHA256 hashes (one per line, optional ',name'): ").strip('"')
            added, error = import_hashes(source)
            print(f"  Imported {added} hash(es)" + (f" - {error}" if error else ""))
            pause()
        elif choice == "a":
            if is_admin():
                print("  Already elevated")
            elif relaunch_as_admin():
                return
            else:
                print("  Elevation was cancelled or failed")
            pause()
        elif choice in ("0", "q", "exit"):
            return
        else:
            print("  Unknown option")
            time.sleep(0.8)


def parse_args():
    parser = argparse.ArgumentParser(prog=APP_NAME, description="Full-system Windows security scanner")
    parser.add_argument("--quick", action="store_true", help="quick scan of high-risk locations")
    parser.add_argument("--full", action="store_true", help="full scan of every fixed drive")
    parser.add_argument("--scan", metavar="PATH", action="append", help="scan a folder or drive (repeatable)")
    parser.add_argument("--system", action="store_true", help="system checks only, no file scan")
    parser.add_argument("--once", action="store_true", help="alias for --quick")
    parser.add_argument("--watch", action="store_true", help="continuous protection")
    parser.add_argument("--with-defender", action="store_true", help="also run a Defender scan afterwards")
    parser.add_argument("--defender-update", action="store_true", help="update Defender signatures and exit")
    parser.add_argument("--deep", action="store_true", help="include WinSxS and other normally skipped folders")
    parser.add_argument("--removable", action="store_true", help="include removable drives in full scans")
    parser.add_argument("--threads", type=int, help="worker threads")
    parser.add_argument("--no-cache", action="store_true", help="re-inspect every file")
    parser.add_argument("--auto-quarantine", action="store_true", help="quarantine high/critical file detections")
    parser.add_argument("--no-report", action="store_true")
    parser.add_argument("--import-hashes", metavar="FILE", help="add SHA256 hashes to the signature list")
    parser.add_argument("--list-quarantine", action="store_true")
    parser.add_argument("--elevate", action="store_true", help="restart as Administrator")
    parser.add_argument("--quiet", action="store_true", help="no console output (used by startup)")
    parser.add_argument("--no-update", action="store_true", help="skip the GitHub update check")
    parser.add_argument("--no-rpc", action="store_true")
    parser.add_argument("--no-startup", action="store_true")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    return parser.parse_args()


def main():
    global DISCORD_CLIENT_ID, rpc_enabled

    if os.name != "nt":
        print("DaniAV requires Windows.")
        return 1
    if sys.version_info < (3, 9):
        print("DaniAV needs Python 3.9 or newer.")
        return 1

    args = parse_args()

    if args.elevate and not is_admin():
        passthrough = [a for a in sys.argv[1:] if a != "--elevate"]
        return 0 if relaunch_as_admin(passthrough) else 1

    if (not args.no_update and not os.getenv("DANIAV_NO_UPDATE") and not os.getenv("DANIAV_UPDATED")
            and not (args.import_hashes or args.list_quarantine)):
        if check_for_update(quiet=args.quiet) and restart_self():
            return 0

    if not acquire_single_instance():
        print("DaniAV is already running.")
        return 1

    try:
        init_environment()
        enable_ansi()
        try:
            ctypes.windll.kernel32.SetConsoleTitleW(f"{APP_NAME} {VERSION}")
        except Exception:
            pass

        if args.no_rpc:
            DISCORD_CLIENT_ID = ""
            rpc_enabled = False

        opts = ScanOptions(deep=args.deep, removable=args.removable,
                           threads=max(1, min(64, args.threads or THREADS)),
                           use_cache=not args.no_cache, auto_quarantine=args.auto_quarantine,
                           write_report=not args.no_report, interactive=True, quiet=args.quiet)

        if args.import_hashes:
            added, error = import_hashes(args.import_hashes)
            print(f"Imported {added} hash(es)" + (f" - {error}" if error else ""))
            return 0
        if args.list_quarantine:
            for entry in load_manifest():
                print(f"{entry['id']}  {entry['detection']}  {entry['original']}")
            return 0
        if args.defender_update:
            ok, _ = defender_update()
            return 0 if ok else 1

        noninteractive = args.quick or args.once or args.full or args.scan or args.system
        if noninteractive:
            opts.interactive = sys.stdin is not None and sys.stdin.isatty() and not args.quiet
            if not args.quiet:
                header("READY" if rpc_configured() else "NOT CONFIGURED")
            if args.system:
                do_scan("system", opts)
            elif args.scan:
                do_scan("custom", opts, args.scan)
            elif args.full:
                do_scan("full", opts)
            else:
                do_scan("quick", opts)
            if args.with_defender:
                defender_scan("full" if args.full else "quick", None, remediate=False)
            return 0

        if args.watch:
            run_watch(register=not args.no_startup, opts=opts)
            return 0

        interactive_menu(opts)
        return 0

    except KeyboardInterrupt:
        print("\n  DaniAV stopped safely")
        log.info("DaniAV stopped by user")
        return 0
    except Exception as exc:
        log.error("Unhandled application error: %s", exc)
        log.error(traceback.format_exc())
        print(f"\n  Fatal error: {exc}\n  Details are in {LOG_FILE}")
        return 1
    finally:
        rpc_close()
        release_single_instance()


if __name__ == "__main__":
    raise SystemExit(main())
