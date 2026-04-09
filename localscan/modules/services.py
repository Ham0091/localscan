"""
Services security checks for LocalScan.
Checks installed software versions, suspicious scheduled tasks,
and startup program entries on both Windows and macOS.
"""

import platform
import plistlib
import subprocess
import sys
import logging
import re
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

PLATFORM = platform.system().lower()

# ---------------------------------------------------------------------------
# Software version detection via registry
# ---------------------------------------------------------------------------

# Registry paths to search for installed software
_UNINSTALL_PATHS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
]

# Known software display-name fragments and their friendly names
SOFTWARE_OF_INTEREST = {
    "java": "Java",
    "adobe reader": "Adobe Reader",
    "adobe acrobat reader": "Adobe Reader",
    "vlc": "VLC Media Player",
    "7-zip": "7-Zip",
    "google chrome": "Google Chrome",
    "mozilla firefox": "Mozilla Firefox",
}


def _get_installed_software_windows() -> List[Dict[str, str]]:
    """Enumerate installed software from the Windows registry."""
    if sys.platform != "win32":
        return []

    import winreg  # noqa: PLC0415

    software: List[Dict[str, str]] = []

    for path in _UNINSTALL_PATHS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as base_key:
                subkey_count, _, _ = winreg.QueryInfoKey(base_key)
                for i in range(subkey_count):
                    try:
                        subkey_name = winreg.EnumKey(base_key, i)
                        with winreg.OpenKey(base_key, subkey_name) as subkey:
                            try:
                                name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                                version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                                software.append({"name": str(name), "version": str(version)})
                            except FileNotFoundError:
                                pass
                    except Exception:  # noqa: BLE001
                        pass
        except Exception:  # noqa: BLE001
            pass

    # Also enumerate HKCU uninstall root
    hkcu_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, hkcu_path) as base_key:
            subkey_count, _, _ = winreg.QueryInfoKey(base_key)
            for i in range(subkey_count):
                try:
                    subkey_name = winreg.EnumKey(base_key, i)
                    with winreg.OpenKey(base_key, subkey_name) as subkey:
                        try:
                            name, _ = winreg.QueryValueEx(subkey, "DisplayName")
                            version, _ = winreg.QueryValueEx(subkey, "DisplayVersion")
                            software.append({"name": str(name), "version": str(version)})
                        except FileNotFoundError:
                            pass
                except Exception:  # noqa: BLE001
                    pass
    except Exception:  # noqa: BLE001
        pass

    return software


def _version_key(v: str):
    """Parse a version string into a list of ints for comparison."""
    try:
        return [int(x) for x in v.split(".") if x.isdigit()]
    except Exception:
        return [0]


def check_software_versions() -> List[Dict[str, Any]]:
    """Detect installed versions of known software and flag them for review."""
    findings = []

    if PLATFORM == "darwin":
        apps_to_find = {
            "Google Chrome.app": "Google Chrome",
            "Firefox.app": "Mozilla Firefox",
            "VLC.app": "VLC Media Player",
            "LibreOffice.app": "LibreOffice",
            "zoom.us.app": "Zoom",
            "Microsoft Word.app": "Microsoft Word",
            "Microsoft Excel.app": "Microsoft Excel",
        }
        for app_filename, friendly_name in apps_to_find.items():
            app_path = Path("/Applications") / app_filename
            plist_path = app_path / "Contents" / "Info.plist"
            if not app_path.exists():
                continue
            try:
                with open(plist_path, "rb") as f:
                    plist = plistlib.load(f)
                version = plist.get(
                    "CFBundleShortVersionString", "Unknown"
                )
                findings.append({
                    "name": (
                        f"Installed Software Detected: "
                        f"{friendly_name} v{version}"
                    ),
                    "severity": "Low",
                    "description": (
                        f"{friendly_name} version {version} is installed. "
                        "Automated update status could not be verified."
                    ),
                    "recommendation": (
                        f"Ensure {friendly_name} is updated to the latest "
                        "version. Enable automatic updates where available."
                    ),
                })
            except Exception:
                findings.append({
                    "name": (
                        f"Installed Software Detected: {friendly_name}"
                    ),
                    "severity": "Low",
                    "description": (
                        f"{friendly_name} is installed but its version "
                        "could not be read from Info.plist."
                    ),
                    "recommendation": (
                        f"Verify {friendly_name} is up to date."
                    ),
                })
        if not findings:
            findings.append({
                "name": "Installed Software Versions",
                "severity": "Info",
                "description": (
                    "No tracked software detected in /Applications."
                ),
                "recommendation": "No action required.",
            })
        return findings

    if sys.platform != "win32":
        return [{
            "name": "Installed Software Versions",
            "severity": "Info",
            "description": "Software version check skipped \u2014 not running on Windows.",
            "recommendation": "Run LocalScan on a Windows system.",
        }]

    installed = _get_installed_software_windows()

    detected: Dict[str, str] = {}
    for entry in installed:
        lower_name = entry["name"].lower()
        for key, friendly in SOFTWARE_OF_INTEREST.items():
            if key in lower_name:
                # Keep the entry with the highest version string
                if friendly not in detected or _version_key(entry["version"]) > _version_key(detected[friendly]):
                    detected[friendly] = entry["version"]

    if detected:
        for friendly, version in detected.items():
            findings.append({
                "name": f"Installed Software Detected: {friendly} v{version}",
                "severity": "Low",
                "description": (
                    f"{friendly} version {version} is installed. "
                    "Automated update status could not be verified."
                ),
                "recommendation": (
                    f"Ensure {friendly} is updated to the latest version. "
                    "Enable automatic updates where available."
                ),
            })
    else:
        findings.append({
            "name": "Installed Software Versions",
            "severity": "Info",
            "description": "No tracked software (Java, Adobe Reader, VLC, 7-Zip, Chrome, Firefox) detected.",
            "recommendation": "No action required.",
        })

    return findings


# ---------------------------------------------------------------------------
# Scheduled tasks
# ---------------------------------------------------------------------------

_SUSPICIOUS_TASK_PATTERNS = [
    re.compile(r"temp", re.IGNORECASE),
    re.compile(r"\\appdata\\", re.IGNORECASE),
    re.compile(r"powershell.*-enc", re.IGNORECASE),
    re.compile(r"cmd.*\/c", re.IGNORECASE),
    re.compile(r"wscript|cscript", re.IGNORECASE),
    re.compile(r"mshta", re.IGNORECASE),
    re.compile(r"regsvr32", re.IGNORECASE),
    re.compile(r"rundll32", re.IGNORECASE),
]


def check_scheduled_tasks() -> List[Dict[str, Any]]:
    """Check scheduled tasks for suspicious entries."""
    findings = []

    if PLATFORM == "darwin":
        LAUNCH_DIRS = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
            Path("/Library/LaunchDaemons"),
        ]
        # /System/Library/LaunchDaemons is scanned for count only —
        # too many false positives from Apple's own daemons
        SYSTEM_LAUNCH_DAEMONS = Path("/System/Library/LaunchDaemons")

        suspicious_entries = []
        plist_count = 0

        for launch_dir in LAUNCH_DIRS:
            if not launch_dir.exists():
                continue
            for plist_file in launch_dir.glob("*.plist"):
                if plist_file.is_symlink():
                    continue
                plist_count += 1
                try:
                    with open(plist_file, "rb") as f:
                        plist = plistlib.load(f)
                    args = plist.get("ProgramArguments", [])
                    args_str = " ".join(str(a) for a in args)
                    run_at_load = plist.get("RunAtLoad", False)
                    label = plist.get("Label", str(plist_file.name))

                    # Apply existing suspicious patterns
                    flagged = False
                    for pattern in _SUSPICIOUS_TASK_PATTERNS:
                        if pattern.search(args_str):
                            suspicious_entries.append(
                                f"{label} | {args_str[:120]}"
                            )
                            flagged = True
                            break

                    # Additional check: RunAtLoad with risky program
                    if not flagged and run_at_load:
                        risky_terms = [
                            "curl", "wget", "bash -c",
                            "/tmp/", "/var/tmp/",
                        ]
                        if any(t in args_str for t in risky_terms):
                            suspicious_entries.append(
                                f"{label} [RunAtLoad+risky] | "
                                f"{args_str[:120]}"
                            )
                except Exception:
                    pass

        # Count Apple system daemons (info only)
        system_daemon_count = 0
        try:
            if SYSTEM_LAUNCH_DAEMONS.exists():
                system_daemon_count = sum(
                    1 for p in SYSTEM_LAUNCH_DAEMONS.glob("*.plist")
                    if not p.is_symlink()
                )
        except Exception:
            pass

        if suspicious_entries:
            findings.append({
                "name": "Suspicious Launch Agents/Daemons Detected",
                "severity": "High",
                "description": (
                    f"{len(suspicious_entries)} LaunchAgent/Daemon "
                    "plist(s) contain suspicious patterns "
                    "(temp paths, curl/wget, encoded commands, etc.):\n"
                    + "\n".join(suspicious_entries[:20])
                ),
                "recommendation": (
                    "Review these plist files and remove any that are "
                    "not legitimate. Use "
                    "'sudo launchctl disable <label>' to disable."
                ),
            })
        else:
            findings.append({
                "name": "Scheduled Tasks / Launch Agents",
                "severity": "Info",
                "description": (
                    f"No suspicious LaunchAgents/Daemons detected "
                    f"({plist_count} plists scanned across user and "
                    f"system directories). "
                    f"{system_daemon_count} Apple system daemons "
                    "present (not scanned for suspicious patterns)."
                ),
                "recommendation": (
                    "Periodically review LaunchAgents for unexpected "
                    "entries."
                ),
            })
        return findings

    if sys.platform != "win32":
        return [{
            "name": "Scheduled Tasks",
            "severity": "Info",
            "description": "Scheduled task check skipped \u2014 not running on Windows.",
            "recommendation": "Run LocalScan on a Windows system.",
        }]

    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        suspicious: List[str] = []
        lines = result.stdout.splitlines()
        # CSV header is on the first line; subsequent lines are task entries
        for line in lines[1:]:
            for pattern in _SUSPICIOUS_TASK_PATTERNS:
                if pattern.search(line):
                    # Extract task name (first CSV field)
                    parts = line.split('","')
                    task_name = parts[0].strip('"') if parts else line[:80]
                    if task_name and task_name not in suspicious:
                        suspicious.append(task_name)
                    break

        if suspicious:
            findings.append({
                "name": "Suspicious Scheduled Tasks Detected",
                "severity": "High",
                "description": (
                    f"{len(suspicious)} scheduled task(s) contain suspicious patterns "
                    "(temp paths, encoded PowerShell, mshta, etc.):\n"
                    + "\n".join(suspicious[:20])
                ),
                "recommendation": (
                    "Review these tasks in Task Scheduler and remove any that are "
                    "not legitimate. Use 'schtasks /delete /tn <name> /f' to remove."
                ),
            })
        else:
            findings.append({
                "name": "Scheduled Tasks",
                "severity": "Info",
                "description": "No obviously suspicious scheduled tasks were detected.",
                "recommendation": "Periodically review scheduled tasks for unexpected entries.",
            })

    except Exception as exc:  # noqa: BLE001
        findings.append({
            "name": "Scheduled Tasks",
            "severity": "Info",
            "description": f"Could not enumerate scheduled tasks: {exc}",
            "recommendation": "Run 'schtasks /query /fo LIST /v' manually.",
        })

    return findings


# ---------------------------------------------------------------------------
# Startup programs
# ---------------------------------------------------------------------------

_STARTUP_REGISTRY_PATHS = [
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
]

_STARTUP_SUSPICIOUS_PATTERNS = [
    re.compile(r"\\temp\\", re.IGNORECASE),
    re.compile(r"\\appdata\\local\\temp\\", re.IGNORECASE),
    re.compile(r"powershell.*-enc", re.IGNORECASE),
    re.compile(r"mshta|wscript|cscript", re.IGNORECASE),
    re.compile(r"regsvr32|rundll32", re.IGNORECASE),
]


def _get_startup_entries_windows() -> List[Dict[str, str]]:
    """Read startup registry keys from HKLM and HKCU."""
    if sys.platform != "win32":
        return []

    import winreg  # noqa: PLC0415

    hive_map = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
    }
    entries: List[Dict[str, str]] = []

    for path, hive_name in _STARTUP_REGISTRY_PATHS:
        hive = hive_map[hive_name]
        try:
            with winreg.OpenKey(hive, path) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                        entries.append({"hive": hive_name, "path": path, "name": name, "value": str(value)})
                        index += 1
                    except OSError:
                        break
        except FileNotFoundError:
            pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("Startup registry read failed (%s\\%s): %s", hive_name, path, exc)

    return entries


def check_startup_programs() -> List[Dict[str, Any]]:
    """Check startup registry entries for suspicious programs."""
    findings = []

    if PLATFORM == "darwin":
        STARTUP_DIRS = [
            Path.home() / "Library" / "LaunchAgents",
            Path("/Library/LaunchAgents"),
        ]
        entries = []
        suspicious = []

        for launch_dir in STARTUP_DIRS:
            if not launch_dir.exists():
                continue
            for plist_file in launch_dir.glob("*.plist"):
                if plist_file.is_symlink():
                    continue
                try:
                    with open(plist_file, "rb") as f:
                        plist = plistlib.load(f)
                    label = plist.get("Label", str(plist_file.name))
                    args = plist.get("ProgramArguments", [])
                    args_str = " ".join(str(a) for a in args)
                    entries.append({
                        "dir": str(launch_dir),
                        "name": label,
                        "value": args_str,
                    })
                    for pattern in _STARTUP_SUSPICIOUS_PATTERNS:
                        if pattern.search(args_str):
                            suspicious.append(
                                f"{launch_dir.name} | "
                                f"{label} = {args_str[:120]}"
                            )
                            break
                except Exception:
                    pass

        if suspicious:
            return [{
                "name": "Suspicious Startup LaunchAgent(s) Detected",
                "severity": "High",
                "description": (
                    f"{len(suspicious)} LaunchAgent entry/entries "
                    "contain suspicious patterns:\n"
                    + "\n".join(suspicious[:20])
                ),
                "recommendation": (
                    "Review these LaunchAgents using a tool like "
                    "KnockKnock or Autoruns for Mac. Remove entries "
                    "that are not legitimate."
                ),
            }]
        elif entries:
            return [{
                "name": "Startup LaunchAgents",
                "severity": "Info",
                "description": (
                    f"{len(entries)} LaunchAgent entry/entries found. "
                    "None matched suspicious patterns."
                ),
                "recommendation": (
                    "Periodically review LaunchAgents for unexpected "
                    "programs."
                ),
            }]
        else:
            return [{
                "name": "Startup LaunchAgents",
                "severity": "Info",
                "description": "No LaunchAgent entries found.",
                "recommendation": "No action required.",
            }]

    if sys.platform != "win32":
        return [{
            "name": "Startup Programs",
            "severity": "Info",
            "description": "Startup program check skipped \u2014 not running on Windows.",
            "recommendation": "Run LocalScan on a Windows system.",
        }]

    entries = _get_startup_entries_windows()
    suspicious: List[str] = []

    for entry in entries:
        for pattern in _STARTUP_SUSPICIOUS_PATTERNS:
            if pattern.search(entry["value"]):
                suspicious.append(
                    f"{entry['hive']}\\{entry['path']} | {entry['name']} = {entry['value'][:120]}"
                )
                break

    if suspicious:
        findings.append({
            "name": "Suspicious Startup Program(s) Detected",
            "severity": "High",
            "description": (
                f"{len(suspicious)} startup registry entry/entries contain suspicious patterns:\n"
                + "\n".join(suspicious[:20])
            ),
            "recommendation": (
                "Review these startup entries using Autoruns (Sysinternals) or "
                "Task Manager > Startup tab. Remove entries that are not legitimate."
            ),
        })
    elif entries:
        findings.append({
            "name": "Startup Programs",
            "severity": "Info",
            "description": (
                f"{len(entries)} startup program entry/entries found. "
                "None matched suspicious patterns."
            ),
            "recommendation": "Periodically review startup entries for unexpected programs.",
        })
    else:
        findings.append({
            "name": "Startup Programs",
            "severity": "Info",
            "description": "No startup registry entries found.",
            "recommendation": "No action required.",
        })

    return findings


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def run_checks(
    progress_callback=None,
    quick: bool = False,
    is_admin: bool = False,
) -> List[Dict[str, Any]]:
    """Run all services checks and return findings."""
    findings = []

    sub_checks = [
        ("Checking installed software versions", check_software_versions),
        ("Checking scheduled tasks", check_scheduled_tasks),
        ("Checking startup programs", check_startup_programs),
    ]

    for description, check_fn in sub_checks:
        if progress_callback:
            progress_callback(description)
        try:
            result = check_fn()
            findings.extend(result)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Services check '%s' failed: %s", description, exc)
            findings.append({
                "name": f"Check Failed: {description}",
                "severity": "Info",
                "description": f"An error occurred: {exc}",
                "recommendation": "Check scanner.log for details.",
            })

    return findings
