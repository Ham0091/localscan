"""
Services security checks for LocalScan.
Checks installed software versions, suspicious scheduled tasks,
and startup program entries.
"""

import subprocess
import sys
import logging
import re
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

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

    return software


def check_software_versions() -> List[Dict[str, Any]]:
    """Detect installed versions of known software and flag them for review."""
    findings = []

    if sys.platform != "win32":
        return [{
            "name": "Installed Software Versions",
            "severity": "Info",
            "description": "Software version check skipped — not running on Windows.",
            "recommendation": "Run LocalScan on a Windows system.",
        }]

    installed = _get_installed_software_windows()

    detected: Dict[str, str] = {}
    for entry in installed:
        lower_name = entry["name"].lower()
        for key, friendly in SOFTWARE_OF_INTEREST.items():
            if key in lower_name:
                # Keep first (most recent) match
                if friendly not in detected:
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

    if sys.platform != "win32":
        return [{
            "name": "Scheduled Tasks",
            "severity": "Info",
            "description": "Scheduled task check skipped — not running on Windows.",
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

    if sys.platform != "win32":
        return [{
            "name": "Startup Programs",
            "severity": "Info",
            "description": "Startup program check skipped — not running on Windows.",
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
