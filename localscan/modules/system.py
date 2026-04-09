"""
System security checks for LocalScan.
Checks OS version, antivirus, privilege controls, guest account, auto-login,
execution policy / Gatekeeper, disk encryption / SMB v1, and remote access
on both Windows and macOS.
"""

import json
import platform
import subprocess
import sys
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

PLATFORM = platform.system().lower()

# ---------------------------------------------------------------------------
# Helper — safe registry read (Windows only)
# ---------------------------------------------------------------------------


def _reg_read(hive, path: str, name: str) -> tuple:
    """
    Read a single registry value.
    Returns (value, "ok") on success.
    Returns (None, "missing") if the key or value does not exist.
    Returns (None, "error") on access denied or any other failure.
    """
    if sys.platform != "win32":
        return None, "missing"
    try:
        import winreg  # noqa: PLC0415
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value, "ok"
    except FileNotFoundError:
        return None, "missing"
    except PermissionError:
        return None, "error"
    except Exception:  # noqa: BLE001
        return None, "error"


def _reg_read_hklm(path: str, name: str):
    """Convenience wrapper — returns value or None."""
    if sys.platform != "win32":
        return None
    import winreg  # noqa: PLC0415
    value, _ = _reg_read(winreg.HKEY_LOCAL_MACHINE, path, name)
    return value


def _reg_read_hkcu(path: str, name: str):
    """Convenience wrapper — returns value or None."""
    if sys.platform != "win32":
        return None
    import winreg  # noqa: PLC0415
    value, _ = _reg_read(winreg.HKEY_CURRENT_USER, path, name)
    return value


def _reg_read_hklm_full(path: str, name: str) -> tuple:
    """Returns (value, status) where status is 'ok', 'missing', or 'error'."""
    if sys.platform != "win32":
        return None, "missing"
    import winreg  # noqa: PLC0415
    return _reg_read(winreg.HKEY_LOCAL_MACHINE, path, name)


def _reg_read_hkcu_full(path: str, name: str) -> tuple:
    """Returns (value, status) where status is 'ok', 'missing', or 'error'."""
    if sys.platform != "win32":
        return None, "missing"
    import winreg  # noqa: PLC0415
    return _reg_read(winreg.HKEY_CURRENT_USER, path, name)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_os_version() -> Dict[str, Any]:
    """Return OS version and patch level information."""
    if PLATFORM == "darwin":
        try:
            result = subprocess.run(
                ["sw_vers"],
                capture_output=True, text=True, timeout=10,
            )
            info = {}
            for line in result.stdout.splitlines():
                if ":" in line:
                    key, _, val = line.partition(":")
                    info[key.strip()] = val.strip()
            product = info.get("ProductName", "macOS")
            version = info.get("ProductVersion", "Unknown")
            build = info.get("BuildVersion", "Unknown")
            return {
                "name": "macOS Version and Build",
                "severity": "Info",
                "description": f"OS: {product} {version} (Build {build})",
                "recommendation": (
                    "Ensure macOS is updated via System Settings > "
                    "General > Software Update."
                ),
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "name": "macOS Version and Build",
                "severity": "Info",
                "description": f"Could not determine macOS version: {exc}",
                "recommendation": "Verify macOS version manually.",
            }

    if sys.platform != "win32":
        return {
            "name": "OS Version",
            "severity": "Info",
            "description": "Not running on Windows or macOS — check skipped.",
            "recommendation": "Run LocalScan on a supported system for full coverage.",
        }

    current_version = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    product_name = _reg_read_hklm(current_version, "ProductName") or "Unknown"
    build = _reg_read_hklm(current_version, "CurrentBuild") or "Unknown"
    ubr = _reg_read_hklm(current_version, "UBR")
    full_build = f"{build}.{ubr}" if ubr is not None else build

    return {
        "name": "Windows Version and Patch Level",
        "severity": "Info",
        "description": f"OS: {product_name} | Build: {full_build}",
        "recommendation": (
            "Ensure Windows Update is enabled and the system is fully patched. "
            "End-of-support versions (e.g., Windows 7, Windows 8.1) should be upgraded."
        ),
    }


def _check_third_party_av() -> List[Dict[str, Any]]:
    """
    Query Windows Security Center for registered AV products.
    Returns list of dicts with 'name' and 'active' keys.
    """
    try:
        sc_result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command",
             "Get-CimInstance -Namespace root/SecurityCenter2 "
             "-ClassName AntiVirusProduct | "
             "Select-Object displayName, productState | ConvertTo-Json"],
            capture_output=True, text=True, timeout=30,
        )
        if sc_result.returncode != 0 or not sc_result.stdout.strip():
            return []
        data = json.loads(sc_result.stdout)
        if isinstance(data, dict):
            data = [data]
        products = []
        for item in data:
            display_name = item.get("displayName", "")
            product_state = item.get("productState", 0)
            # Bit 12 of productState indicates whether the AV is active
            is_active = bool(product_state & 0x1000)
            products.append({"name": display_name, "active": is_active})
        return products
    except Exception:  # noqa: BLE001
        return []


def check_antivirus() -> List[Dict[str, Any]]:
    """Check antivirus status — Defender on Windows, XProtect on macOS."""
    findings = []

    if PLATFORM == "darwin":
        # Sub-check 1 — XProtect present
        xprotect_path = Path(
            "/System/Library/CoreServices/XProtect.bundle"
        )
        if not xprotect_path.exists():
            findings.append({
                "name": "XProtect Not Found",
                "severity": "Critical",
                "description": (
                    "The XProtect malware protection bundle was not found "
                    "at the expected path."
                ),
                "recommendation": (
                    "This may indicate a corrupted macOS installation. "
                    "Reinstall macOS or verify system integrity."
                ),
            })
        else:
            findings.append({
                "name": "XProtect Present",
                "severity": "Info",
                "description": "XProtect malware protection bundle is present.",
                "recommendation": "No action required.",
            })

        # Sub-check 2 — XProtect last updated
        try:
            result = subprocess.run(
                ["system_profiler", "SPInstallHistoryDataType"],
                capture_output=True, text=True, timeout=60,
            )
            xprotect_dates: List[str] = []
            lines = result.stdout.splitlines()
            for i, line in enumerate(lines):
                if "XProtect" in line:
                    for j in range(max(0, i - 3), min(len(lines), i + 5)):
                        stripped = lines[j].strip()
                        if stripped.startswith("Install Date:"):
                            date_str = stripped.split(":", 1)[1].strip()
                            xprotect_dates.append(date_str)
            if xprotect_dates:
                latest = xprotect_dates[-1]
                try:
                    last_update = None
                    for fmt in ("%m/%d/%Y", "%Y-%m-%d", "%m/%d/%y"):
                        try:
                            last_update = datetime.strptime(latest, fmt)
                            break
                        except ValueError:
                            continue
                    if last_update and (datetime.now() - last_update) > timedelta(days=7):
                        findings.append({
                            "name": "XProtect Definitions May Be Outdated",
                            "severity": "High",
                            "description": (
                                f"The most recent XProtect update was on {latest}. "
                                "Definitions older than 7 days may leave the system exposed."
                            ),
                            "recommendation": (
                                "Check for macOS updates via System Settings > "
                                "General > Software Update."
                            ),
                        })
                    elif last_update:
                        findings.append({
                            "name": "XProtect Definitions Current",
                            "severity": "Info",
                            "description": f"XProtect was last updated on {latest}.",
                            "recommendation": "No action required.",
                        })
                    else:
                        findings.append({
                            "name": "XProtect Update Date Unparseable",
                            "severity": "Low",
                            "description": (
                                f"Found XProtect update entry ({latest}) but could "
                                "not parse the date."
                            ),
                            "recommendation": "Verify XProtect update status manually.",
                        })
                except Exception:  # noqa: BLE001
                    findings.append({
                        "name": "XProtect Update Date Unparseable",
                        "severity": "Low",
                        "description": "Could not parse XProtect update date.",
                        "recommendation": "Verify XProtect update status manually.",
                    })
            else:
                findings.append({
                    "name": "XProtect Update History Not Found",
                    "severity": "Low",
                    "description": (
                        "No XProtect entries found in the install history."
                    ),
                    "recommendation": (
                        "Verify XProtect is receiving updates via "
                        "System Settings > General > Software Update."
                    ),
                })
        except Exception as exc:  # noqa: BLE001
            findings.append({
                "name": "XProtect Update Check",
                "severity": "Info",
                "description": f"Could not check XProtect update history: {exc}",
                "recommendation": "Verify XProtect status manually.",
            })

        # Sub-check 3 — Third-party AV processes
        known_av = {
            "CbOsxSensorService": "Carbon Black",
            "com.malwarebytes": "Malwarebytes",
            "SentinelAgent": "SentinelOne",
            "com.crowdstrike": "CrowdStrike Falcon",
        }
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, timeout=15,
            )
            for key, friendly_name in known_av.items():
                if key in result.stdout:
                    findings.append({
                        "name": f"{friendly_name} Detected Running",
                        "severity": "Info",
                        "description": (
                            f"Third-party antivirus process '{key}' "
                            f"({friendly_name}) is running."
                        ),
                        "recommendation": "No action required.",
                    })
        except Exception:  # noqa: BLE001
            pass

        return findings

    if sys.platform != "win32":
        return [{
            "name": "Antivirus Status",
            "severity": "Info",
            "description": "Not running on Windows or macOS — check skipped.",
            "recommendation": "Run LocalScan on a supported system.",
        }]

    # --- Windows: third-party AV awareness (Fix A3) ---
    third_party_av = _check_third_party_av()
    active_third_party = [
        p for p in third_party_av
        if p["active"] and "windows defender" not in p["name"].lower()
    ]

    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command",
             "Get-MpComputerStatus | Select-Object -Property "
             "AntivirusEnabled,RealTimeProtectionEnabled,AntispywareSignatureAge | "
             "ConvertTo-Json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        data = json.loads(result.stdout)

        av_enabled = data.get("AntivirusEnabled", False)
        rtp_enabled = data.get("RealTimeProtectionEnabled", False)
        sig_age = data.get("AntispywareSignatureAge", -1)

        if not av_enabled:
            if active_third_party:
                tp_name = active_third_party[0]["name"]
                findings.append({
                    "name": "Windows Defender Disabled \u2014 Third-Party AV Active",
                    "severity": "Info",
                    "description": (
                        f"Windows Defender is disabled, but {tp_name} "
                        "is registered and active as the system antivirus."
                    ),
                    "recommendation": (
                        "Ensure your third-party AV has real-time protection "
                        "enabled and definitions are current."
                    ),
                })
            else:
                findings.append({
                    "name": "Windows Defender Antivirus Disabled",
                    "severity": "Critical",
                    "description": "Windows Defender Antivirus is not enabled.",
                    "recommendation": "Enable Windows Defender via Windows Security settings.",
                })
        else:
            findings.append({
                "name": "Windows Defender Antivirus",
                "severity": "Info",
                "description": "Windows Defender Antivirus is enabled.",
                "recommendation": "No action required.",
            })

        if not rtp_enabled:
            findings.append({
                "name": "Windows Defender Real-Time Protection Disabled",
                "severity": "High",
                "description": "Real-time protection is turned off.",
                "recommendation": "Enable real-time protection in Windows Security settings.",
            })

        if isinstance(sig_age, int) and sig_age > 7:
            findings.append({
                "name": "Windows Defender Definitions Outdated",
                "severity": "High",
                "description": (
                    f"Antispyware/antivirus definitions are {sig_age} day(s) old. "
                    "Definitions older than 7 days may leave the system exposed."
                ),
                "recommendation": "Run 'Update-MpSignature' in PowerShell or check for updates.",
            })

    except Exception as exc:  # noqa: BLE001
        logger.warning("Defender check failed: %s", exc)
        findings.append({
            "name": "Windows Defender",
            "severity": "Info",
            "description": f"Could not query Windows Defender status: {exc}",
            "recommendation": "Verify Defender status manually via Windows Security.",
        })

    return findings


def check_software_updates() -> Dict[str, Any]:
    """Check software update configuration."""
    if PLATFORM == "darwin":
        try:
            result = subprocess.run(
                ["softwareupdate", "--list"],
                capture_output=True, text=True, timeout=60,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return {
                    "name": "macOS Software Updates",
                    "severity": "Info",
                    "description": "Software update state could not be determined.",
                    "recommendation": (
                        "Check for updates via System Settings > General > "
                        "Software Update."
                    ),
                }
            pending = []
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if stripped.startswith("*") or stripped.startswith("-"):
                    name = stripped.lstrip("*- ").strip()
                    if name:
                        pending.append(name)
            if pending:
                update_list = ", ".join(pending[:10])
                return {
                    "name": "macOS Software Updates Available",
                    "severity": "Medium",
                    "description": f"{len(pending)} pending update(s): {update_list}",
                    "recommendation": (
                        "Install updates: sudo softwareupdate --install --all"
                    ),
                }
            return {
                "name": "macOS Software Updates",
                "severity": "Info",
                "description": "macOS is up to date.",
                "recommendation": "No action required.",
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "name": "macOS Software Updates",
                "severity": "Info",
                "description": f"Could not check for software updates: {exc}",
                "recommendation": "Check for updates manually.",
            }

    if sys.platform != "win32":
        return {
            "name": "Software Update Configuration",
            "severity": "Info",
            "description": "Not running on Windows or macOS \u2014 check skipped.",
            "recommendation": "Run LocalScan on a supported system.",
        }

    au_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    no_auto_update, nau_status = _reg_read_hklm_full(au_path, "NoAutoUpdate")
    au_options = _reg_read_hklm(au_path, "AUOptions")

    if nau_status == "error":
        return {
            "name": "Windows Update \u2014 State Unknown",
            "severity": "Low",
            "description": (
                "Windows Update policy state could not be read from "
                "the registry."
            ),
            "recommendation": "Verify Windows Update configuration manually.",
        }

    if no_auto_update == 1:
        return {
            "name": "Windows Update \u2014 Automatic Updates Disabled",
            "severity": "High",
            "description": (
                "The registry policy 'NoAutoUpdate' is set to 1, "
                "disabling automatic Windows updates."
            ),
            "recommendation": (
                "Enable automatic updates via Group Policy or Settings > "
                "Windows Update > Advanced Options."
            ),
        }

    if au_options is not None and au_options < 3:
        return {
            "name": "Windows Update \u2014 Notify Only (No Auto-Install)",
            "severity": "Medium",
            "description": (
                f"Windows Update AUOptions is {au_options}. "
                "Updates are not automatically downloaded or installed."
            ),
            "recommendation": (
                "Set AUOptions to 4 (auto-download and install) "
                "to ensure timely patching."
            ),
        }

    return {
        "name": "Windows Update Configuration",
        "severity": "Info",
        "description": "Windows Update appears to be configured for automatic updates.",
        "recommendation": "No action required.",
    }


def check_privilege_controls() -> Dict[str, Any]:
    """Check UAC (Windows) or SIP (macOS)."""
    if PLATFORM == "darwin":
        try:
            result = subprocess.run(
                ["csrutil", "status"],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout.lower()
            if "disabled" in output:
                return {
                    "name": "System Integrity Protection (SIP) Disabled",
                    "severity": "High",
                    "description": (
                        "SIP is disabled. System files and processes "
                        "are not protected from modification."
                    ),
                    "recommendation": (
                        "Re-enable SIP by booting into Recovery Mode "
                        "and running 'csrutil enable'."
                    ),
                }
            elif "enabled" in output:
                return {
                    "name": "System Integrity Protection (SIP) Enabled",
                    "severity": "Info",
                    "description": "System Integrity Protection is enabled.",
                    "recommendation": "No action required.",
                }
            else:
                return {
                    "name": "System Integrity Protection (SIP) \u2014 State Unknown",
                    "severity": "Low",
                    "description": "SIP state could not be determined from csrutil output.",
                    "recommendation": "Run 'csrutil status' manually to verify.",
                }
        except Exception as exc:  # noqa: BLE001
            return {
                "name": "System Integrity Protection (SIP)",
                "severity": "Info",
                "description": f"Could not determine SIP state: {exc}",
                "recommendation": "Run 'csrutil status' manually.",
            }

    if sys.platform != "win32":
        return {
            "name": "Privilege Controls",
            "severity": "Info",
            "description": "Not running on Windows or macOS \u2014 check skipped.",
            "recommendation": "Run LocalScan on a supported system.",
        }

    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    enable_lua, status = _reg_read_hklm_full(path, "EnableLUA")

    if status == "error":
        return {
            "name": "User Account Control (UAC) \u2014 State Unknown",
            "severity": "Medium",
            "description": (
                "UAC state could not be read from the registry "
                "(access denied or unexpected error). The system may or may not "
                "have UAC enabled."
            ),
            "recommendation": (
                "Verify UAC state manually via Control Panel > "
                "User Accounts."
            ),
        }

    if enable_lua == 0:
        return {
            "name": "User Account Control (UAC) Disabled",
            "severity": "Critical",
            "description": "UAC is disabled (EnableLUA = 0). Applications run with full admin rights.",
            "recommendation": (
                "Enable UAC by setting HKLM\\...\\Policies\\System\\EnableLUA = 1 "
                "or via the Control Panel."
            ),
        }

    return {
        "name": "User Account Control (UAC)",
        "severity": "Info",
        "description": "UAC is enabled.",
        "recommendation": "No action required.",
    }


def check_guest_account() -> Dict[str, Any]:
    """Check whether the built-in Guest account is enabled."""
    if PLATFORM == "darwin":
        try:
            result = subprocess.run(
                ["defaults", "read",
                 "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout.strip()
            if output == "1":
                return {
                    "name": "Guest Account Enabled",
                    "severity": "High",
                    "description": (
                        "The macOS Guest account is enabled. "
                        "It allows unauthenticated access to the system."
                    ),
                    "recommendation": (
                        "Disable the Guest account via System Settings > "
                        "Users & Groups."
                    ),
                }
            elif output == "0" or result.returncode != 0:
                return {
                    "name": "Guest Account",
                    "severity": "Info",
                    "description": "The macOS Guest account is disabled.",
                    "recommendation": "No action required.",
                }
            else:
                return {
                    "name": "Guest Account \u2014 State Unknown",
                    "severity": "Info",
                    "description": "Guest account state could not be determined.",
                    "recommendation": "Verify via System Settings > Users & Groups.",
                }
        except Exception as exc:  # noqa: BLE001
            return {
                "name": "Guest Account",
                "severity": "Info",
                "description": f"Could not check Guest account status: {exc}",
                "recommendation": "Verify via System Settings > Users & Groups.",
            }

    if sys.platform != "win32":
        return {
            "name": "Guest Account",
            "severity": "Info",
            "description": "Not running on Windows or macOS \u2014 check skipped.",
            "recommendation": "Run LocalScan on a supported system.",
        }

    # Windows: locale-safe query via SID-501 (Fix A2)
    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command",
             "Get-LocalUser -Name (Get-LocalUser | "
             "Where-Object {$_.SID -like '*-501'}).Name | "
             "Select-Object -ExpandProperty Enabled"],
            capture_output=True, text=True, timeout=15,
        )
        output = result.stdout.strip().lower()
        if result.returncode != 0 or not output:
            return {
                "name": "Guest Account \u2014 State Unknown",
                "severity": "Info",
                "description": "Guest account state could not be determined.",
                "recommendation": (
                    "Verify manually via Computer Management > "
                    "Local Users and Groups."
                ),
            }
        if output == "true":
            return {
                "name": "Guest Account Enabled",
                "severity": "High",
                "description": (
                    "The built-in Guest account is active. "
                    "It allows unauthenticated access to the system."
                ),
                "recommendation": (
                    "Disable the Guest account: 'net user Guest /active:no'"
                ),
            }
        elif output == "false":
            return {
                "name": "Guest Account",
                "severity": "Info",
                "description": "The built-in Guest account is disabled.",
                "recommendation": "No action required.",
            }
        return {
            "name": "Guest Account \u2014 State Unknown",
            "severity": "Info",
            "description": f"Unexpected output from Guest account query: {output}",
            "recommendation": (
                "Verify manually via Computer Management > "
                "Local Users and Groups."
            ),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "name": "Guest Account",
            "severity": "Info",
            "description": f"Could not check Guest account status: {exc}",
            "recommendation": "Verify manually with 'net user Guest'.",
        }


def check_autologin() -> Dict[str, Any]:
    """Check whether auto-login credentials are stored."""
    if PLATFORM == "darwin":
        try:
            result = subprocess.run(
                ["defaults", "read",
                 "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                username = result.stdout.strip()
                return {
                    "name": "Auto-Login Enabled",
                    "severity": "Critical",
                    "description": (
                        f"The system is configured to automatically log "
                        f"in as '{username}' without requiring a password."
                    ),
                    "recommendation": (
                        "Disable auto-login via System Settings > "
                        "Users & Groups > uncheck 'Automatically log in as'."
                    ),
                }
            return {
                "name": "Auto-Login Configuration",
                "severity": "Info",
                "description": "Auto-login is not configured.",
                "recommendation": "No action required.",
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "name": "Auto-Login Configuration",
                "severity": "Info",
                "description": f"Could not check auto-login state: {exc}",
                "recommendation": "Verify manually.",
            }

    if sys.platform != "win32":
        return {
            "name": "Auto-Login Configuration",
            "severity": "Info",
            "description": "Not running on Windows or macOS \u2014 check skipped.",
            "recommendation": "Run LocalScan on a supported system.",
        }

    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    auto_admin_logon, aal_status = _reg_read_hklm_full(path, "AutoAdminLogon")
    default_password = _reg_read_hklm(path, "DefaultPassword")

    if aal_status == "error":
        return {
            "name": "Auto-Login \u2014 State Unknown",
            "severity": "Low",
            "description": "Auto-login state could not be read from the registry.",
            "recommendation": (
                "Verify via registry key: "
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoAdminLogon"
            ),
        }

    if str(auto_admin_logon) == "1":
        desc = "Auto-login is enabled (AutoAdminLogon = 1)."
        if default_password:
            desc += " A DefaultPassword value is present in the registry."
        return {
            "name": "Auto-Login Enabled",
            "severity": "Critical",
            "description": desc,
            "recommendation": (
                "Disable auto-login by setting AutoAdminLogon to 0 and "
                "removing the DefaultPassword registry value."
            ),
        }

    return {
        "name": "Auto-Login Configuration",
        "severity": "Info",
        "description": "Auto-login is not configured.",
        "recommendation": "No action required.",
    }


def check_powershell_execution_policy() -> Dict[str, Any]:
    """Check PowerShell execution policy (Windows) or Gatekeeper (macOS)."""
    if PLATFORM == "darwin":
        try:
            result = subprocess.run(
                ["spctl", "--status"],
                capture_output=True, text=True, timeout=15,
            )
            output = (result.stdout + result.stderr).lower()
            if "disabled" in output:
                return {
                    "name": "Gatekeeper Disabled",
                    "severity": "High",
                    "description": (
                        "Gatekeeper is disabled. macOS will not verify "
                        "that apps are from identified developers or "
                        "notarized by Apple."
                    ),
                    "recommendation": (
                        "Re-enable Gatekeeper: sudo spctl --master-enable"
                    ),
                }
            elif "enabled" in output or "assessments enabled" in output:
                return {
                    "name": "Gatekeeper Enabled",
                    "severity": "Info",
                    "description": "Gatekeeper is enabled.",
                    "recommendation": "No action required.",
                }
            else:
                return {
                    "name": "Gatekeeper \u2014 State Unknown",
                    "severity": "Low",
                    "description": "Gatekeeper state could not be determined.",
                    "recommendation": "Run 'spctl --status' manually.",
                }
        except Exception as exc:  # noqa: BLE001
            return {
                "name": "Gatekeeper",
                "severity": "Info",
                "description": f"Could not determine Gatekeeper state: {exc}",
                "recommendation": "Run 'spctl --status' manually.",
            }

    if sys.platform != "win32":
        # On non-Windows, try running pwsh if available
        pass

    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command", "Get-ExecutionPolicy"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        policy = result.stdout.strip()
        if result.returncode != 0 or not policy:
            return {
                "name": "PowerShell Execution Policy \u2014 Unknown",
                "severity": "Low",
                "description": "Execution policy could not be determined.",
                "recommendation": "Run 'Get-ExecutionPolicy' in PowerShell manually.",
            }
        risky_policies = {"Unrestricted", "Bypass", "RemoteSigned"}
        if policy in risky_policies:
            severity = "High" if policy in {"Unrestricted", "Bypass"} else "Medium"
            return {
                "name": f"PowerShell Execution Policy: {policy}",
                "severity": severity,
                "description": (
                    f"The PowerShell execution policy is set to '{policy}'. "
                    "This allows unsigned or remote scripts to run."
                ),
                "recommendation": (
                    "Set the execution policy to 'Restricted' or 'AllSigned': "
                    "Set-ExecutionPolicy Restricted -Scope LocalMachine"
                ),
            }
        if policy == "Restricted":
            return {
                "name": "PowerShell Execution Policy",
                "severity": "Info",
                "description": "Execution policy is set to 'Restricted' (most secure).",
                "recommendation": "No action required.",
            }
        return {
            "name": f"PowerShell Execution Policy: {policy}",
            "severity": "Low",
            "description": f"Execution policy is '{policy}'.",
            "recommendation": (
                "Consider setting to 'Restricted' for maximum security."
            ),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "name": "PowerShell Execution Policy",
            "severity": "Info",
            "description": f"Could not determine execution policy: {exc}",
            "recommendation": "Run 'Get-ExecutionPolicy' in PowerShell manually.",
        }


def check_smb_v1() -> Dict[str, Any]:
    """Check SMB v1 (Windows) or FileVault (macOS)."""
    if PLATFORM == "darwin":
        try:
            result = subprocess.run(
                ["fdesetup", "status"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return {
                    "name": "FileVault \u2014 State Unknown",
                    "severity": "Low",
                    "description": "FileVault state could not be determined.",
                    "recommendation": (
                        "Run 'fdesetup status' manually or check "
                        "System Settings > Privacy & Security > FileVault."
                    ),
                }
            if "filevault is off" in result.stdout.lower():
                return {
                    "name": "FileVault Disk Encryption Disabled",
                    "severity": "High",
                    "description": (
                        "FileVault is not enabled. The disk contents "
                        "are not encrypted and could be accessed if the "
                        "device is lost or stolen."
                    ),
                    "recommendation": (
                        "Enable FileVault via System Settings > "
                        "Privacy & Security > FileVault."
                    ),
                }
            return {
                "name": "FileVault Disk Encryption Enabled",
                "severity": "Info",
                "description": "FileVault disk encryption is enabled.",
                "recommendation": "No action required.",
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "name": "FileVault",
                "severity": "Info",
                "description": f"Could not determine FileVault state: {exc}",
                "recommendation": "Run 'fdesetup status' manually.",
            }

    if sys.platform != "win32":
        return {
            "name": "SMB v1 Status",
            "severity": "Info",
            "description": "Not running on Windows or macOS \u2014 check skipped.",
            "recommendation": "Run LocalScan on a supported system.",
        }

    try:
        result = subprocess.run(
            ["powershell", "-NonInteractive", "-Command",
             "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | "
             "Select-Object -ExpandProperty State"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        state = result.stdout.strip()
        if result.returncode != 0 or not state:
            return {
                "name": "SMB v1 Status \u2014 Unknown",
                "severity": "Low",
                "description": (
                    "SMBv1 state could not be determined (command returned "
                    "no output or failed)."
                ),
                "recommendation": (
                    "Run 'Get-WindowsOptionalFeature -Online -FeatureName "
                    "SMB1Protocol' in an elevated PowerShell session."
                ),
            }
        if "Enabled" in state:
            return {
                "name": "SMB v1 Enabled",
                "severity": "Critical",
                "description": (
                    "SMBv1 is enabled. This protocol has critical vulnerabilities "
                    "(EternalBlue/WannaCry) and is deprecated by Microsoft."
                ),
                "recommendation": (
                    "Disable SMBv1: "
                    "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
                ),
            }
        return {
            "name": "SMB v1 Status",
            "severity": "Info",
            "description": "SMBv1 is disabled.",
            "recommendation": "No action required.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "name": "SMB v1 Status",
            "severity": "Info",
            "description": f"Could not determine SMBv1 state: {exc}",
            "recommendation": (
                "Run 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol' "
                "in an elevated PowerShell session."
            ),
        }


def check_remote_desktop():
    """Check remote access \u2014 RDP on Windows, SSH + Screen Sharing on macOS."""
    if PLATFORM == "darwin":
        findings = []
        # Sub-check 1 \u2014 Remote Login (SSH)
        try:
            result = subprocess.run(
                ["systemsetup", "-getremotelogin"],
                capture_output=True, text=True, timeout=15,
            )
            output = result.stdout.lower()
            if "on" in output:
                findings.append({
                    "name": "Remote Login (SSH) Enabled",
                    "severity": "Medium",
                    "description": (
                        "Remote Login is enabled, allowing SSH "
                        "access to this machine."
                    ),
                    "recommendation": (
                        "Disable if not required: sudo systemsetup "
                        "-setremotelogin off. If needed, restrict "
                        "access via /etc/ssh/sshd_config."
                    ),
                })
            elif "off" in output:
                findings.append({
                    "name": "Remote Login (SSH) Disabled",
                    "severity": "Info",
                    "description": "Remote Login (SSH) is disabled.",
                    "recommendation": "No action required.",
                })
            else:
                findings.append({
                    "name": "Remote Login \u2014 State Unknown",
                    "severity": "Info",
                    "description": "Remote Login state could not be determined.",
                    "recommendation": "Verify via System Settings > General > Sharing.",
                })
        except Exception as exc:  # noqa: BLE001
            findings.append({
                "name": "Remote Login (SSH)",
                "severity": "Info",
                "description": f"Could not check Remote Login state: {exc}",
                "recommendation": "Verify via System Settings > General > Sharing.",
            })

        # Sub-check 2 \u2014 Screen Sharing
        try:
            result = subprocess.run(
                ["launchctl", "list", "com.apple.screensharing"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                findings.append({
                    "name": "Screen Sharing Enabled",
                    "severity": "Medium",
                    "description": (
                        "Screen Sharing (VNC) is enabled, allowing "
                        "remote graphical access to this machine."
                    ),
                    "recommendation": (
                        "Disable via System Settings > General > "
                        "Sharing > Screen Sharing if not required."
                    ),
                })
            else:
                findings.append({
                    "name": "Screen Sharing Disabled",
                    "severity": "Info",
                    "description": "Screen Sharing is disabled.",
                    "recommendation": "No action required.",
                })
        except Exception as exc:  # noqa: BLE001
            findings.append({
                "name": "Screen Sharing",
                "severity": "Info",
                "description": f"Could not check Screen Sharing state: {exc}",
                "recommendation": "Verify via System Settings > General > Sharing.",
            })

        return findings

    if sys.platform != "win32":
        return {
            "name": "Remote Access",
            "severity": "Info",
            "description": "Not running on Windows or macOS \u2014 check skipped.",
            "recommendation": "Run LocalScan on a supported system.",
        }

    path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
    fdeny, status = _reg_read_hklm_full(path, "fDenyTSConnections")

    if status == "error":
        return {
            "name": "Remote Desktop \u2014 State Unknown",
            "severity": "Low",
            "description": (
                "RDP state could not be read from the registry "
                "(access denied or unexpected error)."
            ),
            "recommendation": (
                "Verify RDP state manually via System Properties > "
                "Remote."
            ),
        }

    if fdeny == 0:
        return {
            "name": "Remote Desktop (RDP) Enabled",
            "severity": "High",
            "description": (
                "Remote Desktop Protocol is enabled (fDenyTSConnections = 0). "
                "RDP is a common attack target."
            ),
            "recommendation": (
                "Disable RDP if not required: set fDenyTSConnections = 1. "
                "If RDP is needed, restrict access via firewall rules and enable NLA."
            ),
        }

    return {
        "name": "Remote Desktop (RDP)",
        "severity": "Info",
        "description": "Remote Desktop is disabled.",
        "recommendation": "No action required.",
    }


def check_running_services() -> List[Dict[str, Any]]:
    """List running services and flag known risky ones."""
    findings = []

    if PLATFORM == "darwin":
        MACOS_RISKY_SERVICES = {
            "com.apple.ftpd": (
                "FTP Service", "High",
                "FTP transmits credentials in plaintext"),
            "com.apple.telnetd": (
                "Telnet Service", "Critical",
                "Telnet transmits all data in plaintext"),
            "org.apache.httpd": (
                "Apache HTTP Server", "Low",
                "Web server is running \u2014 ensure it is patched"),
            "com.apple.smbd": (
                "SMB Sharing", "Medium",
                "SMB file sharing is active"),
            "com.apple.screensharing": (
                "Screen Sharing", "Medium",
                "VNC-based screen sharing is active"),
            "com.apple.remotedesktop.agent": (
                "Apple Remote Desktop", "Medium",
                "Remote Desktop agent is running"),
        }
        try:
            result = subprocess.run(
                ["launchctl", "list"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return [{
                    "name": "Running Services \u2014 State Unknown",
                    "severity": "Info",
                    "description": "Could not enumerate running launchd jobs.",
                    "recommendation": "Run 'launchctl list' manually.",
                }]
            running_lines = result.stdout.splitlines()
            for label, (svc_name, severity, desc) in MACOS_RISKY_SERVICES.items():
                if any(label in line for line in running_lines):
                    findings.append({
                        "name": f"Risky Service Running: {svc_name}",
                        "severity": severity,
                        "description": f"'{label}' is active. {desc}.",
                        "recommendation": (
                            f"Disable if not required via System Settings > "
                            f"General > Sharing or "
                            f"'sudo launchctl disable system/{label}'."
                        ),
                        "confidence": "Medium",
                    })
            if not findings:
                findings.append({
                    "name": "Running Services",
                    "severity": "Info",
                    "description": (
                        "No known risky services detected among "
                        "running launchd jobs."
                    ),
                    "recommendation": "Review the full service list periodically.",
                })
            return findings
        except Exception as exc:  # noqa: BLE001
            return [{
                "name": "Running Services",
                "severity": "Info",
                "description": f"Service enumeration failed: {exc}",
                "recommendation": "Run 'launchctl list' manually.",
            }]

    risky_services = {
        "telnet": ("Telnet Service", "Critical", "Transmits data in plaintext"),
        "ftpsvc": ("FTP Publishing Service (IIS)", "High", "FTP transmits credentials in plaintext"),
        "msftpsvc": ("Microsoft FTP Service", "High", "FTP transmits credentials in plaintext"),
        "termservice": ("Remote Desktop Services", "High", "RDP exposed \u2014 common attack vector"),
        "remoteregistry": ("Remote Registry", "High", "Allows remote modification of the registry"),
        "sharedaccess": ("Internet Connection Sharing", "Medium", "ICS may expose internal services"),
        "snmp": ("SNMP Service", "Medium", "SNMP v1/v2 uses community strings as weak auth"),
        "w3svc": ("IIS Web Server", "Low", "Web server is running \u2014 ensure it is patched"),
        "schedule": ("Task Scheduler", "Info", "Task Scheduler is running"),
    }

    if sys.platform != "win32":
        return [{
            "name": "Running Services",
            "severity": "Info",
            "description": "Service enumeration skipped \u2014 not running on Windows.",
            "recommendation": "Run LocalScan on a Windows system.",
        }]

    try:
        result = subprocess.run(
            ["sc", "query", "type=", "service", "state=", "running"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        running = set()
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.upper().startswith("SERVICE_NAME:"):
                svc = line.split(":", 1)[1].strip().lower()
                running.add(svc)

        for svc_key, (svc_name, severity, desc) in risky_services.items():
            if svc_key in running:
                if severity != "Info":
                    findings.append({
                        "name": f"Risky Service Running: {svc_name}",
                        "severity": severity,
                        "description": f"Service '{svc_key}' is running. {desc}.",
                        "recommendation": (
                            f"Disable '{svc_key}' if not required: 'sc stop {svc_key}' "
                            f"and 'sc config {svc_key} start= disabled'."
                        ),
                    })

        if not findings:
            findings.append({
                "name": "Running Services",
                "severity": "Info",
                "description": "No known risky services detected among running services.",
                "recommendation": "Review the full service list periodically.",
            })

    except Exception as exc:  # noqa: BLE001
        findings.append({
            "name": "Running Services",
            "severity": "Info",
            "description": f"Service enumeration failed: {exc}",
            "recommendation": "Run 'sc query type= service state= running' manually.",
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
    """Run all system checks and return findings."""
    findings = []
    checks = [
        ("OS version and patch level", check_os_version),
        ("Antivirus status", lambda: check_antivirus()),
        ("Software update configuration", check_software_updates),
        ("Privilege controls", check_privilege_controls),
        ("Guest account status", check_guest_account),
        ("Auto-login configuration", check_autologin),
        ("Execution policy / Gatekeeper", check_powershell_execution_policy),
        ("SMB v1 / disk encryption", check_smb_v1),
        ("Remote access", check_remote_desktop),
        ("Running services", lambda: check_running_services()),
    ]

    for description, check_fn in checks:
        if progress_callback:
            progress_callback(description)
        try:
            result = check_fn()
            if isinstance(result, list):
                findings.extend(result)
            else:
                findings.append(result)
        except Exception as exc:  # noqa: BLE001
            logger.exception("System check '%s' failed: %s", description, exc)
            findings.append({
                "name": f"Check Failed: {description}",
                "severity": "Info",
                "description": f"An error occurred: {exc}",
                "recommendation": "Check scanner.log for details.",
            })

    return findings
