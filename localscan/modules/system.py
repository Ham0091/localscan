"""
System security checks for LocalScan.
Checks Windows version, Defender, UAC, guest account, auto-login,
PowerShell execution policy, SMB v1, and Remote Desktop state.
"""

import subprocess
import sys
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helper — safe registry read (Windows only)
# ---------------------------------------------------------------------------

def _reg_read(hive, path: str, name: str):
    """Read a single registry value. Returns None on any failure."""
    if sys.platform != "win32":
        return None
    try:
        import winreg  # noqa: PLC0415
        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except Exception:  # noqa: BLE001
        return None


def _reg_read_hklm(path: str, name: str):
    if sys.platform != "win32":
        return None
    import winreg  # noqa: PLC0415
    return _reg_read(winreg.HKEY_LOCAL_MACHINE, path, name)


def _reg_read_hkcu(path: str, name: str):
    if sys.platform != "win32":
        return None
    import winreg  # noqa: PLC0415
    return _reg_read(winreg.HKEY_CURRENT_USER, path, name)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def check_windows_version() -> Dict[str, Any]:
    """Return Windows version and patch level information."""
    if sys.platform != "win32":
        return {
            "name": "Windows Version",
            "severity": "Info",
            "description": "Not running on Windows — check skipped.",
            "recommendation": "Run LocalScan on a Windows system for full coverage.",
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


def check_windows_defender() -> List[Dict[str, Any]]:
    """Check whether Windows Defender is enabled and definitions are current."""
    findings = []
    if sys.platform != "win32":
        return [{
            "name": "Windows Defender",
            "severity": "Info",
            "description": "Not running on Windows — check skipped.",
            "recommendation": "Run LocalScan on a Windows system.",
        }]

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
        import json  # noqa: PLC0415
        data = json.loads(result.stdout)

        av_enabled = data.get("AntivirusEnabled", False)
        rtp_enabled = data.get("RealTimeProtectionEnabled", False)
        sig_age = data.get("AntispywareSignatureAge", -1)

        if not av_enabled:
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


def check_windows_update() -> Dict[str, Any]:
    """Check if Windows Update automatic updates are configured."""
    if sys.platform != "win32":
        return {
            "name": "Windows Update Configuration",
            "severity": "Info",
            "description": "Not running on Windows — check skipped.",
            "recommendation": "Run LocalScan on a Windows system.",
        }

    au_path = r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    no_auto_update = _reg_read_hklm(au_path, "NoAutoUpdate")
    au_options = _reg_read_hklm(au_path, "AUOptions")

    if no_auto_update == 1:
        return {
            "name": "Windows Update — Automatic Updates Disabled",
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
            "name": "Windows Update — Notify Only (No Auto-Install)",
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


def check_uac() -> Dict[str, Any]:
    """Check whether User Account Control (UAC) is enabled."""
    if sys.platform != "win32":
        return {
            "name": "User Account Control (UAC)",
            "severity": "Info",
            "description": "Not running on Windows — check skipped.",
            "recommendation": "Run LocalScan on a Windows system.",
        }

    path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    enable_lua = _reg_read_hklm(path, "EnableLUA")

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
    if sys.platform != "win32":
        return {
            "name": "Guest Account",
            "severity": "Info",
            "description": "Not running on Windows — check skipped.",
            "recommendation": "Run LocalScan on a Windows system.",
        }

    try:
        result = subprocess.run(
            ["net", "user", "Guest"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout
        if "Account active" in output:
            for line in output.splitlines():
                if "Account active" in line:
                    if "Yes" in line:
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
                    break
        return {
            "name": "Guest Account",
            "severity": "Info",
            "description": "The built-in Guest account is disabled.",
            "recommendation": "No action required.",
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "name": "Guest Account",
            "severity": "Info",
            "description": f"Could not check Guest account status: {exc}",
            "recommendation": "Verify manually with 'net user Guest'.",
        }


def check_autologin() -> Dict[str, Any]:
    """Check whether auto-login credentials are stored in the registry."""
    if sys.platform != "win32":
        return {
            "name": "Auto-Login Configuration",
            "severity": "Info",
            "description": "Not running on Windows — check skipped.",
            "recommendation": "Run LocalScan on a Windows system.",
        }

    path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    auto_admin_logon = _reg_read_hklm(path, "AutoAdminLogon")
    default_password = _reg_read_hklm(path, "DefaultPassword")

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
    """Check the PowerShell execution policy."""
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
    """Check whether SMB v1 is enabled (associated with WannaCry/EternalBlue)."""
    if sys.platform != "win32":
        return {
            "name": "SMB v1 Status",
            "severity": "Info",
            "description": "Not running on Windows — check skipped.",
            "recommendation": "Run LocalScan on a Windows system.",
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


def check_remote_desktop() -> Dict[str, Any]:
    """Check whether Remote Desktop (RDP) is enabled."""
    if sys.platform != "win32":
        return {
            "name": "Remote Desktop (RDP)",
            "severity": "Info",
            "description": "Not running on Windows — check skipped.",
            "recommendation": "Run LocalScan on a Windows system.",
        }

    path = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
    fdeny = _reg_read_hklm(path, "fDenyTSConnections")

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

    risky_services = {
        "telnet": ("Telnet Service", "Critical", "Transmits data in plaintext"),
        "ftpsvc": ("FTP Publishing Service (IIS)", "High", "FTP transmits credentials in plaintext"),
        "msftpsvc": ("Microsoft FTP Service", "High", "FTP transmits credentials in plaintext"),
        "termservice": ("Remote Desktop Services", "High", "RDP exposed — common attack vector"),
        "remoteregistry": ("Remote Registry", "High", "Allows remote modification of the registry"),
        "sharedaccess": ("Internet Connection Sharing", "Medium", "ICS may expose internal services"),
        "snmp": ("SNMP Service", "Medium", "SNMP v1/v2 uses community strings as weak auth"),
        "w3svc": ("IIS Web Server", "Low", "Web server is running — ensure it is patched"),
        "schedule": ("Task Scheduler", "Info", "Task Scheduler is running"),
    }

    if sys.platform != "win32":
        return [{
            "name": "Running Services",
            "severity": "Info",
            "description": "Service enumeration skipped — not running on Windows.",
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
        ("Windows version and patch level", check_windows_version),
        ("Windows Defender status", lambda: check_windows_defender()),
        ("Windows Update configuration", check_windows_update),
        ("UAC status", check_uac),
        ("Guest account status", check_guest_account),
        ("Auto-login configuration", check_autologin),
        ("PowerShell execution policy", check_powershell_execution_policy),
        ("SMB v1 status", check_smb_v1),
        ("Remote Desktop status", check_remote_desktop),
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
