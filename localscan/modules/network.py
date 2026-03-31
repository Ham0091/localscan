"""
Network security checks for LocalScan.
Checks open ports, dangerous services, firewall status, and unencrypted protocols.
"""

import socket
import subprocess
import sys
import concurrent.futures
from typing import List, Dict, Any


DANGEROUS_PORTS = {
    21: ("FTP", "High", "FTP transmits credentials in plaintext"),
    23: ("Telnet", "Critical", "Telnet transmits all data including credentials in plaintext"),
    445: ("SMB", "High", "SMB exposed on localhost — potential lateral movement risk"),
    3306: ("MySQL", "High", "MySQL database port is openly accessible"),
    3389: ("RDP", "High", "Remote Desktop Protocol is exposed"),
    5900: ("VNC", "High", "VNC remote desktop is exposed"),
    6379: ("Redis", "Critical", "Redis is exposed without authentication by default"),
}

UNENCRYPTED_PROTOCOLS = {21, 23}


def _check_port(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    """Return True if a TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False


def _identify_service(port: int) -> str:
    """Return a best-guess service name for a port."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return DANGEROUS_PORTS.get(port, (f"unknown-{port}",))[0]


def scan_open_ports(start: int = 1, end: int = 10000) -> List[int]:
    """Scan localhost for open TCP ports in the given range."""
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = {executor.submit(_check_port, port): port for port in range(start, end + 1)}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass
    return sorted(open_ports)


def check_firewall() -> Dict[str, Any]:
    """
    Check whether the Windows Firewall is enabled for all profiles.
    Returns a finding dict.
    """
    finding = {
        "name": "Windows Firewall Status",
        "severity": "Info",
        "description": "",
        "recommendation": "",
    }

    if sys.platform != "win32":
        finding["description"] = "Firewall check skipped — not running on Windows."
        finding["severity"] = "Info"
        return finding

    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout
        if "OFF" in output.upper():
            finding["severity"] = "Critical"
            finding["description"] = (
                "Windows Firewall is disabled on one or more profiles. "
                "Raw output:\n" + output.strip()
            )
            finding["recommendation"] = (
                "Enable the Windows Firewall for all profiles via "
                "'netsh advfirewall set allprofiles state on' or through "
                "Windows Defender Firewall settings."
            )
        else:
            finding["severity"] = "Info"
            finding["description"] = "Windows Firewall is enabled on all profiles."
            finding["recommendation"] = "No action required."
    except FileNotFoundError:
        finding["severity"] = "Info"
        finding["description"] = "netsh not found — firewall state could not be determined."
        finding["recommendation"] = "Verify firewall status manually."
    except subprocess.TimeoutExpired:
        finding["severity"] = "Info"
        finding["description"] = "Firewall check timed out."
        finding["recommendation"] = "Verify firewall status manually."
    except Exception as exc:  # noqa: BLE001
        finding["severity"] = "Info"
        finding["description"] = f"Firewall check failed: {exc}"
        finding["recommendation"] = "Verify firewall status manually."

    return finding


def run_checks(progress_callback=None) -> List[Dict[str, Any]]:
    """Run all network checks and return a list of finding dicts."""
    findings = []

    # 1. Scan open ports
    if progress_callback:
        progress_callback("Scanning open ports on localhost (1–10000)…")
    open_ports = scan_open_ports(1, 10000)

    # Open port summary finding
    if open_ports:
        findings.append({
            "name": "Open Ports Detected",
            "severity": "Info",
            "description": (
                f"{len(open_ports)} open TCP port(s) found on localhost: "
                + ", ".join(str(p) for p in open_ports)
            ),
            "recommendation": "Review each open port and disable services that are not required.",
        })

    # 2. Dangerous services
    for port in open_ports:
        if port in DANGEROUS_PORTS:
            svc_name, svc_severity, svc_desc = DANGEROUS_PORTS[port]
            findings.append({
                "name": f"Dangerous Service Exposed: {svc_name} (port {port})",
                "severity": svc_severity,
                "description": (
                    f"Port {port} ({svc_name}) is open on localhost. {svc_desc}."
                ),
                "recommendation": (
                    f"Disable or restrict access to {svc_name} (port {port}) "
                    "unless explicitly required, and ensure it is not accessible "
                    "from untrusted networks."
                ),
            })

    # 3. Unencrypted protocols
    unencrypted_found = [p for p in open_ports if p in UNENCRYPTED_PROTOCOLS]
    if unencrypted_found:
        names = [DANGEROUS_PORTS[p][0] for p in unencrypted_found]
        findings.append({
            "name": "Unencrypted Protocol(s) Active",
            "severity": "Critical",
            "description": (
                "The following unencrypted protocols are running locally: "
                + ", ".join(f"{n} (port {p})" for n, p in zip(names, unencrypted_found))
                + ". These transmit credentials and data in plaintext."
            ),
            "recommendation": (
                "Replace FTP with SFTP/FTPS and Telnet with SSH. "
                "Disable these services immediately."
            ),
        })

    # 4. Firewall check
    if progress_callback:
        progress_callback("Checking Windows Firewall status…")
    findings.append(check_firewall())

    return findings
