"""
Network security checks for LocalScan.
Checks open ports, dangerous services, firewall status, and unencrypted protocols.
"""

import socket
import subprocess
import sys
import logging
import concurrent.futures
from typing import List, Dict, Any, Optional, Tuple

logger = logging.getLogger(__name__)

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

# Ordered severity levels used for downgrade logic
_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"]

# Banner-based service hints: partial string match → service name
_BANNER_HINTS = {
    "SSH": "SSH",
    "FTP": "FTP",
    "SMTP": "SMTP",
    "HTTP": "HTTP",
    "220": "FTP/SMTP",
    "Redis": "Redis",
    "MySQL": "MySQL",
}

MAX_DISPLAYED_BANNERS = 50


def _is_loopback_addr(addr: str) -> bool:
    """Return True if an address is a loopback endpoint."""
    return addr.startswith("127.") or addr in {"::1", "localhost"}


def _grab_banner(host: str, port: int, timeout: float = 1.0) -> Optional[str]:
    """Attempt to grab a one-line banner from an open TCP port.

    Returns the banner string on success, or None if unavailable.
    Never raises — all errors are silently swallowed.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            try:
                data = sock.recv(256)
                return data.decode("utf-8", errors="replace").strip()[:200]
            except (socket.timeout, OSError):
                return None
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None
    except Exception:  # noqa: BLE001
        return None


def _check_port(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    """Return True if a TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, socket.timeout, OSError):
        return False


def _get_listening_interfaces(port: int) -> List[str]:
    """
    Return a list of bind addresses for which the given TCP port is
    reachable. Checks loopback and local host addresses (IPv4/IPv6 when
    available). Returns a list of addresses that accepted a connection.
    Never raises.
    """
    candidates = ["127.0.0.1", "::1"]
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(
            hostname,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        ):
            addr = info[4][0]
            if addr not in candidates:
                candidates.append(addr)
    except Exception:
        pass

    reachable = []
    for addr in candidates:
        try:
            with socket.create_connection((addr, port), timeout=0.5):
                reachable.append(addr)
        except Exception:
            pass
    return reachable


def _listener_binding_summary(
    open_ports: List[int],
    interfaces_by_port: Optional[Dict[int, List[str]]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Summarize loopback-only vs externally reachable listeners.
    """
    if not open_ports:
        return None

    loopback_only: List[int] = []
    externally_reachable: List[int] = []
    unknown: List[int] = []

    for port in open_ports:
        interfaces = (
            interfaces_by_port.get(port, [])
            if interfaces_by_port is not None
            else _get_listening_interfaces(port)
        )
        if not interfaces:
            unknown.append(port)
        elif all(_is_loopback_addr(addr) for addr in interfaces):
            loopback_only.append(port)
        else:
            externally_reachable.append(port)

    severity = "Info"
    if externally_reachable:
        severity = "Medium"

    details = [
        f"Externally reachable ports: {', '.join(str(p) for p in externally_reachable) or 'none'}",
        f"Loopback-only ports: {', '.join(str(p) for p in loopback_only) or 'none'}",
    ]
    if unknown:
        details.append(
            "Ports with undetermined binding reachability: "
            + ", ".join(str(p) for p in unknown)
        )

    return {
        "name": "Listener Binding Analysis",
        "severity": severity,
        "description": "\n".join(details),
        "recommendation": (
            "Prefer loopback-only bindings for local-only services, and restrict "
            "externally reachable listeners with host firewalls and access controls."
        ),
        "confidence": "Medium",
    }


def _identify_service(port: int, banner: Optional[str] = None) -> Tuple[str, str]:
    """Return (service_name, confidence) for a port.

    Confidence levels:
      High   — banner confirms the service
      Medium — well-known port with no banner confirmation
      Low    — unknown port, guessed from heuristics
    """
    # Try banner-based detection first
    if banner:
        for hint, svc in _BANNER_HINTS.items():
            if hint.upper() in banner.upper():
                return svc, "High"

    # Fall back to known-port heuristics
    if port in DANGEROUS_PORTS:
        return DANGEROUS_PORTS[port][0], "Medium"

    # Try OS service database
    try:
        name = socket.getservbyport(port, "tcp")
        return name, "Medium"
    except OSError:
        pass

    return f"unknown-{port}", "Low"


def _downgrade_severity(severity: str) -> str:
    """Return the next-lower severity level, or the same level if already at minimum."""
    try:
        idx = _SEVERITY_ORDER.index(severity)
    except ValueError:
        return "Low"  # Unknown severity — treat conservatively
    return _SEVERITY_ORDER[min(idx + 1, len(_SEVERITY_ORDER) - 1)]


def scan_open_ports(
    start: int = 1,
    end: int = 10000,
    max_workers: int = 100,
    timeout: float = 0.5,
) -> List[int]:
    """Scan localhost for open TCP ports in the given range using a thread pool."""
    open_ports: List[int] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_check_port, port, "127.0.0.1", timeout): port
            for port in range(start, end + 1)
        }
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:  # noqa: BLE001
                pass
    return sorted(open_ports)


def check_firewall() -> Tuple[Dict[str, Any], Optional[bool]]:
    """
    Check whether the Windows Firewall is enabled for all profiles.

    Returns:
        (finding_dict, firewall_disabled)
        firewall_disabled is True if any profile is OFF, False if all are ON,
        or None if the state could not be determined.
    """
    finding: Dict[str, Any] = {
        "name": "Firewall Status",
        "severity": "Info",
        "description": "",
        "recommendation": "",
        "confidence": "High",
    }

    if sys.platform == "darwin":
        FIREWALL_CMD = (
            "/usr/libexec/ApplicationFirewall/socketfilterfw"
            " --getglobalstate"
        )
        try:
            result = subprocess.run(
                FIREWALL_CMD.split(),
                capture_output=True,
                text=True,
                timeout=15,
            )
            output = result.stdout.lower()
            if result.returncode != 0 or not output.strip():
                finding["severity"] = "Info"
                finding["confidence"] = "Low"
                finding["description"] = (
                    "macOS Application Firewall state could not be "
                    "determined (socketfilterfw returned no output)."
                )
                finding["recommendation"] = (
                    "Verify firewall status manually via System Settings "
                    "> Network > Firewall."
                )
                return finding, None
            if "disabled" in output:
                finding["name"] = "macOS Application Firewall Disabled"
                finding["severity"] = "Critical"
                finding["description"] = (
                    "The macOS Application Firewall is disabled. "
                    "Incoming connections are not filtered."
                )
                finding["recommendation"] = (
                    "Enable the firewall via System Settings > Network > "
                    "Firewall, or run: sudo /usr/libexec/ApplicationFirewall"
                    "/socketfilterfw --setglobalstate on"
                )
                return finding, True
            else:
                finding["name"] = "macOS Application Firewall Status"
                finding["severity"] = "Info"
                finding["description"] = "macOS Application Firewall is enabled."
                finding["recommendation"] = "No action required."
                return finding, False
        except FileNotFoundError:
            finding["severity"] = "Info"
            finding["confidence"] = "Low"
            finding["description"] = (
                "socketfilterfw not found — firewall state could not "
                "be determined."
            )
            finding["recommendation"] = (
                "Verify firewall status via System Settings > Network > "
                "Firewall."
            )
            return finding, None
        except Exception as exc:
            logger.exception("macOS firewall check failed: %s", exc)
            finding["severity"] = "Info"
            finding["confidence"] = "Low"
            finding["description"] = f"macOS firewall check failed: {exc}"
            finding["recommendation"] = "Verify firewall status manually."
            return finding, None

    elif sys.platform != "win32":
        finding["description"] = (
            "Firewall check not supported on this platform."
        )
        finding["confidence"] = "Low"
        return finding, None

    try:
        result = subprocess.run(
            ["netsh", "advfirewall", "show", "allprofiles", "state"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        output = result.stdout
        if result.returncode != 0:
            finding["severity"] = "Info"
            finding["confidence"] = "Low"
            finding["description"] = (
                "netsh returned a non-zero exit code — firewall state "
                "could not be confirmed."
            )
            finding["recommendation"] = "Verify firewall status manually."
            return finding, None
        if "State" not in output:
            finding["severity"] = "Info"
            finding["confidence"] = "Low"
            finding["description"] = (
                "netsh output did not match expected format — firewall "
                "state could not be confirmed."
            )
            finding["recommendation"] = "Verify firewall status manually."
            return finding, None
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
            return finding, True
        else:
            finding["severity"] = "Info"
            finding["description"] = "Windows Firewall is enabled on all profiles."
            finding["recommendation"] = "No action required."
            return finding, False
    except FileNotFoundError:
        finding["severity"] = "Info"
        finding["confidence"] = "Low"
        finding["description"] = "netsh not found — firewall state could not be determined."
        finding["recommendation"] = "Verify firewall status manually."
    except subprocess.TimeoutExpired:
        finding["severity"] = "Info"
        finding["confidence"] = "Low"
        finding["description"] = "Firewall check timed out."
        finding["recommendation"] = "Verify firewall status manually."
    except Exception as exc:  # noqa: BLE001
        logger.exception("Firewall check failed: %s", exc)
        finding["severity"] = "Info"
        finding["confidence"] = "Low"
        finding["description"] = f"Firewall check failed: {exc}"
        finding["recommendation"] = "Verify firewall status manually."

    return finding, None


def run_checks(
    progress_callback=None,
    quick: bool = False,
    is_admin: bool = False,
) -> List[Dict[str, Any]]:
    """Run all network checks and return a list of finding dicts."""
    findings: List[Dict[str, Any]] = []

    # 1. Firewall check first (result is used for severity escalation)
    if progress_callback:
        progress_callback("Checking firewall status…")
    firewall_finding, firewall_disabled = check_firewall()
    findings.append(firewall_finding)

    # 2. Scan open ports
    if quick:
        if progress_callback:
            progress_callback("Quick mode: scanning well-known ports + all known dangerous ports…")
        quick_ports = sorted(set(range(1, 1025)) | set(DANGEROUS_PORTS.keys()))
        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            futures = {
                executor.submit(_check_port, port, "127.0.0.1", 0.5): port
                for port in quick_ports
            }
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass
        open_ports.sort()
    else:
        if progress_callback:
            progress_callback("Scanning open ports on localhost (1–10000)…")
        open_ports = scan_open_ports(1, 10000)

    # Open port summary finding
    interfaces_by_port: Dict[int, List[str]] = {}
    if open_ports:
        findings.append({
            "name": "Open Ports Detected",
            "severity": "Info",
            "description": (
                f"{len(open_ports)} open TCP port(s) found on localhost: "
                + ", ".join(str(p) for p in open_ports)
            ),
            "recommendation": "Review each open port and disable services that are not required.",
            "confidence": "High",
        })

        if progress_callback:
            progress_callback("Analyzing listener binding exposure…")
        for port in open_ports:
            interfaces_by_port[port] = _get_listening_interfaces(port)
        binding_finding = _listener_binding_summary(open_ports, interfaces_by_port)
        if binding_finding:
            findings.append(binding_finding)

        if progress_callback:
            progress_callback("Collecting service banners from open ports…")
        banner_entries = []
        for port in open_ports:
            banner = _grab_banner("127.0.0.1", port)
            if banner:
                service_name, confidence = _identify_service(port, banner)
                banner_entries.append(
                    f"Port {port} ({service_name}, confidence={confidence}): {banner}"
                )
        if banner_entries:
            sample = "\n".join(banner_entries[:MAX_DISPLAYED_BANNERS])
            if len(banner_entries) > MAX_DISPLAYED_BANNERS:
                sample += f"\n... and {len(banner_entries) - MAX_DISPLAYED_BANNERS} more banner(s)"
            findings.append({
                "name": "Service Banner Collection",
                "severity": "Info",
                "description": (
                    f"Collected {len(banner_entries)} banner(s) from open local TCP ports:\n{sample}"
                ),
                "recommendation": (
                    "Review disclosed service metadata and suppress unnecessary banners "
                    "or version strings where possible."
                ),
                "confidence": "Medium",
            })

    # 3. Dangerous services with banner grabbing
    for port in open_ports:
        if port in DANGEROUS_PORTS:
            svc_name, base_severity, svc_desc = DANGEROUS_PORTS[port]

            # Check which interfaces the port is reachable on
            interfaces = interfaces_by_port.get(port, _get_listening_interfaces(port))
            is_loopback_only = all(_is_loopback_addr(a) for a in interfaces)

            # Attempt banner grab for confirmation
            banner = _grab_banner("127.0.0.1", port)
            _, confidence = _identify_service(port, banner)

            severity = base_severity
            extra_desc = ""

            # Escalate RDP severity when firewall is also disabled
            if port == 3389 and firewall_disabled is True:
                severity = "Critical"
                extra_desc = (
                    " ESCALATED: RDP is exposed AND the Windows Firewall is disabled, "
                    "making this system directly reachable from the network."
                )

            # Downgrade severity for loopback-only listeners
            if is_loopback_only:
                severity = _downgrade_severity(severity)

            # Downgrade severity for low-confidence detections
            if confidence == "Low":
                severity = _downgrade_severity(severity)

            banner_note = f" Banner: {banner!r}" if banner else ""
            if is_loopback_only:
                finding_name = f"Dangerous Service — Loopback Only: {svc_name} (port {port})"
                port_desc = (
                    f"Port {port} ({svc_name}) is listening on loopback only "
                    f"(not externally reachable). {svc_desc}.{extra_desc}"
                )
            else:
                finding_name = f"Dangerous Service — Externally Exposed: {svc_name} (port {port})"
                port_desc = (
                    f"Port {port} ({svc_name}) is open and externally reachable. {svc_desc}.{extra_desc}"
                )
            findings.append({
                "name": finding_name,
                "severity": severity,
                "description": (
                    port_desc
                    + (f"\n{banner_note}" if banner_note else "")
                ),
                "recommendation": (
                    f"Disable or restrict access to {svc_name} (port {port}) "
                    "unless explicitly required, and ensure it is not accessible "
                    "from untrusted networks."
                ),
                "confidence": confidence,
            })

    # 4. Unencrypted protocols
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
            "confidence": "High",
        })

    return findings
