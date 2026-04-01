"""
Filesystem security checks for LocalScan.
Scans for plaintext credential files, weak SSH permissions, key files,
and browser password database files.
"""

import os
import stat
import sys
import logging
from pathlib import Path
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)

# Patterns for files that likely contain credentials
CREDENTIAL_PATTERNS = [
    "*password*",
    "*passwd*",
    "*credentials*",
    "*secret*",
    "*api_key*",
    "*.env",
]

# Browser SQLite password databases (existence check only — never read)
BROWSER_DB_PATHS = {
    "Chrome": [
        Path.home() / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default" / "Login Data",
        Path.home() / ".config" / "google-chrome" / "Default" / "Login Data",
    ],
    "Firefox": [
        Path.home() / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles",
        Path.home() / ".mozilla" / "firefox",
    ],
    "Edge": [
        Path.home() / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data" / "Default" / "Login Data",
    ],
}

SCAN_DIRS = [
    Path.home() / "Desktop",
    Path.home() / "Documents",
    Path.home() / "Downloads",
]

# Safety limits
MAX_SCAN_DEPTH = 4          # Maximum directory recursion depth
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB — skip files larger than this


def _safe_rglob(
    directory: Path,
    pattern: str,
    max_depth: int = MAX_SCAN_DEPTH,
) -> List[Path]:
    """
    Recursively glob *pattern* under *directory* up to *max_depth* levels deep.

    Safety measures applied:
    - Respects max_depth to prevent unbounded recursion
    - Skips symbolic links (files and directories)
    - Skips files larger than MAX_FILE_SIZE
    - Silently handles PermissionError and other OS errors
    """
    results: List[Path] = []

    def _recurse(current: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            for entry in current.iterdir():
                # Never follow symlinks
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    _recurse(entry, depth + 1)
                elif entry.is_file():
                    try:
                        # Skip oversized files
                        if entry.stat().st_size > MAX_FILE_SIZE:
                            continue
                    except OSError:
                        continue
                    # Pattern match (case-insensitive on Windows)
                    try:
                        if entry.match(pattern):
                            results.append(entry)
                    except Exception:  # noqa: BLE001
                        pass
        except PermissionError:
            pass
        except OSError as exc:
            logger.debug("Filesystem scan skipped %s: %s", current, exc)

    _recurse(directory, 0)
    return results


def _check_ssh_permissions() -> List[Dict[str, Any]]:
    """Check whether the ~/.ssh directory has overly permissive access rights."""
    findings = []
    ssh_dir = Path.home() / ".ssh"

    if not ssh_dir.exists():
        return findings  # Nothing to check

    findings.append({
        "name": ".ssh Directory Exists",
        "severity": "Info",
        "description": f"An SSH configuration directory was found at {ssh_dir}.",
        "recommendation": (
            "Ensure SSH private keys are passphrase-protected and that "
            "the directory has restricted permissions (700)."
        ),
        "confidence": "High",
    })

    if sys.platform != "win32":
        try:
            mode = stat.S_IMODE(os.stat(ssh_dir).st_mode)
            if mode & 0o077:  # group or other bits set
                findings.append({
                    "name": ".ssh Directory Has Weak Permissions",
                    "severity": "High",
                    "description": (
                        f"~/.ssh has permissions {oct(mode)}. "
                        "Group or other users may be able to read SSH keys."
                    ),
                    "recommendation": "Run 'chmod 700 ~/.ssh' to restrict access.",
                    "confidence": "High",
                })
            # Check individual key files
            for key_file in ssh_dir.iterdir():
                if key_file.is_symlink():
                    continue
                if key_file.is_file() and not key_file.name.endswith(".pub"):
                    key_mode = stat.S_IMODE(os.stat(key_file).st_mode)
                    if key_mode & 0o077:
                        findings.append({
                            "name": f"SSH Key File Has Weak Permissions: {key_file.name}",
                            "severity": "High",
                            "description": (
                                f"SSH private key '{key_file}' has permissions {oct(key_mode)}."
                            ),
                            "recommendation": f"Run 'chmod 600 {key_file}' to restrict access.",
                            "confidence": "High",
                        })
        except Exception as exc:  # noqa: BLE001
            logger.warning("SSH permission check failed: %s", exc)

    return findings


def _scan_credential_files() -> List[Dict[str, Any]]:
    """Scan common locations for files that may contain plaintext credentials."""
    findings = []
    flagged_files: List[Path] = []

    for scan_dir in SCAN_DIRS:
        if not scan_dir.exists():
            continue
        if scan_dir.is_symlink():
            continue
        for pattern in CREDENTIAL_PATTERNS:
            try:
                matched = _safe_rglob(scan_dir, pattern, max_depth=MAX_SCAN_DEPTH)
                flagged_files.extend(matched)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Filesystem scan error in %s pattern %s: %s", scan_dir, pattern, exc)

    # Deduplicate
    seen: Set[Path] = set()
    unique_files = []
    for f in flagged_files:
        if f not in seen:
            seen.add(f)
            unique_files.append(f)

    if unique_files:
        file_list = "\n".join(str(f) for f in unique_files[:50])
        if len(unique_files) > 50:
            file_list += f"\n... and {len(unique_files) - 50} more"
        findings.append({
            "name": "Potential Plaintext Credential Files Found",
            "severity": "High",
            "description": (
                f"{len(unique_files)} file(s) with credential-related names were found "
                f"in common user directories. File contents were NOT read or transmitted.\n"
                f"{file_list}"
            ),
            "recommendation": (
                "Review these files and remove any plaintext credentials. "
                "Use a password manager or secrets vault instead."
            ),
            "confidence": "Medium",
        })

    return findings


def _check_pem_key_files() -> List[Dict[str, Any]]:
    """Check for .pem or .key files in the home directory."""
    findings = []
    home = Path.home()
    pem_files = []

    for pattern in ("*.pem", "*.key"):
        try:
            pem_files.extend(
                p for p in home.glob(pattern)
                if not p.is_symlink() and p.is_file()
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("PEM/key file search failed: %s", exc)

    if pem_files:
        findings.append({
            "name": "Private Key / Certificate Files in Home Directory",
            "severity": "Medium",
            "description": (
                f"{len(pem_files)} .pem or .key file(s) found directly in the home directory: "
                + ", ".join(f.name for f in pem_files[:10])
            ),
            "recommendation": (
                "Store private keys in a secure location with restricted permissions "
                "(e.g., ~/.ssh/ with chmod 600). Verify these files are necessary."
            ),
            "confidence": "High",
        })

    return findings


def _check_browser_databases() -> List[Dict[str, Any]]:
    """Check for browser password databases (existence only — contents are never read)."""
    findings = []

    for browser, paths in BROWSER_DB_PATHS.items():
        for db_path in paths:
            try:
                if db_path.is_symlink():
                    continue
                if db_path.exists():
                    findings.append({
                        "name": f"{browser} Password Database Detected",
                        "severity": "Info",
                        "description": (
                            f"A {browser} password database was found at: {db_path}. "
                            "Contents were NOT read."
                        ),
                        "recommendation": (
                            f"Be aware that {browser} stores passwords locally. "
                            "Use a dedicated password manager and enable browser sync "
                            "with a strong master password."
                        ),
                        "confidence": "High",
                    })
                    break  # One finding per browser is enough
            except PermissionError:
                pass
            except Exception as exc:  # noqa: BLE001
                logger.warning("Browser DB check for %s failed: %s", browser, exc)

    return findings


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------

def run_checks(
    progress_callback=None,
    quick: bool = False,
    is_admin: bool = False,
) -> List[Dict[str, Any]]:
    """Run all filesystem checks and return findings."""
    findings = []

    sub_checks = [
        ("Scanning for potential credential files", _scan_credential_files),
        ("Checking .ssh directory permissions", _check_ssh_permissions),
        ("Checking for .pem/.key files in home directory", _check_pem_key_files),
        ("Checking for browser password databases", _check_browser_databases),
    ]

    for description, check_fn in sub_checks:
        if progress_callback:
            progress_callback(description)
        try:
            findings.extend(check_fn())
        except Exception as exc:  # noqa: BLE001
            logger.exception("Filesystem check '%s' failed: %s", description, exc)
            findings.append({
                "name": f"Check Failed: {description}",
                "severity": "Info",
                "description": f"An error occurred: {exc}",
                "recommendation": "Check scanner.log for details.",
                "confidence": "Low",
            })

    if not findings:
        findings.append({
            "name": "Filesystem Checks",
            "severity": "Info",
            "description": "No significant filesystem security issues were detected.",
            "recommendation": "No action required.",
            "confidence": "High",
        })

    return findings
