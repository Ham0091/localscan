# LocalScan — Windows vulnerability scanner
# For educational and authorized use only.
# Do not run this tool on systems you do not own or have explicit permission to scan.
# No data is transmitted externally — all findings are stored in a local HTML report.

"""
LocalScan — main entry point.

Usage:
    python scanner.py

Runs all security checks, shows live progress in the terminal, and generates
a timestamped HTML report: report_YYYYMMDD_HHMMSS.html
"""

import ctypes
import importlib
import logging
import os
import platform
import sys
import traceback
import webbrowser
from datetime import datetime
from typing import Dict, List, Any

try:
    import colorama
    from colorama import Fore, Style
    colorama.init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False

    class _Stub:
        def __getattr__(self, _name: str) -> str:
            return ""

    Fore = _Stub()   # type: ignore[assignment]
    Style = _Stub()  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("localscan")

# ---------------------------------------------------------------------------
# Terminal helpers
# ---------------------------------------------------------------------------

TICK = "[✓]"
CROSS = "[!]"
INFO = "[-]"


def _print_pass(msg: str) -> None:
    print(f"{Fore.GREEN}{TICK}{Style.RESET_ALL} {msg}")


def _print_fail(msg: str) -> None:
    print(f"{Fore.RED}{CROSS}{Style.RESET_ALL} {msg}")


def _print_warn(msg: str) -> None:
    print(f"{Fore.YELLOW}{INFO}{Style.RESET_ALL} {msg}")


def _print_info(msg: str) -> None:
    print(f"{Fore.CYAN}{INFO}{Style.RESET_ALL} {msg}")


def _section(title: str) -> None:
    print()
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 60}{Style.RESET_ALL}")


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def _is_admin() -> bool:
    """Return True if the process is running with elevated privileges."""
    try:
        if sys.platform == "win32":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.getuid() == 0  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Module runner
# ---------------------------------------------------------------------------

def _run_module(
    module_name: str,
    module,
    step: int,
    total: int,
) -> List[Dict[str, Any]]:
    """Run a single module and return its findings."""
    _section(f"Running {module_name} checks… ({step}/{total})")

    findings: List[Dict[str, Any]] = []

    def progress_callback(msg: str) -> None:
        _print_info(msg)

    try:
        findings = module.run_checks(progress_callback=progress_callback)
    except Exception as exc:  # noqa: BLE001
        logger.exception("Module '%s' crashed: %s", module_name, exc)
        _print_fail(f"Module '{module_name}' encountered an error: {exc}")
        findings = [{
            "name": f"Module Error: {module_name}",
            "severity": "Info",
            "description": f"The module crashed: {exc}",
            "recommendation": "Check scanner.log for the full traceback.",
        }]

    # Print per-finding summary
    for f in findings:
        sev = f.get("severity", "Info")
        name = f.get("name", "")
        if sev in ("Critical", "High"):
            _print_fail(f"[{sev}] {name}")
        elif sev == "Medium":
            _print_warn(f"[{sev}] {name}")
        else:
            _print_pass(f"[{sev}] {name}")

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print()
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  LocalScan — Local Vulnerability Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    print(f"  Platform : {platform.system()} {platform.release()}")
    print(f"  Python   : {sys.version.split()[0]}")
    print(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    # Administrator check
    if _is_admin():
        _print_pass("Running with elevated privileges — all checks available.")
    else:
        _print_warn(
            "Not running as Administrator. Some checks may be skipped or incomplete. "
            "Re-run as Administrator for full results."
        )

    # Import modules lazily so that a missing dependency only affects that module
    modules_to_run = []
    module_defs = [
        ("network", "localscan.modules.network"),
        ("system", "localscan.modules.system"),
        ("filesystem", "localscan.modules.filesystem"),
        ("services", "localscan.modules.services"),
    ]

    for module_key, module_path in module_defs:
        try:
            mod = importlib.import_module(module_path)
            modules_to_run.append((module_key, mod))
        except ImportError as exc:
            logger.error("Could not import module '%s': %s", module_path, exc)
            _print_fail(f"Could not load module '{module_key}': {exc}")

    total_modules = len(modules_to_run)
    all_results: Dict[str, List[Dict[str, Any]]] = {}

    for step, (module_key, module) in enumerate(modules_to_run, start=1):
        results = _run_module(module_key.title(), module, step, total_modules)
        all_results[module_key] = results

    # Generate report
    _section("Generating report…")
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_filename = f"report_{timestamp_str}.html"
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), report_filename)

    try:
        from localscan.report import generate_report, calculate_risk_score, _count_severities  # noqa: PLC0415
        generate_report(all_results, report_path)
        all_findings = [f for findings in all_results.values() for f in findings]
        score = calculate_risk_score(all_findings)
        counts = _count_severities(all_findings)

        print()
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}  SCAN COMPLETE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
        print(f"  Risk Score : {score}/100")
        print(
            f"  Critical: {counts['Critical']}  "
            f"High: {counts['High']}  "
            f"Medium: {counts['Medium']}  "
            f"Low: {counts['Low']}  "
            f"Info: {counts['Info']}"
        )
        print(f"  Report     : {report_path}")
        print()

        _print_pass(f"Report written to {report_filename}")

        # Open in default browser
        try:
            webbrowser.open(f"file://{report_path}")
        except Exception:  # noqa: BLE001
            pass

    except Exception as exc:  # noqa: BLE001
        logger.exception("Report generation failed: %s", exc)
        _print_fail(f"Report generation failed: {exc}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
