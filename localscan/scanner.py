# LocalScan — Windows vulnerability scanner
# For educational and authorized use only.
# Do not run this tool on systems you do not own or have explicit permission to scan.
# No data is transmitted externally — all findings are stored in a local HTML report.

"""
LocalScan — main entry point.

Usage:
    python scanner.py [--debug] [--quick] [--no-color]

Flags:
    --debug     Enable verbose logging output to terminal
    --quick     Skip heavy checks (e.g. full port scan)
    --no-color  Disable colored terminal output

Runs all security checks, shows live progress in the terminal, and generates
a timestamped HTML report: report_YYYYMMDD_HHMMSS.html
"""

import argparse
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

# ---------------------------------------------------------------------------
# Package path bootstrap — ensures "localscan.*" imports resolve whether this
# file is run directly (python localscan/scanner.py) or as a module
# (python -m localscan.scanner).
# ---------------------------------------------------------------------------
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

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
# CLI argument parsing
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="LocalScan — local vulnerability scanner",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose debug logging to terminal",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Skip heavy checks (e.g. full port scan)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        help="Disable colored terminal output",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate an HTML report in localscan/reports/ and open it in the browser",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner.log")

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

# Module definitions: (key, importable path, display name)
MODULE_DEFS = [
    ("network",    "localscan.modules.network",    "Network"),
    ("system",     "localscan.modules.system",     "System"),
    ("filesystem", "localscan.modules.filesystem",  "Filesystem"),
    ("services",   "localscan.modules.services",    "Services"),
]


def _run_module(
    module_name: str,
    module,
    step: int,
    total: int,
    quick: bool = False,
    is_admin: bool = False,
    on_progress: Any = None,
) -> List[Dict[str, Any]]:
    """Run a single module and return its findings."""
    if module is None:
        return [{
            "name": f"Module Unavailable: {module_name}",
            "severity": "Info",
            "description": (
                f"The {module_name} module could not be loaded. "
                "This scan category was skipped entirely."
            ),
            "recommendation": "Check scanner.log for the import error details.",
            "confidence": "High",
        }]

    _section(f"Running {module_name} checks… ({step}/{total})")

    findings: List[Dict[str, Any]] = []

    def progress_callback(msg: str) -> None:
        _print_info(msg)
        if on_progress:
            on_progress(msg)

    def _module_error(exc: Exception) -> List[Dict[str, Any]]:
        logger.exception("Module '%s' crashed: %s", module_name, exc)
        _print_fail(f"Module '{module_name}' encountered an error: {exc}")
        return [{
            "name": f"Module Error: {module_name}",
            "severity": "Info",
            "description": f"The module crashed: {exc}",
            "recommendation": "Check scanner.log for the full traceback.",
        }]

    try:
        findings = module.run_checks(
            progress_callback=progress_callback,
            quick=quick,
            is_admin=is_admin,
        )
    except Exception as exc:  # noqa: BLE001
        findings = _module_error(exc)

    # Print per-finding summary
    for f in findings:
        sev = f.get("severity", "Info")
        name = f.get("name", "")
        conf = f.get("confidence", "")
        conf_str = f" [{conf}]" if conf else ""
        if sev in ("Critical", "High"):
            _print_fail(f"[{sev}{conf_str}] {name}")
        elif sev == "Medium":
            _print_warn(f"[{sev}{conf_str}] {name}")
        else:
            _print_pass(f"[{sev}{conf_str}] {name}")

    return findings


# ---------------------------------------------------------------------------
# Reusable scan core — used by both CLI and GUI
# ---------------------------------------------------------------------------

class ScanCallbacks:
    """Optional callbacks for scan progress. All default to no-ops."""

    def on_module_start(self, module_name: str, step: int, total: int) -> None:
        """Called when a module begins running."""

    def on_finding(self, module_name: str, finding: Dict[str, Any]) -> None:
        """Called for each individual finding."""

    def on_progress(self, module_name: str, message: str) -> None:
        """Called for progress messages within a module."""

    def on_module_done(self, module_name: str, findings: List[Dict[str, Any]],
                       step: int, total: int) -> None:
        """Called when a module finishes. step/total for percentage."""

    def on_scan_complete(self, results: Dict[str, List[Dict[str, Any]]]) -> None:
        """Called when the entire scan is finished."""


def run_scan(
    *,
    quick: bool = False,
    is_admin: bool | None = None,
    callbacks: ScanCallbacks | None = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Execute all scan modules and return aggregated results.

    This is the reusable core shared by the CLI ``main()`` and the GUI
    ``ScanWorker``.  It never touches CLI args, report generation, or the
    terminal banner — callers handle those concerns.

    Parameters
    ----------
    quick : bool
        Skip heavy checks (e.g. full port scan).
    is_admin : bool | None
        Whether we're running elevated.  *None* = auto-detect.
    callbacks : ScanCallbacks | None
        Optional observer for live progress.

    Returns
    -------
    dict mapping module key -> list of finding dicts.
    """
    if callbacks is None:
        callbacks = ScanCallbacks()

    if is_admin is None:
        is_admin = _is_admin()

    modules_to_run = []
    for module_key, module_path, _display in MODULE_DEFS:
        try:
            mod = importlib.import_module(module_path, package="localscan")
            modules_to_run.append((module_key, mod))
        except ImportError as exc:
            logger.error("Could not import module '%s': %s", module_path, exc)
            _print_fail(f"Could not load module '{module_key}': {exc}")
            modules_to_run.append((module_key, None))

    total_modules = len(modules_to_run)
    all_results: Dict[str, List[Dict[str, Any]]] = {}

    for step, (module_key, module) in enumerate(modules_to_run, start=1):
        display_name = module_key.title()
        callbacks.on_module_start(display_name, step, total_modules)

        results = _run_module(
            display_name,
            module,
            step,
            total_modules,
            quick=quick,
            is_admin=is_admin,
            on_progress=lambda msg, mn=display_name: callbacks.on_progress(mn, msg),
        )
        all_results[module_key] = results

        for finding in results:
            callbacks.on_finding(display_name, finding)

        callbacks.on_module_done(display_name, results, step, total_modules)

    callbacks.on_scan_complete(all_results)
    return all_results


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    args = _parse_args()

    # Disable color if --no-color or colorama not available
    global Fore, Style  # noqa: PLW0603
    if args.no_color or not HAS_COLOR:
        class _Stub:  # type: ignore[no-redef]
            def __getattr__(self, _name: str) -> str:
                return ""
        Fore = _Stub()   # type: ignore[assignment]
        Style = _Stub()  # type: ignore[assignment]

    # Configure logging now that we know whether --debug was requested
    _log_handlers: List[logging.Handler] = [
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
    ]
    if args.debug:
        _log_handlers.append(logging.StreamHandler(sys.stderr))
    logging.basicConfig(
        handlers=_log_handlers,
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    print()
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  LocalScan — Local Vulnerability Scanner{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}")
    print(f"  Platform : {platform.system()} {platform.release()}")
    print(f"  Python   : {sys.version.split()[0]}")
    print(f"  Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if args.quick:
        print(f"  Mode     : {Fore.YELLOW}QUICK (heavy checks skipped){Style.RESET_ALL}")
    if args.debug:
        print(f"  Logging  : {Fore.YELLOW}DEBUG (verbose){Style.RESET_ALL}")
    print()

    # Administrator check
    is_admin = _is_admin()
    if is_admin:
        _print_pass("Running with elevated privileges — all checks available.")
    else:
        _print_warn(
            "Not running as Administrator. Some checks may be skipped or incomplete. "
            "Re-run as Administrator for full results."
        )
        logger.warning(
            "LocalScan started without elevated privileges. "
            "Registry, WMI, and service checks may be incomplete."
        )

    # Run scan via reusable core
    all_results = run_scan(quick=args.quick, is_admin=is_admin)

    # Always compute summary stats for the terminal output
    all_findings = [f for findings in all_results.values() for f in findings]

    try:
        from .report import (  # noqa: PLC0415
            generate_report,
            calculate_risk_score,
            _count_severities,
            get_report_path,
        )
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
        print()

        if args.report:
            _section("Generating report…")
            report_path = get_report_path()
            generate_report(all_results, str(report_path))
            print(f"  Report     : {report_path}")
            print()
            _print_pass(f"Report written to {report_path.name}")

            # Open in default browser
            try:
                webbrowser.open(report_path.as_uri())
            except Exception:  # noqa: BLE001
                pass
        else:
            _print_info("No report generated. Use --report to save an HTML report.")

    except Exception as exc:  # noqa: BLE001
        logger.exception("Report generation failed: %s", exc)
        _print_fail(f"Report generation failed: {exc}")
        traceback.print_exc()


if __name__ == "__main__":
    main()
