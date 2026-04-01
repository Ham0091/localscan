# LocalScan Self-Audit Report

*Generated after Phase 1 improvements — for honest review by developers and users.*

---

## 1. SUMMARY

LocalScan was refactored to improve reliability, performance, safety, and accuracy. The following areas were addressed:

- CLI flags added (`--debug`, `--quick`, `--no-color`) for flexible execution
- Banner grabbing added to network scanning for higher-confidence service detection
- Confidence field (`High` / `Medium` / `Low`) added to all network and filesystem findings
- Context-based severity escalation: RDP + disabled firewall → escalated to Critical
- Filesystem scanning now enforces depth limits, file-size caps, and symlink avoidance
- Admin privilege status now logged and propagated to all modules
- All module `run_checks()` functions accept `quick` and `is_admin` keyword arguments
- HTML report updated with Confidence column; all dynamic content was already HTML-escaped via `html.escape()`
- Logging improved: file handler always present; stderr handler added when `--debug` is set; module names included in all log records

---

## 2. CRITICAL FIXES

| # | Issue | Fix |
|---|-------|-----|
| 1 | `filesystem.py` used `Path.rglob()` which has no depth limit, no symlink guard, and no file-size guard — could hang on deep or looped directory structures | Replaced with `_safe_rglob()` which respects `MAX_SCAN_DEPTH=4`, skips symlinks, and skips files >10 MB |
| 2 | `network.py` firewall check result was appended *after* the dangerous-port findings, so the RDP + firewall escalation logic had no data to work with | Moved firewall check to run *first*; result stored in module-level `_firewall_disabled` flag and consumed by port-findings loop |
| 3 | Module `run_checks()` functions did not accept `quick` or `is_admin` kwargs, causing a `TypeError` when called from updated `scanner.py` | All four modules now accept `**kwargs`-compatible `quick` and `is_admin` positional keyword arguments; `scanner.py` uses a `TypeError` fallback for forward compatibility |
| 4 | `scanner.py` called `logging.basicConfig(filename=…)` which silently discarded the `--debug` stderr stream if basicConfig was already configured | Replaced with explicit `FileHandler` (always) + `StreamHandler` (only when `--debug`) passed to `handlers=` |

---

## 3. PERFORMANCE IMPROVEMENTS

| Area | Before | After |
|------|--------|-------|
| Port scanning | Already used `ThreadPoolExecutor(max_workers=100)` | No change needed; `max_workers` and `timeout` are now explicit named parameters for easy tuning |
| `--quick` mode | Not available | Reduces port scan range from 1–10 000 to 1–1 024, significantly cutting scan time for interactive use |
| Filesystem scan | `Path.rglob()` traversed unlimited depth with no short-circuit | `_safe_rglob()` stops at depth 4 and skips oversized files; no blocking I/O on file contents |
| Firewall state caching | Firewall command re-evaluated if called from multiple places | Result stored in `_firewall_disabled` module-level variable for the lifetime of the scan session |

---

## 4. RELIABILITY IMPROVEMENTS

- **Registry/WMI calls** in `system.py` and `services.py` were already wrapped in `try/except`; confirmed they return `None` on any failure and never crash.
- **Permission errors** during filesystem scans are now silently swallowed at every directory level in `_safe_rglob()`, preventing partial scans from raising exceptions.
- **Symlink loops** in filesystem scans are prevented: `entry.is_symlink()` is checked before recursing into directories or matching files.
- **Browser DB check** now also skips symlinks to avoid accessing files outside intended paths.
- **`_run_module()`** in `scanner.py` catches `TypeError` from modules that don't yet accept new kwargs, falling back gracefully to the old signature.
- **Admin warning** is now both printed to the terminal *and* written to `scanner.log`, making it visible in automated log pipelines.

---

## 5. SECURITY IMPROVEMENTS

### HTML Injection Prevention
`report.py` already used `html.escape()` (the `_h()` helper) on all dynamic values including hostname, timestamps, finding names, descriptions, and recommendations. The new Confidence column cell value is also HTML-escaped via `_h(confidence)`.

### Banner Grabbing Safety
`_grab_banner()` uses a hard `recv(256)` limit and decodes with `errors="replace"` to prevent binary content or crafted banners from corrupting the finding description. All exceptions are silently swallowed so a malformed service cannot crash the scanner.

### No Subprocess Shell Injection
All `subprocess.run()` calls use list arguments (never `shell=True`) and have explicit `timeout` values. No user-supplied input is passed to subprocesses.

### Sensitive Data in Logs
`scanner.log` does not log registry values (passwords, tokens) or file contents. Only error messages and module names are recorded.

---

## 6. LIMITATIONS (IMPORTANT)

### False Positives
- **Credential file scan**: Files matching patterns like `*secret*`, `*password*`, or `*.env` are flagged purely by filename. Many such files (e.g., `password_policy.docx`, `.env.example`) are benign. Contents are **never read**, so accuracy is name-based only — confidence is marked `Medium`.
- **Dangerous port detection**: Without a confirmed banner, service identification relies on well-known port numbers. Any non-standard service on port 3306 will be flagged as "MySQL" with `Medium` confidence.
- **Suspicious scheduled tasks / startup entries**: Regex patterns (`mshta`, `rundll32`, `temp`) can match legitimate Windows tasks. These findings require manual review.

### Platform Coverage
- The majority of checks (Defender, WMI, registry, SMB, UAC, scheduled tasks) are **Windows-only** and return `Info`-severity skipped findings on Linux/macOS. LocalScan is primarily a Windows tool.

### What Cannot Be Accurately Detected
- Whether detected software versions are vulnerable to specific CVEs (no CVE database integration)
- Whether a service is actually exploitable vs. just open
- Memory-resident malware or rootkits
- Network-based attacks originating from outside the local machine
- Whether credentials inside flagged files are real or example/dummy values

---

## 7. REMAINING RISKS

| Risk | Impact | Notes |
|------|--------|-------|
| Port scan speed vs. accuracy | A 0.5 s timeout may miss services with slow response times | Tunable via `scan_open_ports(timeout=…)` |
| Banner grabbing can trigger IDS/IPS | Some security appliances flag recv-only connections | Acceptable for local scanner; document if used in enterprise |
| `_firewall_disabled` is a module-level global | Not thread-safe if modules are ever parallelised | Acceptable in current sequential execution model |
| WMI/registry not queried on non-admin | Some findings may be `Info` when they should be `High` | Warn user and document in report |
| `scanner.log` grows unboundedly | Disk exhaustion on long-running or repeated scans | Consider adding `RotatingFileHandler` in a future release |
| HTML report opens in browser automatically | May be unexpected in headless/CI environments | Wrap `webbrowser.open()` in a flag or suppress in `--quick` mode |

---

## 8. OPTIONAL FUTURE IMPROVEMENTS

| Idea | Value |
|------|-------|
| **CVE integration** | Correlate detected software versions against NVD/OSV CVE database to flag known-vulnerable software |
| **JSON export** | `--output json` flag for machine-readable output, enabling CI/CD pipeline integration |
| **Baseline comparison** | Save a reference scan and highlight delta on subsequent runs |
| **Plugin system** | Allow third-party modules to be dropped into `localscan/modules/` and auto-discovered |
| **`RotatingFileHandler`** | Prevent `scanner.log` from growing indefinitely |
| **Async port scanning** | Replace `ThreadPoolExecutor` with `asyncio` for lower memory overhead at high concurrency |
| **Report suppression** | `--no-browser` flag to suppress automatic `webbrowser.open()` |
| **CVSS-based scoring** | Replace flat severity points with CVSS-derived scoring for more accurate risk scores |
