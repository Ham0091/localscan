# LocalScan

A lightweight local security posture scanner for Windows that checks common host-level misconfigurations, exposed local services, risky files, startup persistence, and basic hardening indicators.

---

## Overview

LocalScan performs local host inspection and generates an HTML security report with severity-based findings.

It is designed for:

* educational security auditing
* local hardening review
* rapid host hygiene checks
* demonstrating modular vulnerability scanning architecture

This tool does **not** perform remote exploitation, packet interception, or vulnerability database correlation.

---

## Current Scan Coverage

### Network Checks

* local TCP port scan
* dangerous service detection
* firewall status check
* insecure protocol detection
* service banner collection

### System Checks

* User Account Control (UAC)
* Windows Defender status
* Windows Update policy
* Remote Desktop configuration
* Guest account status
* PowerShell execution policy
* SMBv1 detection
* running service inspection

### Filesystem Checks

* credential-pattern file discovery
* PEM / key file detection
* browser credential database presence
* SSH file permission review

### Services & Persistence Checks

* startup registry entries
* scheduled task inspection
* installed software inventory
* common risky software detection

---

## Output

LocalScan generates:

* HTML security report
* severity summary
* risk score
* timestamped scan output

---

## Project Structure

```text
localscan/
├── scanner.py
├── report.py
├── modules/
│   ├── __init__.py
│   ├── network.py
│   ├── system.py
│   ├── filesystem.py
│   └── services.py
```

---

## Installation

```bash
git clone https://github.com/Ham0091/localscan.git
cd localscan
pip install -r requirements.txt
```

---

## Run

Recommended:

```bash
python -m localscan.scanner
```

If using package entrypoint:

```bash
python scanner.py
```

(Depends on final package structure.)

---

## Requirements

* Python 3.10+
* Windows 10 / 11
* Administrator privileges recommended

---

## Important Scope Notes

LocalScan currently focuses on **local host hygiene**, not full enterprise hardening.

Current limitations include:

* loopback-based port checks only
* Windows-first implementation
* limited version intelligence
* no CVE feed integration
* no BitLocker / Secure Boot / LSASS coverage yet

---

## Planned Improvements

* stronger Windows hardening checks
* listener binding analysis
* improved software version intelligence
* safer risk scoring model
* better macOS support
* module result schema validation

---

## Report Philosophy

Findings are grouped by severity:

* Critical
* High
* Medium
* Low

Risk score is intended as a quick indicator and should be interpreted together with severity counts.

---

## Educational Use

This project is intended for learning modular scanner design, local enumeration techniques, and security reporting workflows.

---

## License

Add a LICENSE file before production distribution.
