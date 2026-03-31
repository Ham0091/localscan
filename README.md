# localscan

A standalone Python CLI tool that scans a Windows system for common local security vulnerabilities and generates a self-contained HTML report.

## Setup

**Requirements:** Python 3.8 or later on Windows (most checks degrade gracefully on macOS/Linux).

```
cd localscan
pip install -r requirements.txt
python scanner.py
```

Run as Administrator for full results — some checks (registry reads, SMB state, service enumeration) require elevated privileges.

## What it checks

**Network**
- Open TCP ports on localhost (1–10000)
- Dangerous services exposed: Telnet, FTP, RDP, SMB, VNC, MySQL, Redis
- Windows Firewall status across all profiles
- Unencrypted protocols (Telnet, FTP) running locally

**System**
- Windows version and patch level
- Windows Defender status and definition age
- Windows Update configuration
- User Account Control (UAC) state
- Guest account status
- Auto-login configuration
- PowerShell execution policy
- SMB v1 (EternalBlue/WannaCry attack surface)
- Remote Desktop Protocol state
- Running services — flags known risky ones

**Filesystem**
- Potential plaintext credential files in Desktop, Documents, Downloads
- SSH directory permissions
- Private key and certificate files in the home directory
- Browser password database existence (Chrome, Firefox, Edge — contents never read)

**Services and Software**
- Installed versions of Java, Adobe Reader, VLC, 7-Zip, Chrome, Firefox
- Scheduled tasks containing suspicious patterns
- Startup registry entries containing suspicious patterns

## Output

The scanner writes a timestamped HTML report (`report_YYYYMMDD_HHMMSS.html`) to the same directory and opens it in the default browser. A log file (`scanner.log`) captures errors and debug output.

## Risk scoring

| Severity | Points each | Cap |
|----------|-------------|-----|
| Critical | 20          | 40  |
| High     | 10          | 30  |
| Medium   | 5           | 20  |
| Low      | 2           | 10  |

Total is capped at 100.

## Disclaimer

This tool is intended for educational use on systems you own or have explicit written permission to scan. Do not use it on systems you do not control. The authors accept no liability for misuse.