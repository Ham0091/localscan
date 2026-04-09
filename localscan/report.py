"""
HTML report generator for LocalScan.
Produces a self-contained, timestamped HTML report with dark theme.
"""

import html
import socket
from datetime import datetime
from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

SEVERITY_POINTS = {
    "Critical": 25,
    "High":     10,
    "Medium":    4,
    "Low":       1,
    "Info":      0,
}

SEVERITY_CAPS = {
    "Critical": 50,   # 2+ criticals = 50 pts max from this tier
    "High":     30,
    "Medium":   15,
    "Low":       5,
    "Info":      0,
}

SEVERITY_COLORS = {
    "Critical": "#ef4444",
    "High": "#f97316",
    "Medium": "#eab308",
    "Low": "#22c55e",
    "Info": "#71717a",
}


def calculate_risk_score(findings: List[Dict[str, Any]]) -> int:
    """
    Calculate a risk score (0-100) from a list of findings.

    Scoring rules:
    - Each severity tier contributes min(count * points, cap) pts
    - Any Critical finding guarantees the score is at least 50,
      enforcing monotonicity: a host with a Critical always
      outranks a host with zero Criticals
    - Final score is capped at 100
    """
    counts = _count_severities(findings)

    raw = sum(
        min(counts.get(sev, 0) * pts, SEVERITY_CAPS[sev])
        for sev, pts in SEVERITY_POINTS.items()
    )

    # Monotonicity guarantee: any Critical finding floors the
    # score at 50
    if counts.get("Critical", 0) > 0:
        raw = max(raw, 50)

    return min(raw, 100)


def _count_severities(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        sev = f.get("severity", "Info")
        if sev in counts:
            counts[sev] += 1
    return counts


def _executive_summary(score: int, counts: Dict[str, int]) -> str:
    critical = counts["Critical"]
    high = counts["High"]
    medium = counts["Medium"]

    if score >= 70:
        urgency = "The system is at high risk and requires immediate remediation."
    elif score >= 40:
        urgency = "The system has several security weaknesses that should be addressed promptly."
    else:
        urgency = "The system appears to be in a reasonable security posture with minor issues."

    issue_parts = []
    if critical:
        issue_parts.append(f"{critical} critical finding{'s' if critical > 1 else ''}")
    if high:
        issue_parts.append(f"{high} high-severity finding{'s' if high > 1 else ''}")
    if medium:
        issue_parts.append(f"{medium} medium-severity finding{'s' if medium > 1 else ''}")

    if issue_parts:
        issue_str = ", ".join(issue_parts)
        detail = f"The scan identified {issue_str} that require attention."
    else:
        detail = "No critical or high-severity issues were detected."

    return f"{urgency} {detail} Review the findings below and follow the recommendations provided."


def _h(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text), quote=True)


def _findings_table(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "<p class='no-findings'>No findings for this module.</p>"

    rows = []
    for f in findings:
        sev = f.get("severity", "Info")
        color = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["Info"])
        confidence = f.get("confidence", "")
        conf_cell = f"<td class='conf'>{_h(confidence)}</td>" if confidence else "<td class='conf'>—</td>"
        rows.append(
            f"<tr>"
            f"<td><span class='badge' style='background:{color}'>{_h(sev)}</span></td>"
            f"<td>{_h(f.get('name', ''))}</td>"
            f"{conf_cell}"
            f"<td class='desc'>{_h(f.get('description', ''))}</td>"
            f"<td class='rec'>{_h(f.get('recommendation', ''))}</td>"
            f"</tr>"
        )

    return (
        "<table>"
        "<thead><tr>"
        "<th>Severity</th><th>Finding</th><th>Confidence</th>"
        "<th>Description</th><th>Recommendation</th>"
        "</tr></thead>"
        "<tbody>" + "".join(rows) + "</tbody>"
        "</table>"
    )


_VALID_SEVERITIES = frozenset(
    {"Critical", "High", "Medium", "Low", "Info"}
)
_REQUIRED_KEYS = {"name", "severity", "description",
                  "recommendation"}


def _validate_finding(
    finding: Dict[str, Any],
    module: str,
) -> Dict[str, Any]:
    """
    Validate and normalise a single finding dict.
    - Ensures required keys are present (fills in defaults if not)
    - Normalises unknown severity values to 'Info'
    - Never raises — returns a corrected finding
    """
    if not isinstance(finding, dict):
        return {
            "name": f"Malformed Finding ({module})",
            "severity": "Info",
            "description": (
                f"A non-dict finding was returned by the "
                f"{module} module: {finding!r:.200}"
            ),
            "recommendation": "Check scanner.log for details.",
            "confidence": "Low",
        }

    out = dict(finding)
    for key in _REQUIRED_KEYS:
        if key not in out or not out[key]:
            if key == "severity":
                out[key] = "Info"
            elif key == "recommendation":
                out[key] = "No recommendation provided."
            elif key == "name":
                out[key] = f"Unnamed Finding ({module})"
            elif key == "description":
                out[key] = "No description provided."

    if out.get("severity") not in _VALID_SEVERITIES:
        out["_original_severity"] = out["severity"]
        out["severity"] = "Info"

    return out


def generate_report(
    module_results: Dict[str, List[Dict[str, Any]]],
    output_path: str,
) -> None:
    """
    Generate a self-contained HTML report.

    Args:
        module_results: Mapping of module name to list of finding dicts.
        output_path: Absolute path to write the .html file.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        hostname = socket.gethostname()
    except Exception:  # noqa: BLE001
        hostname = "unknown"

    validated_results: Dict[str, List[Dict[str, Any]]] = {}
    for module_name, findings_list in module_results.items():
        validated_results[module_name] = [
            _validate_finding(f, module_name)
            for f in (findings_list or [])
        ]

    all_findings = [f for findings in validated_results.values() for f in findings]
    score = calculate_risk_score(all_findings)
    counts = _count_severities(all_findings)
    summary = _executive_summary(score, counts)

    # Score color
    if score >= 70:
        score_color = SEVERITY_COLORS["Critical"]
    elif score >= 40:
        score_color = SEVERITY_COLORS["High"]
    elif score >= 20:
        score_color = SEVERITY_COLORS["Medium"]
    else:
        score_color = SEVERITY_COLORS["Low"]

    # Module sections
    section_html = ""
    module_display_names = {
        "network": "Network",
        "system": "System",
        "filesystem": "Filesystem",
        "services": "Services & Software",
    }
    for module_key, findings in validated_results.items():
        display_name = module_display_names.get(module_key, module_key.title())
        section_html += f"""
        <section class="module-section">
            <h2>{_h(display_name)} Checks</h2>
            {_findings_table(findings)}
        </section>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LocalScan Report — {_h(hostname)}</title>
<style>
  body, * {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
          "Helvetica Neue", Arial, sans-serif;
  }}
  code, pre, .log, .monospace {{
      font-family: "JetBrains Mono", "Fira Code", "Cascadia Code",
          "Consolas", "Courier New", monospace;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    background: #0a0a0f;
    color: #e4e4e7;
    font-size: 14px;
    line-height: 1.6;
    padding: 2rem;
  }}

  a {{ color: #71717a; }}

  header {{
    border-bottom: 1px solid #27272a;
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }}

  header h1 {{
    font-size: 1.8rem;
    font-weight: 700;
    color: #e4e4e7;
    letter-spacing: 0.05em;
  }}

  header .meta {{
    color: #71717a;
    font-size: 0.85rem;
    margin-top: 0.4rem;
  }}

  .summary-grid {{
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 2rem;
    margin-bottom: 2rem;
  }}

  .score-card {{
    background: #12121a;
    border: 1px solid #27272a;
    border-radius: 8px;
    padding: 1.5rem 2rem;
    text-align: center;
    min-width: 160px;
  }}

  .score-value {{
    font-size: 3rem;
    font-weight: 700;
    color: {score_color};
    line-height: 1;
  }}

  .score-label {{
    color: #71717a;
    font-size: 0.8rem;
    margin-top: 0.4rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
  }}

  .severity-counts {{
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    margin-top: 1rem;
  }}

  .sev-badge {{
    padding: 0.3rem 0.7rem;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 500;
  }}

  .executive-card {{
    background: #12121a;
    border: 1px solid #27272a;
    border-radius: 8px;
    padding: 1.5rem;
    display: flex;
    align-items: center;
  }}

  .executive-card p {{
    color: #a1a1aa;
    line-height: 1.7;
  }}

  .module-section {{
    background: #12121a;
    border: 1px solid #27272a;
    border-radius: 8px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
  }}

  .module-section h2 {{
    font-size: 1rem;
    font-weight: 700;
    color: #e4e4e7;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    margin-bottom: 1rem;
    border-bottom: 1px solid #27272a;
    padding-bottom: 0.5rem;
  }}

  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.83rem;
  }}

  thead tr {{
    background: #1c1c28;
  }}

  th {{
    text-align: left;
    padding: 0.6rem 0.8rem;
    color: #71717a;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-size: 0.75rem;
  }}

  td {{
    padding: 0.6rem 0.8rem;
    vertical-align: top;
    border-top: 1px solid #1e1e2e;
  }}

  tr:hover td {{
    background: #16161f;
  }}

  .badge {{
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    font-size: 0.75rem;
    font-weight: 700;
    color: #0a0a0f;
    white-space: nowrap;
  }}

  .desc, .rec {{
    white-space: pre-wrap;
    word-break: break-word;
  }}

  .no-findings {{
    color: #71717a;
    font-style: italic;
    padding: 0.5rem 0;
  }}

  footer {{
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid #27272a;
    text-align: center;
    color: #3f3f46;
    font-size: 0.8rem;
  }}

  @media (max-width: 700px) {{
    .summary-grid {{ grid-template-columns: 1fr; }}
    body {{ padding: 1rem; }}
  }}
</style>
</head>
<body>

<header>
  <h1>LocalScan Security Report</h1>
  <div class="meta">Host: {_h(hostname)} &nbsp;|&nbsp; Generated: {_h(timestamp)}</div>
</header>

<div class="summary-grid">
  <div class="score-card">
    <div class="score-value">{score}</div>
    <div class="score-label">Risk Score</div>
    <div class="severity-counts">
      <span class="sev-badge" style="background:{SEVERITY_COLORS['Critical']};color:#0a0a0f">
        {counts['Critical']} Critical
      </span>
      <span class="sev-badge" style="background:{SEVERITY_COLORS['High']};color:#0a0a0f">
        {counts['High']} High
      </span>
      <span class="sev-badge" style="background:{SEVERITY_COLORS['Medium']};color:#0a0a0f">
        {counts['Medium']} Medium
      </span>
      <span class="sev-badge" style="background:{SEVERITY_COLORS['Low']};color:#0a0a0f">
        {counts['Low']} Low
      </span>
    </div>
  </div>
  <div class="executive-card">
    <p>{_h(summary)}</p>
  </div>
</div>

{section_html}

<footer>Generated by LocalScan &mdash; for authorized use only</footer>

</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)
