# report.py
# Generates an HTML report from Azure security audit findings.
# Displays risk scores, severity, and recommendations.

from datetime import datetime, timezone

SEVERITY_COLORS = {
    "CRITICAL": "#ff4444",
    "HIGH": "#ff8800",
    "MEDIUM": "#ffcc00",
    "LOW": "#4499ff",
    None: "#aaaaaa"
}

def generate_html_report(all_profiles, output_path):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    total = len(all_profiles)
    critical = sum(1 for p in all_profiles if p.highest_severity() == "CRITICAL")
    high = sum(1 for p in all_profiles if p.highest_severity() == "HIGH")
    medium = sum(1 for p in all_profiles if p.highest_severity() == "MEDIUM")
    total_findings = sum(len(p.findings) for p in all_profiles)

    rows = ""
    for profile in all_profiles:
        for finding in profile.findings:
            color = SEVERITY_COLORS.get(finding.severity, "#aaaaaa")
            rows += f"""
            <tr>
                <td>{profile.resource_type}</td>
                <td>{profile.resource_name}</td>
                <td>{finding.issue}</td>
                <td style="color: {color}; font-weight: bold;">{finding.severity}</td>
                <td style="color: {color}; font-weight: bold;">{finding.risk_score}</td>
                <td>{finding.recommendation}</td>
            </tr>
            """

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azure Security Audit Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #0f0f0f;
            color: #e0e0e0;
            margin: 0;
            padding: 40px;
        }}
        h1 {{ color: #ffffff; font-size: 26px; margin-bottom: 4px; }}
        .timestamp {{ color: #888; font-size: 13px; margin-bottom: 40px; }}
        .summary {{
            display: flex;
            gap: 16px;
            margin-bottom: 40px;
            flex-wrap: wrap;
        }}
        .card {{
            background: #1a1a1a;
            border-radius: 8px;
            padding: 18px 28px;
            min-width: 110px;
            text-align: center;
        }}
        .card .number {{ font-size: 32px; font-weight: bold; }}
        .card .label {{ font-size: 12px; color: #888; margin-top: 4px; text-transform: uppercase; }}
        .total {{ color: #ffffff; }}
        .critical {{ color: #ff4444; }}
        .high {{ color: #ff8800; }}
        .medium {{ color: #ffcc00; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #1a1a1a;
            border-radius: 8px;
            overflow: hidden;
        }}
        th {{
            background: #222;
            padding: 12px 16px;
            text-align: left;
            font-size: 12px;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 12px 16px;
            border-top: 1px solid #222;
            font-size: 13px;
            vertical-align: top;
        }}
        tr:hover td {{ background: #222; }}
    </style>
</head>
<body>
    <h1>Azure Security Audit Report</h1>
    <div class="timestamp">Generated: {timestamp}</div>
    <div class="summary">
        <div class="card">
            <div class="number total">{total_findings}</div>
            <div class="label">Total Findings</div>
        </div>
        <div class="card">
            <div class="number critical">{critical}</div>
            <div class="label">Critical Resources</div>
        </div>
        <div class="card">
            <div class="number high">{high}</div>
            <div class="label">High Risk</div>
        </div>
        <div class="card">
            <div class="number medium">{medium}</div>
            <div class="label">Medium Risk</div>
        </div>
    </div>
    <table>
        <thead>
            <tr>
                <th>Type</th>
                <th>Resource</th>
                <th>Issue</th>
                <th>Severity</th>
                <th>Risk Score</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>
            {rows}
        </tbody>
    </table>
</body>
</html>
"""

    with open(output_path, "w") as f:
        f.write(html)

    print(f"  HTML report saved to {output_path}")