# main.py
# Entry point for the Azure Security Auditor.
# Runs all checks and generates HTML and JSON reports.

import json
import os
from datetime import datetime, timezone

# Toggle between mock and real Azure data
USE_MOCK_DATA = True

if USE_MOCK_DATA:
    from auditor.mock_data import get_mock_users as get_users
    from auditor.mock_data import get_mock_service_principals as get_service_principals
    from auditor.mock_data import get_mock_role_assignments as get_role_assignments
else:
    import asyncio
    from auditor.azure_data import get_azure_users as get_users
    from auditor.azure_data import get_azure_service_principals as get_service_principals
    from auditor.azure_data import get_azure_role_assignments as get_role_assignments

from auditor.checks import check_users, check_service_principals, check_role_assignments
from auditor.report import generate_html_report

def run_audit():
    print("\n" + "=" * 55)
    print("  AZURE SECURITY AUDITOR")
    print("=" * 55 + "\n")

    # Step 1 — Get data
    try:
        print("[1] Fetching Azure data...")
        users = get_users()
        service_principals = get_service_principals()
        role_assignments = get_role_assignments()
        print(f"  Found {len(users)} users, {len(service_principals)} service principals, {len(role_assignments)} role assignments\n")
    except Exception as e:
        print(f"  [FATAL] Failed to fetch Azure data: {e}")
        return

    # Step 2 — Run checks
    print("[2] Running security checks...")
    try:
        user_profiles = check_users(users)
        sp_profiles = check_service_principals(service_principals)
        ra_profiles = check_role_assignments(role_assignments)
        all_profiles = user_profiles + sp_profiles + ra_profiles
        all_profiles.sort(key=lambda p: p.total_risk_score(), reverse=True)
        print(f"  Found {sum(len(p.findings) for p in all_profiles)} findings across {len(all_profiles)} resources\n")
    except Exception as e:
        print(f"  [ERROR] Check failed: {e}")
        return

    # Step 3 — Print results
    print("[3] Audit Results\n")
    for profile in all_profiles:
        print(f"  [{profile.highest_severity()}] {profile.resource_name} ({profile.resource_type}) — Risk Score: {profile.total_risk_score()}")
        for finding in profile.findings:
            print(f"    - {finding.issue}")
            print(f"      Recommendation: {finding.recommendation}")
        print()

    # Step 4 — Save JSON report
    try:
        os.makedirs("output", exist_ok=True)
        findings_dict = {
            "audit_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_findings": sum(len(p.findings) for p in all_profiles),
            "resources": [p.to_dict() for p in all_profiles]
        }
        json_path = os.path.join("output", "azure_audit_report.json")
        with open(json_path, "w") as f:
            json.dump(findings_dict, f, indent=4, default=str)
        print(f"[4] JSON report saved to {json_path}")
    except Exception as e:
        print(f"  [ERROR] Failed to save JSON report: {e}")

    # Step 5 — Save HTML report
    try:
        html_path = os.path.join("output", "azure_audit_report.html")
        generate_html_report(all_profiles, html_path)
        os.startfile(html_path)
    except Exception as e:
        print(f"  [ERROR] Failed to generate HTML report: {e}")

    print("\nDone.")

run_audit()