import json
import os
from datetime import datetime, timezone

USE_MOCK_DATA = False

if USE_MOCK_DATA:
    from auditor.mock_data import get_mock_users as get_users
    from auditor.mock_data import get_mock_service_principals as get_service_principals
    from auditor.mock_data import get_mock_role_assignments as get_role_assignments
else:
    import asyncio
    import subprocess
    from auditor.azure_data import get_azure_users as get_users
    from auditor.azure_data import get_azure_service_principals as get_service_principals
    from auditor.azure_data import get_azure_role_assignments as get_role_assignments

from auditor.checks import check_users, check_service_principals, check_role_assignments
from auditor.report import generate_html_report

def run_audit():
    print("AZURE SECURITY AUDITOR")

    try:
        print("[1] Fetching Azure data...")
        if USE_MOCK_DATA:
            users = get_users()
            service_principals = get_service_principals()
            role_assignments = get_role_assignments()
        else:
            tenant_id = subprocess.run(
                ["az", "account", "show", "--query", "tenantId", "-o", "tsv"],
                capture_output=True, text=True
            ).stdout.strip()
            users = asyncio.run(get_users(tenant_id))
            service_principals = asyncio.run(get_service_principals(tenant_id))
            subscription_id = subprocess.run(["az", "account", "show", "--query", "id", "-o", "tsv"], capture_output=True, text=True).stdout.strip()
            role_assignments = asyncio.run(get_role_assignments(subscription_id))
        print(f"  Found {len(users)} users, {len(service_principals)} service principals, {len(role_assignments)} role assignments")
    except Exception as e:
        print(f"  [FATAL] Failed to fetch Azure data: {e}")
        return

    try:
        user_profiles = check_users(users)
        sp_profiles = check_service_principals(service_principals)
        ra_profiles = check_role_assignments(role_assignments)
        all_profiles = user_profiles + sp_profiles + ra_profiles
        all_profiles.sort(key=lambda p: p.total_risk_score(), reverse=True)
        print(f"  Found {sum(len(p.findings) for p in all_profiles)} findings across {len(all_profiles)} resources")
    except Exception as e:
        print(f"  [ERROR] Check failed: {e}")
        return

    for profile in all_profiles:
        print(f"  [{profile.highest_severity()}] {profile.resource_name} ({profile.resource_type}) Risk Score: {profile.total_risk_score()}")
        for finding in profile.findings:
            print(f"    - {finding.issue}")
            print(f"      Recommendation: {finding.recommendation}")

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

    try:
        html_path = os.path.join("output", "azure_audit_report.html")
        generate_html_report(all_profiles, html_path)
        print(f"  Open {html_path} in a browser to view it.")
    except Exception as e:
        print(f"  [ERROR] Failed to generate HTML report: {e}")

    print("Done.")

run_audit()
