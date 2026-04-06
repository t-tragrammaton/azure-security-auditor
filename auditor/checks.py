# checks.py
# Azure security checks using dataclasses and numeric risk scoring.
# Each resource accumulates a total risk score across multiple findings.
# This differs from the AWS auditor which used flat severity labels.

from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import List, Optional

# -----------------------------------------------
# DATACLASSES
# -----------------------------------------------

@dataclass
class Finding:
    resource_id: str
    resource_name: str
    resource_type: str
    issue: str
    severity: str
    risk_score: int
    recommendation: str

@dataclass
class RiskProfile:
    resource_id: str
    resource_name: str
    resource_type: str
    findings: List[Finding] = field(default_factory=list)

    def total_risk_score(self):
        return sum(f.risk_score for f in self.findings)

    def highest_severity(self):
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: order.get(f.severity, 0)).severity

    def to_dict(self):
        return {
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "total_risk_score": self.total_risk_score(),
            "highest_severity": self.highest_severity(),
            "findings": [
                {
                    "issue": f.issue,
                    "severity": f.severity,
                    "risk_score": f.risk_score,
                    "recommendation": f.recommendation
                }
                for f in self.findings
            ]
        }

# -----------------------------------------------
# CHECKS
# -----------------------------------------------

def check_users(users) -> List[RiskProfile]:
    profiles = []
    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)

    for user in users:
        profile = RiskProfile(
            resource_id=user["id"],
            resource_name=user["displayName"],
            resource_type="User"
        )

        try:
            # Check MFA
            if not user["mfaRegistered"]:
                is_admin = any(r in ["Global Administrator", "Privileged Role Administrator"]
                             for r in user["assignedRoles"])
                score = 95 if is_admin else 75
                severity = "CRITICAL" if is_admin else "HIGH"
                profile.findings.append(Finding(
                    resource_id=user["id"],
                    resource_name=user["displayName"],
                    resource_type="User",
                    issue="MFA not registered",
                    severity=severity,
                    risk_score=score,
                    recommendation="Enforce MFA via Conditional Access policy immediately"
                ))

            # Check guest users with elevated roles
            if user["userType"] == "Guest":
                elevated = any(r in ["Contributor", "Owner", "Global Administrator"]
                             for r in user["assignedRoles"])
                if elevated:
                    profile.findings.append(Finding(
                        resource_id=user["id"],
                        resource_name=user["displayName"],
                        resource_type="User",
                        issue="Guest user with elevated role assignment",
                        severity="HIGH",
                        risk_score=80,
                        recommendation="Review guest access — apply least privilege, restrict to Reader where possible"
                    ))

            # Check inactive users
            sign_in = user.get("signInActivity")
            if sign_in is None:
                profile.findings.append(Finding(
                    resource_id=user["id"],
                    resource_name=user["displayName"],
                    resource_type="User",
                    issue="User has never signed in",
                    severity="MEDIUM",
                    risk_score=50,
                    recommendation="Disable or remove account — no sign-in activity detected"
                ))
            elif sign_in["lastSignInDateTime"] < ninety_days_ago:
                profile.findings.append(Finding(
                    resource_id=user["id"],
                    resource_name=user["displayName"],
                    resource_type="User",
                    issue="No sign-in activity in 90+ days",
                    severity="MEDIUM",
                    risk_score=45,
                    recommendation="Review and disable inactive account"
                ))

        except Exception as e:
            profile.findings.append(Finding(
                resource_id=user["id"],
                resource_name=user["displayName"],
                resource_type="User",
                issue=f"Check error: {e}",
                severity="LOW",
                risk_score=0,
                recommendation="Review manually"
            ))

        if profile.findings:
            profiles.append(profile)

    return sorted(profiles, key=lambda p: p.total_risk_score(), reverse=True)


def check_service_principals(service_principals) -> List[RiskProfile]:
    profiles = []

    for sp in service_principals:
        profile = RiskProfile(
            resource_id=sp["id"],
            resource_name=sp["displayName"],
            resource_type="ServicePrincipal"
        )

        try:
            # Check for Owner role
            if "Owner" in sp["assignedRoles"]:
                profile.findings.append(Finding(
                    resource_id=sp["id"],
                    resource_name=sp["displayName"],
                    resource_type="ServicePrincipal",
                    issue="Service principal assigned Owner role",
                    severity="CRITICAL",
                    risk_score=95,
                    recommendation="Reduce to least privilege — service principals should never hold Owner"
                ))

            # Check expired secrets
            if sp["hasExpiredSecrets"]:
                profile.findings.append(Finding(
                    resource_id=sp["id"],
                    resource_name=sp["displayName"],
                    resource_type="ServicePrincipal",
                    issue="Service principal has expired secrets",
                    severity="HIGH",
                    risk_score=70,
                    recommendation="Rotate secrets immediately and audit all dependent applications"
                ))

            # Check secrets expiring soon
            if sp["secretsExpiringSoon"] and not sp["hasExpiredSecrets"]:
                profile.findings.append(Finding(
                    resource_id=sp["id"],
                    resource_name=sp["displayName"],
                    resource_type="ServicePrincipal",
                    issue="Service principal secrets expiring within 30 days",
                    severity="MEDIUM",
                    risk_score=40,
                    recommendation="Rotate secrets before expiry to prevent service disruption"
                ))

        except Exception as e:
            profile.findings.append(Finding(
                resource_id=sp["id"],
                resource_name=sp["displayName"],
                resource_type="ServicePrincipal",
                issue=f"Check error: {e}",
                severity="LOW",
                risk_score=0,
                recommendation="Review manually"
            ))

        if profile.findings:
            profiles.append(profile)

    return sorted(profiles, key=lambda p: p.total_risk_score(), reverse=True)


def check_role_assignments(role_assignments) -> List[RiskProfile]:
    profiles = []
    privileged_roles = ["Owner", "Global Administrator", "Privileged Role Administrator", "User Access Administrator"]

    for ra in role_assignments:
        profile = RiskProfile(
            resource_id=ra["id"],
            resource_name=ra["principalName"],
            resource_type="RoleAssignment"
        )

        try:
            # Check privileged roles at root scope
            if ra["roleDefinitionName"] in privileged_roles and ra["scope"] == "/":
                profile.findings.append(Finding(
                    resource_id=ra["id"],
                    resource_name=ra["principalName"],
                    resource_type="RoleAssignment",
                    issue=f"Privileged role '{ra['roleDefinitionName']}' assigned at root scope",
                    severity="CRITICAL",
                    risk_score=100,
                    recommendation="Scope role assignments to specific subscriptions or resource groups — never root"
                ))

            # Check guest with any privileged role
            if ra["principalType"] == "Guest" and ra["roleDefinitionName"] in privileged_roles:
                profile.findings.append(Finding(
                    resource_id=ra["id"],
                    resource_name=ra["principalName"],
                    resource_type="RoleAssignment",
                    issue=f"Guest principal holds privileged role '{ra['roleDefinitionName']}'",
                    severity="CRITICAL",
                    risk_score=95,
                    recommendation="Remove privileged access from guest accounts immediately"
                ))

        except Exception as e:
            profile.findings.append(Finding(
                resource_id=ra["id"],
                resource_name=ra["principalName"],
                resource_type="RoleAssignment",
                issue=f"Check error: {e}",
                severity="LOW",
                risk_score=0,
                recommendation="Review manually"
            ))

        if profile.findings:
            profiles.append(profile)

    return sorted(profiles, key=lambda p: p.total_risk_score(), reverse=True)