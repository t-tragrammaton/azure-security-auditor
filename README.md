# Azure Security Auditor

A Python security tool that audits Azure AD users, service principals, and role assignments for misconfigurations. Uses numeric risk scoring to prioritize findings — resources with multiple compounding issues score higher than resources with a single severe finding.

## What it checks

### Users
| Check | Severity | Risk Score |
|---|---|---|
| MFA not registered (admin) | CRITICAL | 95 |
| MFA not registered (standard) | HIGH | 75 |
| Guest user with elevated role | HIGH | 80 |
| No sign-in activity in 90+ days | MEDIUM | 45 |
| User has never signed in | MEDIUM | 50 |

### Service Principals
| Check | Severity | Risk Score |
|---|---|---|
| Owner role assignment | CRITICAL | 95 |
| Expired secrets | HIGH | 70 |
| Secrets expiring within 30 days | MEDIUM | 40 |

### Role Assignments
| Check | Severity | Risk Score |
|---|---|---|
| Privileged role at root scope | CRITICAL | 100 |
| Guest principal with privileged role | CRITICAL | 95 |

## Why risk scoring

Flat severity labels miss compounding risk. A guest user with no MFA, an elevated role, and 90 days of inactivity is more dangerous than an admin who simply hasn't registered MFA yet. Risk scores surface these compounding issues by sorting resources by total accumulated risk.

## Output

Prints findings to terminal sorted by total risk score and saves HTML and JSON reports to the output/ folder.

## How to run it

**1. Clone the repo**

`git clone https://github.com/t-tragrammaton/azure-security-auditor.git`

`cd azure-security-auditor`

**2. Install dependencies**

`pip install azure-identity azure-mgmt-authorization msgraph-sdk`

**3. Run with mock data**

`python main.py`

**4. Run against a live Azure tenant**

Set `USE_MOCK_DATA = False` in `main.py`, then authenticate:

`az login`

`python main.py`

## Project structure

- `auditor/mock_data.py` — Simulated Azure AD data for local testing
- `auditor/azure_data.py` — Live Azure SDK calls against real tenant
- `auditor/checks.py` — Security checks using dataclasses and risk scoring
- `auditor/report.py` — HTML report generator
- `main.py` — Entry point

## Key differences from AWS IAM auditing

- Azure uses service principals instead of IAM roles for application identity
- Guest users are a first-class identity concept in Azure AD with unique risk patterns
- Role assignments scoped to "/" affect the entire tenant — equivalent to AdministratorAccess in AWS
- Secret rotation on service principals is a manual process with real expiry dates unlike AWS access keys

## Status

- [x] Azure AD user auditing
- [x] Service principal secret and role checks
- [x] Role assignment scope analysis
- [x] Numeric risk scoring with compounding
- [x] HTML and JSON report output
- [x] Live Azure SDK integration ready
- [ ] Conditional Access policy gap analysis
- [ ] Privileged Identity Management (PIM) coverage
- [ ] Microsoft Defender for Cloud integration