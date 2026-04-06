# mock_data.py
# Simulates Azure AD and subscription data.
# Azure security model differs from AWS — users, guest accounts,
# service principals, and role assignments are the key identity primitives.

from datetime import datetime, timezone, timedelta

def get_mock_users():
    return [
        {
            "id": "user-001",
            "displayName": "Ishmael Robinson",
            "userPrincipalName": "ishmael@contoso.com",
            "userType": "Member",
            "accountEnabled": True,
            "createdDateTime": datetime.now(timezone.utc) - timedelta(days=365),
            "signInActivity": {
                "lastSignInDateTime": datetime.now(timezone.utc) - timedelta(days=5)
            },
            "mfaRegistered": True,
            "assignedRoles": ["Security Reader"]
        },
        {
            "id": "user-002",
            "displayName": "Bob External",
            "userPrincipalName": "bob@externaldomain.com",
            "userType": "Guest",
            "accountEnabled": True,
            "createdDateTime": datetime.now(timezone.utc) - timedelta(days=200),
            "signInActivity": {
                "lastSignInDateTime": datetime.now(timezone.utc) - timedelta(days=95)
            },
            "mfaRegistered": False,
            "assignedRoles": ["Contributor"]
        },
        {
            "id": "user-003",
            "displayName": "Carol Admin",
            "userPrincipalName": "carol@contoso.com",
            "userType": "Member",
            "accountEnabled": True,
            "createdDateTime": datetime.now(timezone.utc) - timedelta(days=500),
            "signInActivity": {
                "lastSignInDateTime": datetime.now(timezone.utc) - timedelta(days=120)
            },
            "mfaRegistered": False,
            "assignedRoles": ["Global Administrator"]
        },
        {
            "id": "user-004",
            "displayName": "Dave Stale",
            "userPrincipalName": "dave@contoso.com",
            "userType": "Member",
            "accountEnabled": True,
            "createdDateTime": datetime.now(timezone.utc) - timedelta(days=700),
            "signInActivity": None,
            "mfaRegistered": False,
            "assignedRoles": ["Reader"]
        }
    ]

def get_mock_service_principals():
    return [
        {
            "id": "sp-001",
            "displayName": "DeploymentPipeline",
            "appId": "app-id-001",
            "accountEnabled": True,
            "createdDateTime": datetime.now(timezone.utc) - timedelta(days=180),
            "assignedRoles": ["Contributor"],
            "secretsExpiringSoon": False,
            "hasExpiredSecrets": False
        },
        {
            "id": "sp-002",
            "displayName": "LegacyIntegration",
            "appId": "app-id-002",
            "accountEnabled": True,
            "createdDateTime": datetime.now(timezone.utc) - timedelta(days=900),
            "assignedRoles": ["Owner"],
            "secretsExpiringSoon": True,
            "hasExpiredSecrets": True
        },
        {
            "id": "sp-003",
            "displayName": "MonitoringAgent",
            "appId": "app-id-003",
            "accountEnabled": True,
            "createdDateTime": datetime.now(timezone.utc) - timedelta(days=90),
            "assignedRoles": ["Monitoring Reader"],
            "secretsExpiringSoon": False,
            "hasExpiredSecrets": False
        }
    ]

def get_mock_role_assignments():
    return [
        {
            "id": "ra-001",
            "principalId": "user-003",
            "principalName": "Carol Admin",
            "principalType": "User",
            "roleDefinitionName": "Global Administrator",
            "scope": "/"
        },
        {
            "id": "ra-002",
            "principalId": "sp-002",
            "principalName": "LegacyIntegration",
            "principalType": "ServicePrincipal",
            "roleDefinitionName": "Owner",
            "scope": "/"
        },
        {
            "id": "ra-003",
            "principalId": "user-002",
            "principalName": "Bob External",
            "principalType": "Guest",
            "roleDefinitionName": "Contributor",
            "scope": "/subscriptions/sub-001"
        }
    ]