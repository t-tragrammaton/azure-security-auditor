import os
from datetime import datetime, timezone

from azure.identity import ClientSecretCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from msgraph import GraphServiceClient


def _credential():
    return ClientSecretCredential(
        tenant_id=os.environ["AZURE_TENANT_ID"],
        client_id=os.environ["AZURE_CLIENT_ID"],
        client_secret=os.environ["AZURE_CLIENT_SECRET"]
    )


async def get_azure_users(tenant_id):
    graph_client = GraphServiceClient(_credential())
    users_response = await graph_client.users.get()
    users = []

    for user in users_response.value:
        auth_methods = await graph_client.users.by_user_id(user.id).authentication.methods.get()
        mfa_registered = len(auth_methods.value) > 1

        role_assignments = await graph_client.users.by_user_id(user.id).member_of.get()
        roles = []
        for role in role_assignments.value:
            if hasattr(role, 'display_name'):
                roles.append(role.display_name)

        users.append({
            "id": user.id,
            "displayName": user.display_name,
            "userPrincipalName": user.user_principal_name,
            "userType": user.user_type or "Member",
            "accountEnabled": user.account_enabled,
            "createdDateTime": user.created_date_time,
            "signInActivity": {
                "lastSignInDateTime": user.sign_in_activity.last_sign_in_date_time
            } if user.sign_in_activity else None,
            "mfaRegistered": mfa_registered,
            "assignedRoles": roles
        })

    return users


async def get_azure_service_principals(tenant_id):
    graph_client = GraphServiceClient(_credential())
    sp_response = await graph_client.service_principals.get()
    service_principals = []

    for sp in sp_response.value:
        credentials = sp.password_credentials or []
        now = datetime.now(timezone.utc)
        has_expired = any(c.end_date_time < now for c in credentials if c.end_date_time)
        expiring_soon = any(
            0 < (c.end_date_time - now).days <= 30
            for c in credentials if c.end_date_time
        )

        service_principals.append({
            "id": sp.id,
            "displayName": sp.display_name,
            "appId": sp.app_id,
            "accountEnabled": sp.account_enabled,
            "createdDateTime": None,
            "assignedRoles": [],
            "secretsExpiringSoon": expiring_soon,
            "hasExpiredSecrets": has_expired
        })

    return service_principals


async def get_azure_role_assignments(subscription_id):
    credential = _credential()
    auth_client = AuthorizationManagementClient(credential, subscription_id)

    assignments = []
    for ra in auth_client.role_assignments.list_for_subscription():
        assignments.append({
            "id": ra.id,
            "principalId": ra.principal_id,
            "principalName": ra.principal_id,
            "principalType": ra.principal_type,
            "roleDefinitionName": ra.role_definition_id.split("/")[-1],
            "scope": ra.scope
        })

    return assignments
