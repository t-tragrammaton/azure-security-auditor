# azure_data.py
# Real Azure SDK calls — replaces mock_data.py when credentials are configured.
# Uses azure-identity and azure-mgmt libraries.

from azure.identity import DefaultAzureCredential
from azure.mgmt.authorization import AuthorizationManagementClient
from msgraph import GraphServiceClient
from datetime import datetime, timezone

async def get_azure_users(tenant_id):
    credential = DefaultAzureCredential()
    graph_client = GraphServiceClient(credential)

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
    credential = DefaultAzureCredential()
    graph_client = GraphServiceClient(credential)

    sp_response = await graph_client.service_principals.get()
    service_principals = []

    for sp in sp_response.value:
        credentials = await graph_client.service_principals.by_service_principal_id(sp.id).password_credentials.get()
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
            "createdDateTime": sp.created_date_time,
            "assignedRoles": [],
            "secretsExpiringSoon": expiring_soon,
            "hasExpiredSecrets": has_expired
        })

    return service_principals


async def get_azure_role_assignments(subscription_id):
    credential = DefaultAzureCredential()
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