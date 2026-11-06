import json

from lightguard.core import LightGuardAgent
from lightguard.mcp_gateway import MCPSecurityGateway
from lightguard.policy import (
    AuthorizationContext,
    SecurityPolicyConfig,
    ToolMetadata,
    ToolPolicyRegistry,
)


def test_mcp_tools_list_filtered_by_caller_role():
    registry = ToolPolicyRegistry()
    registry.register(
        ToolMetadata(
            name="admin_drop_database",
            required_role="admin",
            risk_level="critical",
        )
    )
    registry.register(
        ToolMetadata(
            name="user_read_profile",
            required_role="user",
            risk_level="low",
        )
    )

    policy = SecurityPolicyConfig(tool_registry=registry)
    guard = LightGuardAgent(policy=policy)
    gateway = MCPSecurityGateway(guard=guard)

    tools_response = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "tools": [
                {"name": "admin_drop_database", "description": "Admin tool"},
                {"name": "user_read_profile", "description": "User tool"},
            ]
        },
    })

    # 1. Non-admin user context should NOT see admin_drop_database
    user_ctx = AuthorizationContext(caller_id="usr_123", caller_role="user")
    _, out_user = gateway.process_server_to_client(tools_response, context=user_ctx)
    res_user = json.loads(out_user)["result"]["tools"]
    tool_names_user = [t["name"] for t in res_user]
    assert "user_read_profile" in tool_names_user
    assert "admin_drop_database" not in tool_names_user

    # 2. Admin context should see both
    admin_ctx = AuthorizationContext(caller_id="adm_999", caller_role="admin")
    _, out_admin = gateway.process_server_to_client(tools_response, context=admin_ctx)
    res_admin = json.loads(out_admin)["result"]["tools"]
    tool_names_admin = [t["name"] for t in res_admin]
    assert "user_read_profile" in tool_names_admin
    assert "admin_drop_database" in tool_names_admin


def test_mcp_tools_list_filtered_by_untrusted_caller():
    registry = ToolPolicyRegistry()
    registry.register(
        ToolMetadata(
            name="execute_system_command",
            risk_level="high",
        )
    )
    registry.register(
        ToolMetadata(
            name="search_documentation",
            risk_level="low",
        )
    )

    policy = SecurityPolicyConfig(tool_registry=registry)
    guard = LightGuardAgent(policy=policy)
    gateway = MCPSecurityGateway(guard=guard)

    tools_response = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "result": {
            "tools": [
                {"name": "execute_system_command", "description": "High risk tool"},
                {"name": "search_documentation", "description": "Safe tool"},
            ]
        },
    })

    # Untrusted caller should not see high-risk tool
    untrusted_ctx = AuthorizationContext(caller_id="usr_123", is_untrusted=True)
    _, out = gateway.process_server_to_client(tools_response, context=untrusted_ctx)
    tools = json.loads(out)["result"]["tools"]
    tool_names = [t["name"] for t in tools]
    assert "search_documentation" in tool_names
    assert "execute_system_command" not in tool_names
