"""Tests for Advanced Centralized Policy & Tool Authorization Engine."""

import pytest
from lightguard.core import LightGuardAgent
from lightguard.policy import (
    AuthorizationContext,
    PolicyProfile,
    SecurityPolicyConfig,
    ToolCapability,
    ToolMetadata,
    ToolPolicyRegistry,
)


def test_tool_registry_registration_and_discovery():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="read_file",
            capabilities={ToolCapability.FS_READ},
            risk_level="low",
            required_role="user",
        )
    )
    registry.register_tool(
        ToolMetadata(
            name="rm_file",
            capabilities={ToolCapability.FS_WRITE, ToolCapability.SHELL_EXEC},
            risk_level="critical",
            required_role="admin",
            requires_approval=True,
        )
    )

    assert registry.has_capability("read_file", ToolCapability.FS_READ)
    assert not registry.has_capability("read_file", ToolCapability.FS_WRITE)
    assert registry.has_capability("rm_file", ToolCapability.SHELL_EXEC)

    # Filter tools by caller role
    user_tools = registry.list_tools(caller_role="user")
    tool_names = [t.name for t in user_tools]
    assert "read_file" in tool_names
    assert "rm_file" not in tool_names

    admin_tools = registry.list_tools(caller_role="admin")
    admin_tool_names = [t.name for t in admin_tools]
    assert "read_file" in admin_tool_names
    assert "rm_file" in admin_tool_names


def test_rbac_authorization_enforcement():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="system_reboot",
            capabilities={ToolCapability.SYSTEM_ADMIN},
            risk_level="critical",
            required_role="admin",
        )
    )

    policy = SecurityPolicyConfig(
        profile=PolicyProfile.STRICT,
        tool_registry=registry,
        role_permissions={
            "user": ["fs:read"],
            "admin": ["*"],
        },
    )
    agent = LightGuardAgent(policy=policy)

    # User role cannot invoke admin tool
    user_ctx = AuthorizationContext(caller_id="alice", caller_role="user")
    res_user = agent.verify_action(
        proposed_tool="system_reboot",
        tool_args={},
        is_untrusted=False,
        context=user_ctx,
    )
    assert not res_user["allowed"]
    assert "RBAC" in res_user["reason"] or "role" in res_user["reason"].lower()

    # Admin role can invoke it
    admin_ctx = AuthorizationContext(caller_id="root", caller_role="admin")
    res_admin = agent.verify_action(
        proposed_tool="system_reboot",
        tool_args={},
        is_untrusted=False,
        context=admin_ctx,
    )
    assert res_admin["allowed"]


def test_approval_hook_for_high_impact_actions():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="drop_database",
            capabilities={ToolCapability.DB_QUERY},
            risk_level="critical",
            requires_approval=True,
        )
    )

    approvals_called = []

    def mock_approval(tool_name: str, args: dict, ctx: AuthorizationContext) -> bool:
        approvals_called.append((tool_name, ctx.caller_id))
        return False  # Reject approval

    policy = SecurityPolicyConfig(
        tool_registry=registry,
        approval_hook=mock_approval,
    )
    agent = LightGuardAgent(policy=policy)

    ctx = AuthorizationContext(caller_id="dev1", caller_role="admin")
    res = agent.verify_action(
        proposed_tool="drop_database",
        tool_args={"db": "prod"},
        is_untrusted=False,
        context=ctx,
    )
    assert not res["allowed"]
    assert "approval" in res["reason"].lower()
    assert len(approvals_called) == 1
    assert approvals_called[0] == ("drop_database", "dev1")


def test_deny_overrides_allow_strictly():
    # If a tool is listed in both allowed and denied, policy validation either rejects config or strictly enforces deny
    policy = SecurityPolicyConfig(
        allowed_tools=["curl", "read_file"],
        denied_tools=["curl"],
    )
    agent = LightGuardAgent(policy=policy)

    res = agent.verify_action(
        proposed_tool="curl",
        tool_args={"url": "https://example.com"},
        is_untrusted=False,
    )
    assert not res["allowed"]
    assert "denied" in res["reason"].lower()
