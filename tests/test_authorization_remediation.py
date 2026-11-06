from lightguard.audit import SecurityReasonCode
from lightguard.core import LightGuardAgent
from lightguard.policy import (
    AuthorizationContext,
    AuthorizationMode,
    SecurityPolicyConfig,
    ToolMetadata,
    ToolPolicyRegistry,
)


def test_production_secure_rejects_empty_allowlist():
    policy = SecurityPolicyConfig(
        allowed_tools=[],
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    res = guard.verify_action("custom_unknown_tool", {"arg": "val"}, is_untrusted=False)
    assert res["allowed"] is False
    assert res["reason_code"] == SecurityReasonCode.LG_TOOL_NOT_IN_ALLOWLIST.value


def test_production_secure_rejects_empty_registry():
    policy = SecurityPolicyConfig(
        tool_registry=ToolPolicyRegistry(),
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    res = guard.verify_action("custom_unknown_tool", {"arg": "val"}, is_untrusted=False)
    assert res["allowed"] is False
    assert res["reason_code"] == SecurityReasonCode.LG_TOOL_NOT_REGISTERED.value


def test_production_secure_with_require_tool_registration():
    policy = SecurityPolicyConfig(
        require_tool_registration=True,
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    res = guard.verify_action("custom_unknown_tool", {"arg": "val"}, is_untrusted=False)
    assert res["allowed"] is False
    assert res["reason_code"] == SecurityReasonCode.LG_TOOL_NOT_IN_ALLOWLIST.value


def test_production_secure_rejects_tool_missing_from_registry():
    registry = ToolPolicyRegistry()
    registry.register_tool(ToolMetadata(name="allowed_tool_1"))

    policy = SecurityPolicyConfig(
        tool_registry=registry,
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    # Missing tool
    res_missing = guard.verify_action("unregistered_tool", {}, is_untrusted=False)
    assert res_missing["allowed"] is False
    assert res_missing["reason_code"] == SecurityReasonCode.LG_TOOL_NOT_REGISTERED.value

    # Registered tool
    res_ok = guard.verify_action("allowed_tool_1", {}, is_untrusted=False)
    assert res_ok["allowed"] is True


def test_compatibility_mode_preserves_legacy_unconstrained_execution():
    policy = SecurityPolicyConfig.compatibility()
    guard = LightGuardAgent(policy=policy)

    # In COMPATIBILITY mode, unregistered benign tool is allowed
    res = guard.verify_action("legacy_custom_tool", {"data": "ok"}, is_untrusted=False)
    assert res["allowed"] is True


def test_explicit_deny_highest_precedence_over_allowlist_and_whitelist():
    policy = SecurityPolicyConfig(
        allowed_tools=["critical_tool"],
        whitelisted_tools=["critical_tool"],
        denied_tools=["critical_tool"],
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    res = guard.verify_action("critical_tool", {}, is_untrusted=False)
    assert res["allowed"] is False
    assert res["reason_code"] == SecurityReasonCode.LG_TOOL_EXPLICIT_DENY.value


def test_whitelist_cannot_bypass_schema_validation():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="safe_calc",
            parameters_schema={
                "type": "object",
                "required": ["val"],
                "properties": {"val": {"type": "integer"}},
            },
        )
    )
    policy = SecurityPolicyConfig(
        tool_registry=registry,
        whitelisted_tools=["safe_calc"],
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    # Value is string, schema expects integer -> MUST BE BLOCKED
    res = guard.verify_action("safe_calc", {"val": "not_an_int"}, is_untrusted=False)
    assert res["allowed"] is False
    assert res["reason_code"] == SecurityReasonCode.LG_TOOL_SCHEMA_INVALID.value


def test_whitelist_cannot_bypass_canary_leak():
    canary_token = "LG_CANARY_SECRET_XYZ_999"
    policy = SecurityPolicyConfig(
        whitelisted_tools=["safe_tool"],
        enable_canary_guard=True,
        authorization_mode=AuthorizationMode.COMPATIBILITY,
    )
    guard = LightGuardAgent(policy=policy)
    guard.canary._active_canaries[canary_token] = 9999999999.0

    res = guard.verify_action("safe_tool", {"data": f"leaking {canary_token}"}, is_untrusted=False)
    assert res["allowed"] is False
    assert res["reason_code"] == SecurityReasonCode.LG_CANARY_LEAK.value


def test_whitelist_cannot_bypass_rbac_or_approval_hooks():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="privileged_tool",
            required_role="admin",
            requires_approval=True,
        )
    )

    approval_called = []

    def mock_hook(tool, args, ctx):
        approval_called.append(tool)
        return False

    policy = SecurityPolicyConfig(
        tool_registry=registry,
        whitelisted_tools=["privileged_tool"],
        approval_hook=mock_hook,
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    # 1. Non-admin caller blocked by RBAC
    res_rbac = guard.verify_action(
        "privileged_tool",
        {},
        is_untrusted=False,
        context=AuthorizationContext(caller_role="user"),
    )
    assert res_rbac["allowed"] is False
    assert res_rbac["reason_code"] == SecurityReasonCode.LG_TOOL_ROLE_UNAUTHORIZED.value

    # 2. Admin caller blocked by approval hook
    res_appr = guard.verify_action(
        "privileged_tool",
        {},
        is_untrusted=False,
        context=AuthorizationContext(caller_role="admin"),
    )
    assert res_appr["allowed"] is False
    assert res_appr["reason_code"] == SecurityReasonCode.LG_TOOL_APPROVAL_REJECTED.value
    assert approval_called == ["privileged_tool"]
