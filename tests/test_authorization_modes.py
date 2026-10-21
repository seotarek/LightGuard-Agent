from lightguard.audit import SecurityReasonCode
from lightguard.core import LightGuardAgent
from lightguard.policy import (
    AuthorizationContext,
    AuthorizationMode,
    SecurityPolicyConfig,
    ToolCapability,
    ToolMetadata,
    ToolPolicyRegistry,
    validate_json_schema,
)


def test_pure_python_json_schema_validator():
    schema = {
        "type": "object",
        "required": ["user_id", "amount", "active", "tags"],
        "properties": {
            "user_id": {"type": "string"},
            "amount": {"type": "number"},
            "active": {"type": "boolean"},
            "tags": {
                "type": "array",
                "items": {"type": "string"},
            },
            "meta": {
                "type": "object",
                "properties": {"note": {"type": "string"}},
                "additionalProperties": False,
            },
        },
        "additionalProperties": False,
    }

    # 1. Valid data
    valid_data = {
        "user_id": "usr_123",
        "amount": 42.5,
        "active": True,
        "tags": ["vip", "finance"],
        "meta": {"note": "approved"},
    }
    is_valid, err = validate_json_schema(schema, valid_data)
    assert is_valid is True
    assert err is None

    # 2. Missing required field
    missing_req = {
        "user_id": "usr_123",
        "amount": 42.5,
        # 'active' is missing
        "tags": ["vip"],
    }
    is_valid, err = validate_json_schema(schema, missing_req)
    assert is_valid is False
    assert "Missing required property: 'active'" in err

    # 3. Wrong type for number
    bad_type = {
        "user_id": "usr_123",
        "amount": "forty-two",
        "active": True,
        "tags": ["vip"],
    }
    is_valid, err = validate_json_schema(schema, bad_type)
    assert is_valid is False
    assert "expected 'number'" in err

    # 4. Disallowed additional properties
    extra_prop = {
        "user_id": "usr_123",
        "amount": 100,
        "active": True,
        "tags": [],
        "extra_sneaky_field": "injected",
    }
    is_valid, err = validate_json_schema(schema, extra_prop)
    assert is_valid is False
    assert "Additional property 'extra_sneaky_field' not allowed" in err

    # 5. Invalid array item type
    bad_item = {
        "user_id": "usr_123",
        "amount": 100,
        "active": True,
        "tags": ["valid", 12345],  # 12345 is not a string
    }
    is_valid, err = validate_json_schema(schema, bad_item)
    assert is_valid is False
    assert "items" in err


def test_tool_schema_enforcement_in_verify_action():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="transfer_funds",
            description="Transfer money between accounts",
            capabilities={ToolCapability.DB_QUERY},
            parameters_schema={
                "type": "object",
                "required": ["recipient_id", "amount_cents"],
                "properties": {
                    "recipient_id": {"type": "string"},
                    "amount_cents": {"type": "integer"},
                },
                "additionalProperties": False,
            },
        )
    )

    policy = SecurityPolicyConfig(
        tool_registry=registry,
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    # Valid call
    res_valid = guard.verify_action(
        "transfer_funds",
        {"recipient_id": "acc_999", "amount_cents": 5000},
        is_untrusted=False,
    )
    assert res_valid["allowed"] is True

    # Missing required argument
    res_missing = guard.verify_action(
        "transfer_funds",
        {"recipient_id": "acc_999"},
        is_untrusted=False,
    )
    assert res_missing["allowed"] is False
    assert res_missing["reason_code"] == SecurityReasonCode.LG_TOOL_SCHEMA_INVALID.value
    assert "Missing required property: 'amount_cents'" in res_missing["reason"]

    # Invalid type: float passed instead of integer
    res_bad_type = guard.verify_action(
        "transfer_funds",
        {"recipient_id": "acc_999", "amount_cents": "5000"},
        is_untrusted=False,
    )
    assert res_bad_type["allowed"] is False
    assert res_bad_type["reason_code"] == SecurityReasonCode.LG_TOOL_SCHEMA_INVALID.value


def test_authorization_precedence_order():
    approval_called = []

    def hook(tool, args, ctx):
        approval_called.append(tool)
        return False

    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="dangerous_tool",
            required_role="admin",
            requires_approval=True,
            parameters_schema={
                "type": "object",
                "required": ["cmd"],
                "properties": {"cmd": {"type": "string"}},
            },
        )
    )

    policy = SecurityPolicyConfig(
        denied_tools=["dangerous_tool"],
        allowed_tools=["dangerous_tool"],
        tool_registry=registry,
        approval_hook=hook,
    )
    guard = LightGuardAgent(policy=policy)

    # Step 1: Denylist beats everything
    res = guard.verify_action("dangerous_tool", {"cmd": "run"}, is_untrusted=False)
    assert res["allowed"] is False
    assert res["reason_code"] == SecurityReasonCode.LG_TOOL_EXPLICIT_DENY.value
    assert len(approval_called) == 0

    # Step 2: Remove from denylist, but test schema failure before RBAC and approval
    policy.denied_tools = []
    res_schema = guard.verify_action(
        "dangerous_tool",
        {"wrong_arg": 123},
        is_untrusted=False,
        context=AuthorizationContext(caller_role="user"),
    )
    assert res_schema["allowed"] is False
    assert res_schema["reason_code"] == SecurityReasonCode.LG_TOOL_SCHEMA_INVALID.value
    assert len(approval_called) == 0

    # Step 3: Valid schema, but RBAC unauthorized before approval hook
    res_rbac = guard.verify_action(
        "dangerous_tool",
        {"cmd": "run"},
        is_untrusted=False,
        context=AuthorizationContext(caller_role="guest"),
    )
    assert res_rbac["allowed"] is False
    assert res_rbac["reason_code"] == SecurityReasonCode.LG_TOOL_ROLE_UNAUTHORIZED.value
    assert len(approval_called) == 0

    # Step 4: Admin role, now approval hook is reached and rejects
    res_appr = guard.verify_action(
        "dangerous_tool",
        {"cmd": "run"},
        is_untrusted=False,
        context=AuthorizationContext(caller_role="admin"),
    )
    assert res_appr["allowed"] is False
    assert res_appr["reason_code"] == SecurityReasonCode.LG_TOOL_APPROVAL_REJECTED.value
    assert approval_called == ["dangerous_tool"]


def test_authorization_mode_strict():
    registry = ToolPolicyRegistry()
    registry.register_tool(ToolMetadata(name="known_tool"))

    policy = SecurityPolicyConfig(
        tool_registry=registry,
        authorization_mode=AuthorizationMode.STRICT,
    )
    guard = LightGuardAgent(policy=policy)

    # Unknown tool blocked in STRICT mode
    res_unknown = guard.verify_action("unknown_tool", {}, is_untrusted=False)
    assert res_unknown["allowed"] is False
    assert res_unknown["reason_code"] in (
        SecurityReasonCode.LG_TOOL_NOT_REGISTERED.value,
        SecurityReasonCode.LG_TOOL_NOT_IN_ALLOWLIST.value,
    )

    # Known tool allowed in STRICT mode
    res_known = guard.verify_action("known_tool", {}, is_untrusted=False)
    assert res_known["allowed"] is True
