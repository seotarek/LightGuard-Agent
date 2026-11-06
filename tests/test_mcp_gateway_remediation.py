import json
from unittest.mock import MagicMock

from lightguard.audit import AuditEvent, SecurityReasonCode
from lightguard.core import LightGuardAgent
from lightguard.mcp import LightGuardMCPProxy
from lightguard.mcp_gateway import MCPSecurityGateway
from lightguard.policy import (
    AuthorizationContext,
    AuthorizationMode,
    SecurityPolicyConfig,
    ToolMetadata,
    ToolPolicyRegistry,
)


class LegacyProxyWithoutContext:
    """Mock legacy proxy whose intercept_request does not accept a 'context' parameter."""

    def __init__(self, allowed: bool = True):
        self.allowed = allowed
        self.called_with: dict = {}

    def intercept_request(self, tool_name: str, arguments: dict):
        self.called_with = {"tool_name": tool_name, "arguments": arguments}
        if not self.allowed:
            return {"allowed": False, "reason": "Legacy proxy rejected tool"}
        return {"allowed": True, "reason": "Allowed"}


class CrashingProxy:
    """Mock proxy that raises an unexpected internal exception."""

    def intercept_request(self, tool_name: str, arguments: dict, context=None):
        raise RuntimeError("Unexpected internal crash in external evaluator")


def test_mcp_gateway_legacy_proxy_without_context_fallback():
    """Verify gateway gracefully falls back when proxy does not support 'context' parameter."""
    gateway = MCPSecurityGateway()
    legacy_proxy = LegacyProxyWithoutContext(allowed=True)
    gateway.proxy = legacy_proxy

    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "legacy_calculator",
            "arguments": {"x": 10, "y": 20},
        },
    }
    context = AuthorizationContext(caller_id="agent-01", caller_role="admin")
    allowed, response_str = gateway.process_client_to_server(json.dumps(request), context=context)

    assert allowed is True
    assert legacy_proxy.called_with["tool_name"] == "legacy_calculator"
    assert legacy_proxy.called_with["arguments"] == {"x": 10, "y": 20}


def test_mcp_gateway_unexpected_internal_error_fails_closed():
    """Verify gateway fails closed with JSON-RPC -32603 when interceptor raises an exception."""
    audit_events: list[AuditEvent] = []
    mock_audit_logger = MagicMock()
    mock_audit_logger.log.side_effect = lambda evt: audit_events.append(evt)

    gateway = MCPSecurityGateway(audit_logger=mock_audit_logger)
    gateway.proxy = CrashingProxy()

    request = {
        "jsonrpc": "2.0",
        "id": "req-99",
        "method": "tools/call",
        "params": {
            "name": "dangerous_action",
            "arguments": {},
        },
    }
    allowed, response_str = gateway.process_client_to_server(json.dumps(request))

    assert allowed is False
    resp = json.loads(response_str)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == "req-99"
    assert resp["error"]["code"] == -32603
    assert "Internal error during LightGuard security validation" in resp["error"]["message"]
    assert resp["error"]["data"]["tool_name"] == "dangerous_action"

    # Audit event should be recorded
    assert len(audit_events) == 1
    assert audit_events[0].decision == "BLOCK"
    assert audit_events[0].reason_code == SecurityReasonCode.LG_TOOL_ROLE_UNAUTHORIZED


def test_mcp_gateway_end_to_end_successful_tool_call():
    """Verify full end-to-end execution of a registered, allowed tool."""
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="fetch_weather",
            parameters_schema={
                "type": "object",
                "required": ["city"],
                "properties": {"city": {"type": "string"}},
            },
        )
    )
    policy = SecurityPolicyConfig(
        tool_registry=registry,
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)
    gateway = MCPSecurityGateway(guard=guard)

    request = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "fetch_weather",
            "arguments": {"city": "Cairo"},
        },
    }
    context = AuthorizationContext(caller_id="user-123", caller_role="user")
    allowed, response_str = gateway.process_client_to_server(json.dumps(request), context=context)

    assert allowed is True
    # If allowed, process_client_to_server returns the original request unmodified
    assert json.loads(response_str) == request


def test_mcp_gateway_end_to_end_denied_tool_call():
    """Verify full end-to-end execution of an unauthorized tool call is blocked."""
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="restricted_tool",
            required_role="admin",
        )
    )
    policy = SecurityPolicyConfig(
        tool_registry=registry,
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)
    gateway = MCPSecurityGateway(guard=guard)

    request = {
        "jsonrpc": "2.0",
        "id": 43,
        "method": "tools/call",
        "params": {
            "name": "restricted_tool",
            "arguments": {},
        },
    }
    # Caller is "user", not "admin"
    context = AuthorizationContext(caller_id="user-123", caller_role="user")
    allowed, response_str = gateway.process_client_to_server(json.dumps(request), context=context)

    assert allowed is False
    resp = json.loads(response_str)
    assert resp["jsonrpc"] == "2.0"
    assert resp["id"] == 43
    assert resp["error"]["code"] == -32001
    assert "RBAC Policy Blocked" in resp["error"]["message"]


def test_mcp_proxy_intercept_request_exception_safety():
    """Verify LightGuardMCPProxy.intercept_request catches internal errors and returns an error response."""
    mock_guard = MagicMock()
    mock_guard.verify_action.side_effect = ValueError("Core engine failure")
    proxy = LightGuardMCPProxy(guard=mock_guard)

    result = proxy.intercept_request("any_tool", {})
    assert result["allowed"] is False
    assert "Internal Security Error" in result["reason"]
    assert result["mcp_error_response"]["isError"] is True
