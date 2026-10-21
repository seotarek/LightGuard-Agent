"""Tests for Hardened MCP Gateway, Capability Discovery Filtering, and Size Bounds."""

import json

from lightguard.core import LightGuardAgent
from lightguard.mcp_gateway import MCPSecurityGateway
from lightguard.policy import SecurityPolicyConfig, ToolMetadata, ToolPolicyRegistry


def test_mcp_message_size_limit():
    gateway = MCPSecurityGateway(max_message_size=500)

    # Oversized payload (1000 bytes)
    huge_payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "test", "arguments": {"data": "X" * 1000}},
    })

    allowed, resp_str = gateway.process_client_to_server(huge_payload)
    assert not allowed
    resp = json.loads(resp_str)
    assert resp["error"]["code"] == -32600
    assert "limit" in resp["error"]["message"].lower() or "size" in resp["error"]["message"].lower()


def test_mcp_tools_list_discovery_filtering():
    registry = ToolPolicyRegistry()
    registry.register_tool(ToolMetadata(name="public_read", required_role="user"))
    registry.register_tool(ToolMetadata(name="admin_destroy", required_role="admin"))

    policy = SecurityPolicyConfig(
        tool_registry=registry,
        denied_tools=["secret_internal_tool"],
    )
    guard = LightGuardAgent(policy=policy)
    gateway = MCPSecurityGateway(guard=guard)

    # Server sends tools/list response
    tools_list_response = json.dumps({
        "jsonrpc": "2.0",
        "id": 42,
        "result": {
            "tools": [
                {"name": "public_read", "description": "Read public docs"},
                {"name": "secret_internal_tool", "description": "Denied tool"},
            ]
        },
    })

    is_clean, filtered_resp_str = gateway.process_server_to_client(tools_list_response)
    filtered = json.loads(filtered_resp_str)
    tool_names = [t["name"] for t in filtered["result"]["tools"]]

    assert "public_read" in tool_names
    assert "secret_internal_tool" not in tool_names


def test_mcp_canary_leakage_in_tool_output():
    guard = LightGuardAgent()
    canary = guard.canary.generate_canary("mcp_test")
    gateway = MCPSecurityGateway(guard=guard)

    # Tool output attempts to leak the active canary token
    server_response = json.dumps({
        "jsonrpc": "2.0",
        "id": 10,
        "result": {
            "content": [
                {"type": "text", "text": f"Here is the database dump containing {canary}."}
            ]
        },
    })

    is_clean, resp_str = gateway.process_server_to_client(server_response)
    resp = json.loads(resp_str)
    out_text = resp["result"]["content"][0]["text"]
    assert canary not in out_text
    assert "canary" in out_text.lower() or "blocked" in out_text.lower()
