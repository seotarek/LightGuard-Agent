import json

from lightguard.mcp_gateway import MCPSecurityGateway as MCPGateway


def test_mcp_gateway_rejects_invalid_jsonrpc_version():
    gateway = MCPGateway()
    bad_req = json.dumps({
        "jsonrpc": "1.0",
        "method": "tools/call",
        "id": 1,
        "params": {"name": "fetch", "arguments": {}}
    })
    allowed, resp = gateway.process_client_to_server(bad_req)
    assert allowed is False
    data = json.loads(resp)
    assert data["error"]["code"] == -32600
    assert "jsonrpc" in data["error"]["message"].lower()


def test_mcp_gateway_rejects_missing_method():
    gateway = MCPGateway()
    bad_req = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "params": {"name": "fetch", "arguments": {}}
    })
    allowed, resp = gateway.process_client_to_server(bad_req)
    assert allowed is False
    data = json.loads(resp)
    assert data["error"]["code"] == -32600
    assert "method" in data["error"]["message"].lower()


def test_mcp_gateway_rejects_non_dict_params():
    gateway = MCPGateway()
    bad_req = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": "not-a-dict"
    })
    allowed, resp = gateway.process_client_to_server(bad_req)
    assert allowed is False
    data = json.loads(resp)
    assert data["error"]["code"] == -32602
    assert "params" in data["error"]["message"].lower()


def test_mcp_gateway_rejects_missing_or_empty_tool_name():
    gateway = MCPGateway()
    # Missing name
    bad_req1 = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"arguments": {}}
    })
    allowed1, resp1 = gateway.process_client_to_server(bad_req1)
    assert allowed1 is False
    data1 = json.loads(resp1)
    assert data1["error"]["code"] == -32602
    assert "name" in data1["error"]["message"].lower()

    # Empty string name
    bad_req2 = json.dumps({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "   ", "arguments": {}}
    })
    allowed2, resp2 = gateway.process_client_to_server(bad_req2)
    assert allowed2 is False
    data2 = json.loads(resp2)
    assert data2["error"]["code"] == -32602


def test_mcp_gateway_rejects_non_dict_arguments():
    gateway = MCPGateway()
    bad_req = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "run_test", "arguments": ["not", "a", "dict"]}
    })
    allowed, resp = gateway.process_client_to_server(bad_req)
    assert allowed is False
    data = json.loads(resp)
    assert data["error"]["code"] == -32602
    assert "arguments" in data["error"]["message"].lower()
