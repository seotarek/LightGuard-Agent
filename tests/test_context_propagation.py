import asyncio
from concurrent.futures import ThreadPoolExecutor

from lightguard.audit import SecurityReasonCode
from lightguard.core import LightGuardAgent
from lightguard.mcp_gateway import MCPSecurityGateway
from lightguard.policy import (
    AuthorizationContext,
    SecurityPolicyConfig,
    ToolMetadata,
    ToolPolicyRegistry,
    authorization_context,
    get_current_authorization_context,
)


def test_authorization_context_manager_scoping():
    assert get_current_authorization_context() is None

    ctx = AuthorizationContext(caller_id="usr_42", caller_role="auditor")
    with authorization_context(ctx):
        current = get_current_authorization_context()
        assert current is not None
        assert current.caller_id == "usr_42"
        assert current.caller_role == "auditor"

    assert get_current_authorization_context() is None


def test_concurrent_async_context_isolation():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="nuclear_purge",
            required_role="admin",
        )
    )

    policy = SecurityPolicyConfig(tool_registry=registry)
    guard = LightGuardAgent(policy=policy)

    async def run_worker(role: str, user_id: str):
        ctx = AuthorizationContext(caller_id=user_id, caller_role=role)
        with authorization_context(ctx):
            await asyncio.sleep(0.01)  # Simulate async I/O interleaved context switching
            return guard.verify_action("nuclear_purge", {}, is_untrusted=False)

    async def main():
        tasks = []
        for i in range(10):
            role = "admin" if i % 2 == 0 else "user"
            tasks.append(run_worker(role, f"worker-{i}"))
        return await asyncio.gather(*tasks)

    results = asyncio.run(main())
    assert len(results) == 10

    for i, res in enumerate(results):
        if i % 2 == 0:  # Admin
            assert res["allowed"] is True, f"Admin worker-{i} was unexpectedly blocked"
        else:  # User
            assert res["allowed"] is False, f"User worker-{i} was unexpectedly allowed"
            assert res["reason_code"] == SecurityReasonCode.LG_TOOL_ROLE_UNAUTHORIZED.value


def test_thread_pool_context_isolation():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="format_disk",
            required_role="operator",
        )
    )

    policy = SecurityPolicyConfig(tool_registry=registry)
    guard = LightGuardAgent(policy=policy)

    def thread_worker(role: str):
        ctx = AuthorizationContext(caller_role=role)
        with authorization_context(ctx):
            return guard.verify_action("format_disk", {}, is_untrusted=False)

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = [
            pool.submit(thread_worker, "operator" if i % 2 == 0 else "guest")
            for i in range(10)
        ]
        results = [f.result() for f in futures]

    for i, res in enumerate(results):
        if i % 2 == 0:
            assert res["allowed"] is True
        else:
            assert res["allowed"] is False
            assert res["reason_code"] == SecurityReasonCode.LG_TOOL_ROLE_UNAUTHORIZED.value


def test_mcp_gateway_with_explicit_context():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="privileged_mcp_cmd",
            required_role="admin",
        )
    )

    policy = SecurityPolicyConfig(tool_registry=registry)
    guard = LightGuardAgent(policy=policy)
    gateway = MCPSecurityGateway(guard=guard)

    call_payload = {
        "jsonrpc": "2.0",
        "id": "1",
        "method": "tools/call",
        "params": {"name": "privileged_mcp_cmd", "arguments": {}},
    }

    # 1. Unprivileged user context -> Blocked
    user_ctx = AuthorizationContext(caller_role="user")
    allowed, resp_str = gateway.process_client_to_server(
        __import__("json").dumps(call_payload),
        context=user_ctx,
    )
    assert allowed is False
    assert "requires role 'admin'" in resp_str

    # 2. Privileged admin context -> Allowed
    admin_ctx = AuthorizationContext(caller_role="admin")
    allowed, resp_str = gateway.process_client_to_server(
        __import__("json").dumps(call_payload),
        context=admin_ctx,
    )
    assert allowed is True
