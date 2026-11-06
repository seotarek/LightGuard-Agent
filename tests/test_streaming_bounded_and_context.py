import asyncio

import pytest

from lightguard.core import LightGuardAgent
from lightguard.decorators import SecurityViolationError
from lightguard.policy import (
    AuthorizationContext,
    AuthorizationMode,
    SecurityPolicyConfig,
    ToolMetadata,
    ToolPolicyRegistry,
    authorization_context,
)
from lightguard.wrapper import (
    LightGuardAsyncStreamWrapper,
    LightGuardStreamWrapper,
)


class MockChunkDelta:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []


class MockChunkChoice:
    def __init__(self, delta, finish_reason=None):
        self.delta = delta
        self.finish_reason = finish_reason


class MockStreamChunk:
    def __init__(self, choices):
        self.choices = choices


class MockAsyncStream:
    def __init__(self, chunks):
        self._chunks = chunks

    def __aiter__(self):
        self._iter = iter(self._chunks)
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration:
            raise StopAsyncIteration


def test_sliding_window_catches_canary_split_across_small_chunks():
    guard = LightGuardAgent()
    canary = guard.canary.issue_token("sliding-split-token")

    # Split token into 4 parts
    p1 = canary[:6]
    p2 = canary[6:14]
    p3 = canary[14:22]
    p4 = canary[22:]

    chunks = [
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "Beginning of text: "}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": p1}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": p2}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": p3}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": p4}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": " tail end."}},
    ]

    wrapper = LightGuardStreamWrapper(iter(chunks), guard=guard, block_on_violation=True)
    with pytest.raises(SecurityViolationError, match="confidential canary token"):
        for _ in wrapper:
            pass


def test_streaming_enforces_max_stream_bytes():
    guard = LightGuardAgent()

    # Each chunk is 100 bytes of repetitive text
    chunks = [
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": "A" * 100}}
        for _ in range(10)
    ]

    # Set limit to 350 bytes
    wrapper = LightGuardStreamWrapper(
        iter(chunks),
        guard=guard,
        block_on_violation=True,
        max_stream_bytes=350,
    )

    with pytest.raises(SecurityViolationError, match="exceeded maximum allowed"):
        for _ in wrapper:
            pass


def test_async_streaming_enforces_max_stream_bytes():
    guard = LightGuardAgent()
    chunks = [
        MockStreamChunk([MockChunkChoice(MockChunkDelta(content="B" * 100))])
        for _ in range(10)
    ]

    wrapper = LightGuardAsyncStreamWrapper(
        MockAsyncStream(chunks),
        guard=guard,
        block_on_violation=True,
        max_stream_bytes=250,
    )

    async def run():
        async for _ in wrapper:
            pass

    with pytest.raises(SecurityViolationError, match="exceeded maximum allowed"):
        asyncio.run(run())


def test_lazy_stream_preserves_captured_context_outside_manager():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="admin_purge_logs",
            required_role="admin",
        )
    )
    policy = SecurityPolicyConfig(
        tool_registry=registry,
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    admin_ctx = AuthorizationContext(caller_id="usr_admin", caller_role="admin")

    chunks = [
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "tool_use", "id": "tu_1", "name": "admin_purge_logs"},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": '{"target": "all"}'},
        },
        {
            "type": "content_block_stop",
            "index": 0,
        },
    ]

    # 1. Create stream inside admin context
    with authorization_context(admin_ctx):
        wrapper = LightGuardStreamWrapper(
            iter(chunks),
            guard=guard,
            block_on_violation=True,
            context=admin_ctx,
        )

    # 2. Consume stream outside admin context (e.g. under user or default context)
    guest_ctx = AuthorizationContext(caller_id="usr_guest", caller_role="guest")
    with authorization_context(guest_ctx):
        # Because stream captured admin_ctx, it should succeed without RBAC error
        consumed = list(wrapper)
        assert len(consumed) == 3


def test_lazy_stream_unprivileged_context_cannot_escalate_outside():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="admin_purge_logs",
            required_role="admin",
        )
    )
    policy = SecurityPolicyConfig(
        tool_registry=registry,
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    guest_ctx = AuthorizationContext(caller_id="usr_guest", caller_role="guest")

    chunks = [
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "tool_use", "id": "tu_1", "name": "admin_purge_logs"},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": '{"target": "all"}'},
        },
        {
            "type": "content_block_stop",
            "index": 0,
        },
    ]

    # 1. Stream created by guest
    wrapper = LightGuardStreamWrapper(
        iter(chunks),
        guard=guard,
        block_on_violation=True,
        context=guest_ctx,
    )

    # 2. Consumed inside admin context -> MUST STILL BE BLOCKED because creator was guest!
    admin_ctx = AuthorizationContext(caller_id="usr_admin", caller_role="admin")
    with authorization_context(admin_ctx):
        with pytest.raises(SecurityViolationError, match="RBAC Policy Blocked"):
            list(wrapper)
