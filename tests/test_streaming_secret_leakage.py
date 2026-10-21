import asyncio

import pytest

from lightguard.core import LightGuardAgent
from lightguard.policy import SecurityPolicyConfig, ToolMetadata, ToolPolicyRegistry
from lightguard.wrapper import (
    LightGuardAsyncStreamWrapper,
    LightGuardStreamWrapper,
    SecurityViolationError,
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


def test_async_stream_catches_split_canary_across_chunks():
    guard = LightGuardAgent()
    canary = guard.canary.issue_token("test-split")
    assert len(canary) > 10

    part1 = canary[:8]
    part2 = canary[8:]

    chunks = [
        MockStreamChunk([MockChunkChoice(MockChunkDelta(content="Your secret is: "))]),
        MockStreamChunk([MockChunkChoice(MockChunkDelta(content=part1))]),
        MockStreamChunk([MockChunkChoice(MockChunkDelta(content=part2))]),
        MockStreamChunk([MockChunkChoice(MockChunkDelta(content=" [DONE]"))]),
    ]

    stream_wrapper = LightGuardAsyncStreamWrapper(
        MockAsyncStream(chunks),
        guard=guard,
        block_on_violation=True,
    )

    async def run():
        accumulated = []
        async for chunk in stream_wrapper:
            accumulated.append(chunk)

    with pytest.raises(SecurityViolationError) as exc_info:
        asyncio.run(run())

    err_msg = str(exc_info.value)
    assert "Stream intercepted" in err_msg or "Output leaked" in err_msg
    # Ensure the raw canary token is NEVER leaked inside the exception message
    assert canary not in err_msg


def test_sync_stream_exception_does_not_leak_secret_token():
    guard = LightGuardAgent()
    canary = guard.canary.issue_token("test-sync-leak")

    chunks = [
        {"type": "message_start"},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": f"Secret: {canary}"}},
    ]

    wrapper = LightGuardStreamWrapper(iter(chunks), guard=guard, block_on_violation=True)

    with pytest.raises(SecurityViolationError) as exc_info:
        for _ in wrapper:
            pass

    err_msg = str(exc_info.value)
    assert canary not in err_msg
    assert "confidential canary token" in err_msg.lower() or "canary token leakage" in err_msg.lower()


def test_stream_inspects_multiple_choices_for_canary():
    guard = LightGuardAgent()
    canary = guard.canary.issue_token("test-multi-choice")

    # choice 0 is benign, choice 1 leaks the canary
    chunk = MockStreamChunk([
        MockChunkChoice(MockChunkDelta(content="Benign text in choice 0")),
        MockChunkChoice(MockChunkDelta(content=f"Secret in choice 1: {canary}")),
    ])

    stream_wrapper = LightGuardAsyncStreamWrapper(
        MockAsyncStream([chunk]),
        guard=guard,
        block_on_violation=True,
    )

    async def run():
        async for _ in stream_wrapper:
            pass

    with pytest.raises(SecurityViolationError) as exc_info:
        asyncio.run(run())

    err_msg = str(exc_info.value)
    assert canary not in err_msg


def test_anthropic_stream_block_start_does_not_prematurely_fail_schema():
    registry = ToolPolicyRegistry()
    registry.register_tool(
        ToolMetadata(
            name="execute_query",
            parameters_schema={
                "type": "object",
                "required": ["sql"],
                "properties": {"sql": {"type": "string"}},
            },
        )
    )

    policy = SecurityPolicyConfig(tool_registry=registry)
    guard = LightGuardAgent(policy=policy)

    chunks = [
        {
            "type": "content_block_start",
            "index": 0,
            "content_block": {"type": "tool_use", "id": "tu_1", "name": "execute_query"},
        },
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": '{"sql": "SELECT 1"}'},
        },
        {
            "type": "content_block_stop",
            "index": 0,
        },
    ]

    wrapper = LightGuardStreamWrapper(iter(chunks), guard=guard, block_on_violation=True)

    # Should stream cleanly without schema failure at block_start
    consumed = list(wrapper)
    assert len(consumed) == 3
