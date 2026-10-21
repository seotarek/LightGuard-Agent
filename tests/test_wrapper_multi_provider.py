"""Tests for Multi-Provider LLM Integration & Streamed Tool Call Parsing."""

import json

import pytest

from lightguard.core import LightGuardAgent
from lightguard.policy import SecurityPolicyConfig
from lightguard.wrapper import (
    LightGuardChatCompletionsProxy,
    LightGuardStreamWrapper,
    SecurityViolationError,
)


class DummyToolCallFunction:
    def __init__(self, name: str, arguments: str):
        self.name = name
        self.arguments = arguments


class DummyToolCall:
    def __init__(self, name: str, arguments: str, index: int = 0):
        self.index = index
        self.function = DummyToolCallFunction(name, arguments)


class DummyMessage:
    def __init__(self, content: str = "", tool_calls: list = None):
        self.content = content
        self.tool_calls = tool_calls or []


class DummyChoice:
    def __init__(self, message: DummyMessage):
        self.message = message


class DummyCompletion:
    def __init__(self, choices: list):
        self.choices = choices


class DummyStreamDelta:
    def __init__(self, content: str = None, tool_calls: list = None):
        self.content = content
        self.tool_calls = tool_calls or []


class DummyStreamChoice:
    def __init__(self, delta: DummyStreamDelta, finish_reason: str = None):
        self.delta = delta
        self.finish_reason = finish_reason


class DummyStreamChunk:
    def __init__(self, choices: list):
        self.choices = choices


def test_sync_completion_unmarshals_json_arguments_for_structured_guard():
    agent = LightGuardAgent(policy=SecurityPolicyConfig.strict())

    # Raw arguments is a JSON string containing dangerous command
    dangerous_json = json.dumps({"command": "rm -rf /; cat /etc/passwd"})
    tool_call = DummyToolCall("run_cmd", dangerous_json)
    completion = DummyCompletion([DummyChoice(DummyMessage(tool_calls=[tool_call]))])

    class MockClientCompletions:
        def create(self, *args, **kwargs):
            return completion

    proxy = LightGuardChatCompletionsProxy(MockClientCompletions(), guard=agent, block_on_violation=True)

    with pytest.raises(SecurityViolationError) as exc_info:
        proxy.create(messages=[{"role": "user", "content": "run this"}])

    assert "Structured Output" in str(exc_info.value) or "Firewall" in str(exc_info.value)


def test_sync_completion_detects_ssrf_inside_json_arguments():
    agent = LightGuardAgent(policy=SecurityPolicyConfig.balanced())

    ssrf_json = json.dumps({"url": "http://169.254.169.254/latest/meta-data/"})
    tool_call = DummyToolCall("fetch", ssrf_json)
    completion = DummyCompletion([DummyChoice(DummyMessage(tool_calls=[tool_call]))])

    class MockClientCompletions:
        def create(self, *args, **kwargs):
            return completion

    proxy = LightGuardChatCompletionsProxy(MockClientCompletions(), guard=agent, block_on_violation=True)

    with pytest.raises(SecurityViolationError) as exc_info:
        proxy.create(messages=[{"role": "user", "content": "fetch metadata"}])

    assert "SSRF" in str(exc_info.value) or "Blocked" in str(exc_info.value)


def test_sync_completion_inspects_multiple_parallel_tool_calls():
    agent = LightGuardAgent(policy=SecurityPolicyConfig.balanced())

    # Tool call 1 is benign, tool call 2 has path traversal
    tc1 = DummyToolCall("read_file", json.dumps({"path": "normal.txt"}), index=0)
    tc2 = DummyToolCall("read_file", json.dumps({"path": "../../../etc/shadow"}), index=1)

    completion = DummyCompletion([DummyChoice(DummyMessage(tool_calls=[tc1, tc2]))])

    class MockClientCompletions:
        def create(self, *args, **kwargs):
            return completion

    proxy = LightGuardChatCompletionsProxy(MockClientCompletions(), guard=agent, block_on_violation=True)

    with pytest.raises(SecurityViolationError) as exc_info:
        proxy.create(messages=[{"role": "user", "content": "read files"}])

    assert "Path traversal" in str(exc_info.value) or "Blocked" in str(exc_info.value)


def test_streamed_tool_call_accumulates_and_unmarshals_json():
    agent = LightGuardAgent(policy=SecurityPolicyConfig.strict())

    # Stream chunks arriving in pieces
    chunk1 = DummyStreamChunk([
        DummyStreamChoice(
            DummyStreamDelta(tool_calls=[DummyToolCall("exec_tool", '{"cmd": "c', index=0)]),
            finish_reason=None,
        )
    ])
    chunk2 = DummyStreamChunk([
        DummyStreamChoice(
            DummyStreamDelta(tool_calls=[DummyToolCall("exec_tool", 'at /etc/passwd"}', index=0)]),
            finish_reason="tool_calls",
        )
    ])

    chunks = [chunk1, chunk2]
    stream_wrapper = LightGuardStreamWrapper(iter(chunks), guard=agent, block_on_violation=True)

    # Iterating through the stream must trigger the accumulated inspection at finish_reason
    with pytest.raises(SecurityViolationError) as exc_info:
        list(stream_wrapper)

    assert "Structured Output" in str(exc_info.value) or "Firewall" in str(exc_info.value)
