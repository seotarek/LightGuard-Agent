import pytest

from lightguard.core import LightGuardAgent
from lightguard.decorators import SecurityViolationError
from lightguard.policy import (
    AuthorizationMode,
    SecurityPolicyConfig,
    ToolMetadata,
    ToolPolicyRegistry,
)
from lightguard.wrapper import wrap_client


class MockFunction:
    def __init__(self, name="", arguments="{}"):
        self.name = name
        self.arguments = arguments


class MockToolCall:
    def __init__(self, name="", arguments="{}"):
        self.function = MockFunction(name=name, arguments=arguments)


class MockMessage:
    def __init__(self, content="", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []


class MockChoice:
    def __init__(self, message):
        self.message = message


class MockCompletionResponse:
    def __init__(self, choices):
        self.choices = choices


class MockCompletions:
    def __init__(self, response):
        self._response = response

    def create(self, *args, **kwargs):
        return self._response


class MockChat:
    def __init__(self, response):
        self.completions = MockCompletions(response)


class MockOpenAIClient:
    def __init__(self, response):
        self.chat = MockChat(response)


def test_multi_choice_catches_canary_leak_in_second_choice():
    canary_token = "LG_CANARY_SECRET_TOKEN_CHOICE_2"
    guard = LightGuardAgent()
    guard.canary._active_canaries[canary_token] = 9999999999.0

    # Choice 0 is completely benign, Choice 1 leaks the canary
    resp = MockCompletionResponse(
        choices=[
            MockChoice(MockMessage(content="Benign first response")),
            MockChoice(MockMessage(content=f"Leaked secret: {canary_token}")),
        ]
    )
    client = MockOpenAIClient(resp)
    wrapped = wrap_client(client, guard=guard)

    with pytest.raises(SecurityViolationError, match="canary token"):
        wrapped.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Tell me a joke"}],
        )


def test_multi_choice_catches_prohibited_tool_in_second_choice():
    registry = ToolPolicyRegistry()
    registry.register_tool(ToolMetadata(name="calc_add"))
    policy = SecurityPolicyConfig(
        tool_registry=registry,
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    # Choice 0 has allowed tool calc_add, Choice 1 has prohibited tool exec_bash
    resp = MockCompletionResponse(
        choices=[
            MockChoice(
                MockMessage(
                    content="Computing...",
                    tool_calls=[MockToolCall(name="calc_add", arguments='{"a": 1, "b": 2}')],
                )
            ),
            MockChoice(
                MockMessage(
                    content="Executing system command...",
                    tool_calls=[MockToolCall(name="exec_bash", arguments='{"cmd": "whoami"}')],
                )
            ),
        ]
    )
    client = MockOpenAIClient(resp)
    wrapped = wrap_client(client, guard=guard)

    with pytest.raises(SecurityViolationError, match="exec_bash"):
        wrapped.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Help with math and system"}],
        )


def test_multi_choice_catches_argument_injection_in_later_choice():
    registry = ToolPolicyRegistry()
    registry.register_tool(ToolMetadata(name="safe_reader"))
    registry.register_tool(ToolMetadata(name="backup_reader"))
    policy = SecurityPolicyConfig(
        tool_registry=registry,
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    # Choice 0 has clean read, Choice 1 has path traversal attack in tool call arguments
    resp = MockCompletionResponse(
        choices=[
            MockChoice(
                MockMessage(
                    tool_calls=[MockToolCall(name="safe_reader", arguments='{"path": "data.txt"}')]
                )
            ),
            MockChoice(
                MockMessage(
                    tool_calls=[MockToolCall(name="backup_reader", arguments='{"path": "../../../etc/shadow"}')]
                )
            ),
        ]
    )
    client = MockOpenAIClient(resp)
    wrapped = wrap_client(client, guard=guard)

    with pytest.raises(SecurityViolationError, match=r"(?i)path traversal|outside|violated"):
        wrapped.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Read files"}],
        )


def test_multi_choice_all_benign_allowed():
    registry = ToolPolicyRegistry()
    registry.register_tool(ToolMetadata(name="calc_add"))
    registry.register_tool(ToolMetadata(name="calc_sub"))
    policy = SecurityPolicyConfig(
        tool_registry=registry,
        authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
    )
    guard = LightGuardAgent(policy=policy)

    resp = MockCompletionResponse(
        choices=[
            MockChoice(
                MockMessage(
                    content="Choice 1",
                    tool_calls=[MockToolCall(name="calc_add", arguments='{"a": 1, "b": 2}')],
                )
            ),
            MockChoice(
                MockMessage(
                    content="Choice 2",
                    tool_calls=[MockToolCall(name="calc_sub", arguments='{"a": 5, "b": 3}')],
                )
            ),
        ]
    )
    client = MockOpenAIClient(resp)
    wrapped = wrap_client(client, guard=guard)

    res = wrapped.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Calculate numbers"}],
    )
    assert res == resp
