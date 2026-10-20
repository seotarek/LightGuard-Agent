import functools
import inspect
from typing import Any, Callable, Iterator, Optional, Union

from lightguard.core import LightGuardAgent
from lightguard.decorators import SecurityViolationError


class LightGuardStreamWrapper:
    """Wraps an LLM completion stream to inspect chunk streams for canary leaks & safety."""

    def __init__(self, stream: Iterator[Any], guard: LightGuardAgent, block_on_violation: bool = True):
        self._stream = stream
        self._guard = guard
        self._block = block_on_violation
        self._accumulated_content = []

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        chunk = next(self._stream)
        # Extract delta content if standard OpenAI/Anthropic chunk format
        text_piece = ""
        try:
            if hasattr(chunk, "choices") and chunk.choices:
                delta = chunk.choices[0].delta
                text_piece = getattr(delta, "content", "") or ""
            elif isinstance(chunk, dict) and "choices" in chunk:
                text_piece = chunk["choices"][0].get("delta", {}).get("content", "")
        except Exception:
            pass

        if text_piece:
            self._accumulated_content.append(text_piece)
            full_text = "".join(self._accumulated_content)
            # Check for canary leakage in live streaming
            is_leaked, token = self._guard.canary.check_leakage(full_text)
            if is_leaked and self._block:
                raise SecurityViolationError(
                    f"LightGuard Security Block: Stream intercepted due to secret canary token leakage ({token})."
                )

        return chunk


class LightGuardChatCompletionsProxy:
    """Proxies client.chat.completions to transparently intercept .create() calls."""

    def __init__(self, real_completions: Any, guard: LightGuardAgent, block_on_violation: bool = True):
        self._real = real_completions
        self._guard = guard
        self._block = block_on_violation

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def create(self, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", [])
        if messages and isinstance(messages, list):
            for i, msg in enumerate(messages):
                if isinstance(msg, dict) and "content" in msg and isinstance(msg["content"], str):
                    raw_content = msg["content"]
                    obs_res = self._guard.process_observation(raw_content)
                    if obs_res["is_untrusted"] and self._block:
                        raise SecurityViolationError(
                            f"LightGuard Security Violation: Untrusted prompt injection detected in message #{i}: "
                            f"{obs_res.get('reason', 'Adversarial pattern identified')}."
                        )
                    # Replace with sanitized observation
                    msg["content"] = obs_res["sanitized_observation"]

        result = self._real.create(*args, **kwargs)

        # If it's a stream, wrap it
        if kwargs.get("stream", False):
            return LightGuardStreamWrapper(result, self._guard, self._block)

        # Inspect non-streaming completion output for canary leaks and tool call risks
        try:
            if hasattr(result, "choices") and result.choices:
                msg = result.choices[0].message
                content = getattr(msg, "content", "") or ""
                if content:
                    is_leaked, token = self._guard.canary.check_leakage(content)
                    if is_leaked and self._block:
                        raise SecurityViolationError(
                            f"LightGuard Security Block: Output leaked confidential canary token ({token})."
                        )
                # Inspect tool calls if proposed by LLM
                tool_calls = getattr(msg, "tool_calls", None)
                if tool_calls:
                    for tc in tool_calls:
                        func = getattr(tc, "function", None)
                        if func:
                            fn_name = getattr(func, "name", "")
                            fn_args = getattr(func, "arguments", "{}")
                            act_res = self._guard.verify_action(fn_name, {"args": fn_args}, is_untrusted=False)
                            if not act_res["allowed"] and self._block:
                                raise SecurityViolationError(
                                    f"LightGuard Action Firewall Block: {act_res['reason']}"
                                )
        except SecurityViolationError:
            raise
        except Exception:
            pass

        return result


class LightGuardChatProxy:
    """Proxies client.chat to intercept client.chat.completions."""

    def __init__(self, real_chat: Any, guard: LightGuardAgent, block_on_violation: bool = True):
        self._real = real_chat
        self._guard = guard
        self._block = block_on_violation
        self.completions = LightGuardChatCompletionsProxy(
            getattr(real_chat, "completions", real_chat), guard, block_on_violation
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)


class LightGuardClientWrapper:
    """
    Transparent proxy for LLM SDK clients (e.g. OpenAI, Anthropic, Groq, Ollama).
    Intercepts calls to client.chat.completions.create with sub-millisecond security.
    """

    def __init__(self, client: Any, guard: Optional[LightGuardAgent] = None, block_on_violation: bool = True):
        self._client = client
        self._guard = guard if guard is not None else LightGuardAgent()
        self._block = block_on_violation

        if hasattr(client, "chat"):
            self.chat = LightGuardChatProxy(client.chat, self._guard, self._block)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)


def wrap(
    target: Union[Any, Callable[..., Any]],
    guard: Optional[LightGuardAgent] = None,
    block_on_violation: bool = True,
) -> Any:
    """
    Universal drop-in wrapper for LLM clients, agents, or callable pipelines.

    Usage:
        client = lightguard.wrap(OpenAI())
        response = client.chat.completions.create(model="gpt-4o", messages=[...])
    """
    active_guard = guard if guard is not None else LightGuardAgent()

    # If wrapping a client object with .chat or .chat.completions
    if hasattr(target, "chat") or hasattr(target, "completions"):
        return LightGuardClientWrapper(target, guard=active_guard, block_on_violation=block_on_violation)

    # If wrapping a callable function/agent
    if callable(target) and not inspect.isclass(target):
        @functools.wraps(target)
        def wrapped_fn(*args: Any, **kwargs: Any) -> Any:
            for arg in args:
                if isinstance(arg, str):
                    obs = active_guard.process_observation(arg)
                    if obs["is_untrusted"] and block_on_violation:
                        raise SecurityViolationError(f"LightGuard Security Violation: {obs.get('reason', 'Untrusted input')}")
            for k, v in kwargs.items():
                if isinstance(v, str):
                    obs = active_guard.process_observation(v)
                    if obs["is_untrusted"] and block_on_violation:
                        raise SecurityViolationError(f"LightGuard Security Violation in parameter '{k}': {obs.get('reason', 'Untrusted input')}")
            return target(*args, **kwargs)

        return wrapped_fn

    # Fallback to client proxy
    return LightGuardClientWrapper(target, guard=active_guard, block_on_violation=block_on_violation)
