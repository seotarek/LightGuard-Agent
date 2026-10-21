import functools
import inspect
from typing import Any, Callable, Iterator, Optional, Union

from lightguard.core import LightGuardAgent
from lightguard.decorators import SecurityViolationError


class LightGuardStreamWrapper:
    """Wraps an LLM completion stream to inspect chunk streams for canary leaks & streaming tool calls."""

    def __init__(
        self,
        stream: Iterator[Any],
        guard: LightGuardAgent,
        block_on_violation: bool = True,
        is_untrusted: bool = False,
    ):
        self._stream = stream
        self._guard = guard
        self._block = block_on_violation
        self._is_untrusted = is_untrusted
        self._accumulated_content: list[str] = []
        self._tool_calls_accumulator: dict[int, dict[str, str]] = {}

    def __iter__(self) -> Iterator[Any]:
        return self

    def __next__(self) -> Any:
        chunk = next(self._stream)
        text_piece = ""
        try:
            # 1. Standard OpenAI/Groq streaming chunk format
            if hasattr(chunk, "choices") and chunk.choices:
                delta = chunk.choices[0].delta
                text_piece = getattr(delta, "content", "") or ""
                tcs = getattr(delta, "tool_calls", None)
                if tcs:
                    self._process_tool_call_deltas(tcs)
            elif isinstance(chunk, dict) and "choices" in chunk:
                delta = chunk["choices"][0].get("delta", {})
                text_piece = delta.get("content", "")
                tcs = delta.get("tool_calls")
                if tcs:
                    self._process_tool_call_deltas(tcs)
            # 2. Anthropic streaming event format
            elif hasattr(chunk, "type"):
                if getattr(chunk, "type", "") == "content_block_delta":
                    delta = getattr(chunk, "delta", None)
                    if delta:
                        text_piece = getattr(delta, "text", "") or ""
        except SecurityViolationError:
            raise
        except Exception:
            pass

        if text_piece:
            self._accumulated_content.append(text_piece)
            full_text = "".join(self._accumulated_content)
            is_leaked, token = self._guard.canary.check_leakage(full_text)
            if is_leaked and self._block:
                raise SecurityViolationError(
                    f"LightGuard Security Block: Stream intercepted due to secret canary token leakage ({token})."
                )

        return chunk

    def _process_tool_call_deltas(self, tool_call_deltas: list[Any]) -> None:
        for tc in tool_call_deltas:
            idx = getattr(tc, "index", 0) if hasattr(tc, "index") else tc.get("index", 0)
            if idx not in self._tool_calls_accumulator:
                self._tool_calls_accumulator[idx] = {"name": "", "arguments": ""}

            fn = getattr(tc, "function", None) if hasattr(tc, "function") else tc.get("function")
            if fn:
                name_chunk = getattr(fn, "name", "") if hasattr(fn, "name") else fn.get("name", "")
                args_chunk = getattr(fn, "arguments", "") if hasattr(fn, "arguments") else fn.get("arguments", "")
                if name_chunk:
                    self._tool_calls_accumulator[idx]["name"] += name_chunk
                if args_chunk:
                    self._tool_calls_accumulator[idx]["arguments"] += args_chunk

            fn_name = self._tool_calls_accumulator[idx]["name"]
            if fn_name:
                act_res = self._guard.verify_action(
                    fn_name,
                    {"args": self._tool_calls_accumulator[idx]["arguments"]},
                    is_untrusted=self._is_untrusted,
                )
                if not act_res["allowed"] and self._block:
                    raise SecurityViolationError(
                        f"LightGuard Action Firewall Block in stream: {act_res['reason']}"
                    )


class LightGuardChatCompletionsProxy:
    """Proxies client.chat.completions to transparently intercept .create() calls."""

    def __init__(self, real_completions: Any, guard: LightGuardAgent, block_on_violation: bool = True):
        self._real = real_completions
        self._guard = guard
        self._block = block_on_violation

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def create(self, *args: Any, **kwargs: Any) -> Any:
        session_untrusted = False
        messages = kwargs.get("messages", [])
        if messages and isinstance(messages, list):
            for i, msg in enumerate(messages):
                if isinstance(msg, dict):
                    content = msg.get("content")
                    if isinstance(content, str):
                        obs_res = self._guard.process_observation(content)
                        if obs_res["is_untrusted"]:
                            session_untrusted = True
                            if self._block:
                                raise SecurityViolationError(
                                    f"LightGuard Security Violation: Untrusted prompt injection detected in message #{i}: "
                                    f"{obs_res.get('reason', 'Adversarial pattern identified')}."
                                )
                        msg["content"] = obs_res["sanitized_observation"]
                    elif isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                raw_text = block.get("text", "")
                                obs_res = self._guard.process_observation(raw_text)
                                if obs_res["is_untrusted"]:
                                    session_untrusted = True
                                    if self._block:
                                        raise SecurityViolationError(
                                            f"LightGuard Security Violation in structured message #{i}: "
                                            f"{obs_res.get('reason', 'Adversarial pattern identified')}."
                                        )
                                block["text"] = obs_res["sanitized_observation"]

        result = self._real.create(*args, **kwargs)

        if kwargs.get("stream", False):
            return LightGuardStreamWrapper(result, self._guard, self._block, is_untrusted=session_untrusted)

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


class LightGuardMessagesProxy:
    """Proxies Anthropic client.messages to transparently intercept .create() calls."""

    def __init__(self, real_messages: Any, guard: LightGuardAgent, block_on_violation: bool = True):
        self._real = real_messages
        self._guard = guard
        self._block = block_on_violation

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def create(self, *args: Any, **kwargs: Any) -> Any:
        system_prompt = kwargs.get("system")
        if isinstance(system_prompt, str):
            obs_res = self._guard.process_observation(system_prompt)
            if obs_res["is_untrusted"] and self._block:
                raise SecurityViolationError(
                    f"LightGuard Security Violation in system prompt: {obs_res.get('reason', 'Adversarial pattern identified')}."
                )
            kwargs["system"] = obs_res["sanitized_observation"]

        messages = kwargs.get("messages", [])
        if messages and isinstance(messages, list):
            for i, msg in enumerate(messages):
                if isinstance(msg, dict):
                    content = msg.get("content")
                    if isinstance(content, str):
                        obs_res = self._guard.process_observation(content)
                        if obs_res["is_untrusted"] and self._block:
                            raise SecurityViolationError(
                                f"LightGuard Security Violation: Untrusted prompt injection in Anthropic message #{i}: "
                                f"{obs_res.get('reason', 'Adversarial pattern identified')}."
                            )
                        msg["content"] = obs_res["sanitized_observation"]
                    elif isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("type") == "text":
                                raw_text = block.get("text", "")
                                obs_res = self._guard.process_observation(raw_text)
                                if obs_res["is_untrusted"] and self._block:
                                    raise SecurityViolationError(
                                        f"LightGuard Security Violation in structured Anthropic message #{i}: "
                                        f"{obs_res.get('reason', 'Adversarial pattern identified')}."
                                    )
                                block["text"] = obs_res["sanitized_observation"]

        result = self._real.create(*args, **kwargs)

        if kwargs.get("stream", False):
            return LightGuardStreamWrapper(result, self._guard, self._block)

        try:
            content_blocks = getattr(result, "content", None)
            if content_blocks and isinstance(content_blocks, list):
                for block in content_blocks:
                    b_type = getattr(block, "type", "") if hasattr(block, "type") else block.get("type", "")
                    if b_type == "text":
                        text_val = getattr(block, "text", "") if hasattr(block, "text") else block.get("text", "")
                        if text_val:
                            is_leaked, token = self._guard.canary.check_leakage(text_val)
                            if is_leaked and self._block:
                                raise SecurityViolationError(
                                    f"LightGuard Security Block: Output leaked confidential canary token ({token})."
                                )
                    elif b_type == "tool_use":
                        fn_name = getattr(block, "name", "") if hasattr(block, "name") else block.get("name", "")
                        fn_args = getattr(block, "input", {}) if hasattr(block, "input") else block.get("input", {})
                        act_res = self._guard.verify_action(
                            fn_name,
                            fn_args if isinstance(fn_args, dict) else {"input": fn_args},
                            is_untrusted=False,
                        )
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
    Transparent proxy for LLM SDK clients (OpenAI, Anthropic, Groq, Ollama).
    Intercepts calls to client.chat.completions.create and client.messages.create.
    """

    def __init__(self, client: Any, guard: Optional[LightGuardAgent] = None, block_on_violation: bool = True):
        self._client = client
        self._guard = guard if guard is not None else LightGuardAgent()
        self._block = block_on_violation

        if hasattr(client, "chat"):
            self.chat = LightGuardChatProxy(client.chat, self._guard, self._block)
        if hasattr(client, "messages"):
            self.messages = LightGuardMessagesProxy(client.messages, self._guard, self._block)

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

    # If wrapping a client object with .chat, .completions, or .messages
    if hasattr(target, "chat") or hasattr(target, "completions") or hasattr(target, "messages"):
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
