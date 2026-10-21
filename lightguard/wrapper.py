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
            # 2. Anthropic streaming event format (content_block_start, content_block_delta, content_block_stop)
            elif hasattr(chunk, "type") or (isinstance(chunk, dict) and "type" in chunk):
                chunk_type = getattr(chunk, "type", "") if hasattr(chunk, "type") else chunk.get("type", "")
                if chunk_type == "content_block_start":
                    self._process_anthropic_block_start(chunk)
                elif chunk_type == "content_block_delta":
                    text_piece = self._process_anthropic_block_delta(chunk)
                elif chunk_type == "content_block_stop":
                    self._process_anthropic_block_stop(chunk)
        except SecurityViolationError:
            raise
        except Exception as e:
            if self._block:
                raise SecurityViolationError(
                    f"LightGuard Security Block: Stream verification failed-closed: {e}"
                )

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

    def _process_anthropic_block_start(self, chunk: Any) -> None:
        idx = getattr(chunk, "index", 0) if hasattr(chunk, "index") else chunk.get("index", 0)
        cb = getattr(chunk, "content_block", None) if hasattr(chunk, "content_block") else chunk.get("content_block", {})
        cb_type = getattr(cb, "type", "") if hasattr(cb, "type") else cb.get("type", "")
        if cb_type == "tool_use":
            name = getattr(cb, "name", "") if hasattr(cb, "name") else cb.get("name", "")
            tool_id = getattr(cb, "id", "") if hasattr(cb, "id") else cb.get("id", "")
            self._tool_calls_accumulator[idx] = {"name": name, "arguments": "", "id": tool_id}
            if name:
                act_res = self._guard.verify_action(
                    name, {"id": tool_id}, is_untrusted=self._is_untrusted
                )
                if not act_res["allowed"] and self._block:
                    raise SecurityViolationError(
                        f"LightGuard Action Firewall Block in Anthropic stream: {act_res['reason']}"
                    )

    def _process_anthropic_block_delta(self, chunk: Any) -> str:
        idx = getattr(chunk, "index", 0) if hasattr(chunk, "index") else chunk.get("index", 0)
        delta = getattr(chunk, "delta", None) if hasattr(chunk, "delta") else chunk.get("delta", {})
        d_type = getattr(delta, "type", "") if hasattr(delta, "type") else delta.get("type", "")
        if d_type == "input_json_delta":
            partial_json = (
                getattr(delta, "partial_json", "")
                if hasattr(delta, "partial_json")
                else delta.get("partial_json", "")
            )
            if idx not in self._tool_calls_accumulator:
                self._tool_calls_accumulator[idx] = {"name": "", "arguments": "", "id": ""}
            self._tool_calls_accumulator[idx]["arguments"] += partial_json
            if self._guard.policy.enable_canary_guard and partial_json:
                is_leaked, token = self._guard.canary.check_leakage(partial_json)
                if is_leaked and self._block:
                    raise SecurityViolationError(
                        f"LightGuard Security Block: Stream intercepted due to secret canary token leakage ({token})."
                    )
            return ""
        elif d_type == "text_delta" or hasattr(delta, "text") or (isinstance(delta, dict) and "text" in delta):
            return getattr(delta, "text", "") if hasattr(delta, "text") else delta.get("text", "")
        return ""

    def _process_anthropic_block_stop(self, chunk: Any) -> None:
        idx = getattr(chunk, "index", 0) if hasattr(chunk, "index") else chunk.get("index", 0)
        if idx in self._tool_calls_accumulator:
            tc_data = self._tool_calls_accumulator[idx]
            fn_name = tc_data.get("name", "")
            if fn_name:
                act_res = self._guard.verify_action(
                    fn_name,
                    {"args": tc_data.get("arguments", "")},
                    is_untrusted=self._is_untrusted,
                )
                if not act_res["allowed"] and self._block:
                    raise SecurityViolationError(
                        f"LightGuard Action Firewall Block in Anthropic stream: {act_res['reason']}"
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
                            act_res = self._guard.verify_action(fn_name, {"args": fn_args}, is_untrusted=session_untrusted)
                            if not act_res["allowed"] and self._block:
                                raise SecurityViolationError(
                                    f"LightGuard Action Firewall Block: {act_res['reason']}"
                                )
        except SecurityViolationError:
            raise
        except Exception as e:
            if self._block:
                raise SecurityViolationError(
                    f"LightGuard Security Block: Verification failed-closed on OpenAI completion: {e}"
                )

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
        session_untrusted = False
        system_prompt = kwargs.get("system")
        if isinstance(system_prompt, str):
            obs_res = self._guard.process_observation(system_prompt)
            if obs_res["is_untrusted"]:
                session_untrusted = True
                if self._block:
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
                        if obs_res["is_untrusted"]:
                            session_untrusted = True
                            if self._block:
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
                                if obs_res["is_untrusted"]:
                                    session_untrusted = True
                                    if self._block:
                                        raise SecurityViolationError(
                                            f"LightGuard Security Violation in structured Anthropic message #{i}: "
                                            f"{obs_res.get('reason', 'Adversarial pattern identified')}."
                                        )
                                block["text"] = obs_res["sanitized_observation"]

        result = self._real.create(*args, **kwargs)

        if kwargs.get("stream", False):
            return LightGuardStreamWrapper(result, self._guard, self._block, is_untrusted=session_untrusted)

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
                            is_untrusted=session_untrusted,
                        )
                        if not act_res["allowed"] and self._block:
                            raise SecurityViolationError(
                                f"LightGuard Action Firewall Block: {act_res['reason']}"
                            )
        except SecurityViolationError:
            raise
        except Exception as e:
            if self._block:
                raise SecurityViolationError(
                    f"LightGuard Security Block: Verification failed-closed on Anthropic completion: {e}"
                )

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
