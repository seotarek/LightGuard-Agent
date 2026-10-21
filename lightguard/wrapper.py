import functools
import inspect
import json
from typing import Any, Callable, Iterator, Optional, Union

from lightguard.core import LightGuardAgent
from lightguard.decorators import SecurityViolationError


def _unmarshal_tool_args(raw_args: Any) -> dict[str, Any]:
    """Safely parse tool arguments from JSON string, dict, or arbitrary object."""
    if isinstance(raw_args, dict):
        return raw_args
    if isinstance(raw_args, str):
        trimmed = raw_args.strip()
        if not trimmed:
            return {}
        try:
            parsed = json.loads(trimmed)
            if isinstance(parsed, dict):
                return parsed
            return {"args": parsed}
        except (json.JSONDecodeError, ValueError):
            return {"raw_args": raw_args}
    return {"args": raw_args}


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
            # 1. Standard OpenAI/Groq streaming chunk format (inspecting ALL choices)
            if hasattr(chunk, "choices") and chunk.choices:
                for choice in chunk.choices:
                    delta = getattr(choice, "delta", None)
                    if delta:
                        c_text = getattr(delta, "content", "") or ""
                        if c_text:
                            text_piece += c_text
                        tcs = getattr(delta, "tool_calls", None)
                        if tcs:
                            self._process_tool_call_deltas(tcs)
            elif isinstance(chunk, dict) and "choices" in chunk:
                for choice in chunk["choices"]:
                    delta = choice.get("delta", {}) if isinstance(choice, dict) else getattr(choice, "delta", {})
                    c_text = delta.get("content", "") if isinstance(delta, dict) else getattr(delta, "content", "")
                    if c_text:
                        text_piece += c_text
                    tcs = delta.get("tool_calls") if isinstance(delta, dict) else getattr(delta, "tool_calls", None)
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
            is_leaked, _ = self._guard.canary.check_leakage(full_text)
            if is_leaked and self._block:
                raise SecurityViolationError(
                    "LightGuard Security Block: Stream intercepted due to confidential canary token leakage."
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
                parsed_args = _unmarshal_tool_args(self._tool_calls_accumulator[idx]["arguments"])
                act_res = self._guard.verify_action(
                    fn_name,
                    parsed_args,
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
                # Pre-validate tool name on start without validating parameter schema until arguments arrive
                if name in self._guard.policy.denied_tools and self._block:
                    raise SecurityViolationError(
                        f"LightGuard Action Firewall Block in Anthropic stream: Tool '{name}' is explicitly denied."
                    )
                if self._guard.policy.allowed_tools and name not in self._guard.policy.allowed_tools and self._block:
                    raise SecurityViolationError(
                        f"LightGuard Action Firewall Block in Anthropic stream: Tool '{name}' is not in allowed_tools."
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
                is_leaked, _ = self._guard.canary.check_leakage(partial_json)
                if is_leaked and self._block:
                    raise SecurityViolationError(
                        "LightGuard Security Block: Stream intercepted due to confidential canary token leakage."
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
                parsed_args = _unmarshal_tool_args(tc_data.get("arguments", ""))
                act_res = self._guard.verify_action(
                    fn_name,
                    parsed_args,
                    is_untrusted=self._is_untrusted,
                )
                if not act_res["allowed"] and self._block:
                    raise SecurityViolationError(
                        f"LightGuard Action Firewall Block in Anthropic stream: {act_res['reason']}"
                    )


class LightGuardAsyncStreamWrapper:
    """Wraps an asynchronous LLM chunk stream, enforcing real-time inspection on streaming tokens and tool calls."""

    def __init__(
        self,
        async_stream: Any,
        guard: LightGuardAgent,
        block_on_violation: bool = True,
        is_untrusted: bool = False,
    ):
        self._stream = async_stream
        self._guard = guard
        self._block = block_on_violation
        self._is_untrusted = is_untrusted
        self._accumulated_content: list[str] = []
        self._tool_calls_accumulator: dict[int, dict[str, str]] = {}

    def __aiter__(self) -> Any:
        self._async_iter = self._stream.__aiter__()
        return self

    async def __anext__(self) -> Any:
        chunk = await self._async_iter.__anext__()

        # 1. Standard OpenAI streaming chunk format
        choices = getattr(chunk, "choices", None)
        if choices and len(choices) > 0:
            for choice in choices:
                delta = getattr(choice, "delta", None)
                if delta:
                    content = getattr(delta, "content", None)
                    if content:
                        self._accumulated_content.append(content)
                        full_text = "".join(self._accumulated_content)
                        is_leaked, _ = self._guard.canary.check_leakage(full_text)
                        if is_leaked and self._block:
                            raise SecurityViolationError(
                                "LightGuard Security Block in async stream: Output leaked confidential canary token."
                            )
                    tool_calls = getattr(delta, "tool_calls", None)
                    if tool_calls:
                        for tc in tool_calls:
                            idx = getattr(tc, "index", 0)
                            if idx not in self._tool_calls_accumulator:
                                self._tool_calls_accumulator[idx] = {"name": "", "arguments": ""}
                            func = getattr(tc, "function", None)
                            if func:
                                if getattr(func, "name", None):
                                    self._tool_calls_accumulator[idx]["name"] = func.name
                                if getattr(func, "arguments", None):
                                    self._tool_calls_accumulator[idx]["arguments"] += func.arguments

                finish_reason = getattr(choice, "finish_reason", None)
                if finish_reason in ("tool_calls", "function_call", "stop") and self._tool_calls_accumulator:
                    for idx, tc_data in list(self._tool_calls_accumulator.items()):
                        fn_name = tc_data.get("name", "")
                        if fn_name:
                            parsed_args = _unmarshal_tool_args(tc_data.get("arguments", ""))
                            act_res = self._guard.verify_action(
                                fn_name,
                                parsed_args,
                                is_untrusted=self._is_untrusted,
                            )
                            if not act_res["allowed"] and self._block:
                                raise SecurityViolationError(
                                    f"LightGuard Action Firewall Block in async stream: {act_res['reason']}"
                                )
                    self._tool_calls_accumulator.clear()

        # 2. Anthropic streaming chunk format
        c_type = getattr(chunk, "type", None)
        if c_type == "content_block_delta":
            c_delta = getattr(chunk, "delta", None)
            if c_delta:
                d_type = getattr(c_delta, "type", None)
                if d_type == "text_delta":
                    text_val = getattr(c_delta, "text", "")
                    if text_val:
                        self._accumulated_content.append(text_val)
                        full_text = "".join(self._accumulated_content)
                        is_leaked, _ = self._guard.canary.check_leakage(full_text)
                        if is_leaked and self._block:
                            raise SecurityViolationError(
                                "LightGuard Security Block in async Anthropic stream: Output leaked confidential canary token."
                            )
                elif d_type == "input_json_delta":
                    idx = getattr(chunk, "index", 0)
                    if idx not in self._tool_calls_accumulator:
                        self._tool_calls_accumulator[idx] = {"name": "", "arguments": ""}
                    self._tool_calls_accumulator[idx]["arguments"] += getattr(c_delta, "partial_json", "")

        elif c_type == "content_block_stop":
            idx = getattr(chunk, "index", 0)
            if idx in self._tool_calls_accumulator:
                tc_data = self._tool_calls_accumulator[idx]
                fn_name = tc_data.get("name", "")
                if fn_name:
                    parsed_args = _unmarshal_tool_args(tc_data.get("arguments", ""))
                    act_res = self._guard.verify_action(
                        fn_name,
                        parsed_args,
                        is_untrusted=self._is_untrusted,
                    )
                    if not act_res["allowed"] and self._block:
                        raise SecurityViolationError(
                            f"LightGuard Action Firewall Block in async Anthropic stream: {act_res['reason']}"
                        )

        return chunk


class LightGuardChatCompletionsProxy:
    """Proxies client.chat.completions to transparently intercept .create() calls for both sync and async clients."""

    def __init__(self, real_completions: Any, guard: LightGuardAgent, block_on_violation: bool = True):
        self._real = real_completions
        self._guard = guard
        self._block = block_on_violation

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def _inspect_result(self, result: Any, session_untrusted: bool) -> None:
        try:
            if hasattr(result, "choices") and result.choices:
                msg = result.choices[0].message
                content = getattr(msg, "content", "") or ""
                if content:
                    is_leaked, _ = self._guard.canary.check_leakage(content)
                    if is_leaked and self._block:
                        raise SecurityViolationError(
                            "LightGuard Security Block: Output leaked confidential canary token."
                        )
                tool_calls = getattr(msg, "tool_calls", None)
                if tool_calls:
                    for tc in tool_calls:
                        func = getattr(tc, "function", None)
                        if func:
                            fn_name = getattr(func, "name", "")
                            raw_args = getattr(func, "arguments", "{}")
                            fn_args = _unmarshal_tool_args(raw_args)
                            act_res = self._guard.verify_action(
                                fn_name, fn_args, is_untrusted=session_untrusted
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
                    f"LightGuard Security Block: Verification failed-closed on OpenAI completion: {e}"
                )

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

        if inspect.iscoroutine(result):
            async def _async_create():
                resolved = await result
                if kwargs.get("stream", False):
                    return LightGuardAsyncStreamWrapper(
                        resolved, self._guard, self._block, is_untrusted=session_untrusted
                    )
                self._inspect_result(resolved, session_untrusted)
                return resolved

            return _async_create()

        if kwargs.get("stream", False):
            return LightGuardStreamWrapper(result, self._guard, self._block, is_untrusted=session_untrusted)

        self._inspect_result(result, session_untrusted)
        return result


class LightGuardMessagesProxy:
    """Proxies Anthropic client.messages to transparently intercept .create() calls for sync and async clients."""

    def __init__(self, real_messages: Any, guard: LightGuardAgent, block_on_violation: bool = True):
        self._real = real_messages
        self._guard = guard
        self._block = block_on_violation

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def _inspect_result(self, result: Any, session_untrusted: bool) -> None:
        try:
            content_blocks = getattr(result, "content", None)
            if content_blocks and isinstance(content_blocks, list):
                for block in content_blocks:
                    b_type = getattr(block, "type", "") if hasattr(block, "type") else block.get("type", "")
                    if b_type == "text":
                        text_val = getattr(block, "text", "") if hasattr(block, "text") else block.get("text", "")
                        if text_val:
                            is_leaked, _ = self._guard.canary.check_leakage(text_val)
                            if is_leaked and self._block:
                                raise SecurityViolationError(
                                    "LightGuard Security Block: Output leaked confidential canary token."
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

        if inspect.iscoroutine(result):
            async def _async_create():
                resolved = await result
                if kwargs.get("stream", False):
                    return LightGuardAsyncStreamWrapper(
                        resolved, self._guard, self._block, is_untrusted=session_untrusted
                    )
                self._inspect_result(resolved, session_untrusted)
                return resolved

            return _async_create()

        if kwargs.get("stream", False):
            return LightGuardStreamWrapper(result, self._guard, self._block, is_untrusted=session_untrusted)

        self._inspect_result(result, session_untrusted)
        return result


class LightGuardChatProxy:
    """Proxies client.chat to intercept client.chat.completions or callable client.chat(model=..., messages=...)."""

    def __init__(self, real_chat: Any, guard: LightGuardAgent, block_on_violation: bool = True):
        self._real = real_chat
        self._guard = guard
        self._block = block_on_violation
        self.completions = LightGuardChatCompletionsProxy(
            getattr(real_chat, "completions", real_chat), guard, block_on_violation
        )

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Enables direct function invocation: client.chat(...) for Ollama and similar engines."""
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
                                    f"LightGuard Security Violation: Untrusted prompt injection in chat call message #{i}: "
                                    f"{obs_res.get('reason', 'Adversarial pattern identified')}."
                                )
                        msg["content"] = obs_res["sanitized_observation"]

        result = self._real(*args, **kwargs)

        if inspect.iscoroutine(result):
            async def _async_call():
                resolved = await result
                self._inspect_call_result(resolved, session_untrusted)
                return resolved

            return _async_call()

        self._inspect_call_result(result, session_untrusted)
        return result

    def _inspect_call_result(self, result: Any, session_untrusted: bool) -> None:
        if isinstance(result, dict):
            msg = result.get("message", {})
            content = msg.get("content", "") if isinstance(msg, dict) else ""
            if content:
                is_leaked, _ = self._guard.canary.check_leakage(content)
                if is_leaked and self._block:
                    raise SecurityViolationError(
                        "LightGuard Security Block: Output leaked confidential canary token."
                    )
            tool_calls = msg.get("tool_calls", []) if isinstance(msg, dict) else []
            if tool_calls and isinstance(tool_calls, list):
                for tc in tool_calls:
                    fn = tc.get("function", {}) if isinstance(tc, dict) else {}
                    fn_name = fn.get("name", "")
                    fn_args = fn.get("arguments", {})
                    act_res = self._guard.verify_action(
                        fn_name,
                        _unmarshal_tool_args(fn_args),
                        is_untrusted=session_untrusted,
                    )
                    if not act_res["allowed"] and self._block:
                        raise SecurityViolationError(
                            f"LightGuard Action Firewall Block: {act_res['reason']}"
                        )


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


wrap_client = wrap
