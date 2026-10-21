"""Structured Output & Function Calling Argument Guard.

Validates and sanitizes structured tool parameters, preventing JSON Parameter
Smuggling, Command Chaining, Path Traversal, and Delimiter Escapes inside
structured LLM function calls.
"""

import re
import time
from typing import Any, Dict, List, Optional, Set

from lightguard.core import LightGuardAgent


class StructuredOutputGuard:
    """Enforces boundary safety and parameter validation on structured tool calls."""

    DANGEROUS_SHELL_PATTERNS = [
        re.compile(r"[;&|`$><]"),
        re.compile(r"\b(rm|cat|curl|wget|nc|bash|sh|powershell)\b", re.IGNORECASE),
        re.compile(r"\.\./|\.\.\\"),  # Path traversal
    ]

    def __init__(
        self,
        guard: Optional[LightGuardAgent] = None,
        sensitive_arg_keys: Optional[Set[str]] = None,
    ) -> None:
        self.guard = guard if guard is not None else LightGuardAgent()
        self.sensitive_arg_keys = sensitive_arg_keys or {
            "path",
            "filepath",
            "filename",
            "command",
            "cmd",
            "query",
            "sql",
            "url",
            "destination",
        }

    def _validate_node(
        self,
        key: str,
        val: Any,
        violations: List[str],
        strict_shell_check: bool,
        current_depth: int = 0,
        max_depth: int = 10,
    ) -> Any:
        if current_depth > max_depth:
            return val

        if isinstance(val, str):
            # 1. Scan for prompt injection directives
            obs = self.guard.process_observation(val)
            clean_val = val
            if obs["is_untrusted"]:
                violations.append(f"Prompt injection in argument '{key}': {obs['threat_categories']}")
                clean_val = obs["clean_text"]

            # 2. Check sensitive arguments for dangerous shell escapes or path traversal
            if strict_shell_check and (key.lower() in self.sensitive_arg_keys or "../" in val or "..\\" in val or "/etc/" in val):
                if "../" in val or "..\\" in val or "/etc/" in val:
                    violations.append(f"Path traversal detected in argument '{key}': {val}")
                if key.lower() in {"cmd", "command"} and any(
                    p.search(val) for p in self.DANGEROUS_SHELL_PATTERNS
                ):
                    violations.append(f"Dangerous command chaining syntax in argument '{key}'")
            return clean_val

        elif isinstance(val, dict):
            sanitized_dict = {}
            for sub_k, sub_v in val.items():
                sanitized_dict[sub_k] = self._validate_node(
                    sub_k, sub_v, violations, strict_shell_check, current_depth + 1, max_depth
                )
            return sanitized_dict

        elif isinstance(val, list):
            sanitized_list = []
            for item in val:
                sanitized_list.append(
                    self._validate_node(
                        key, item, violations, strict_shell_check, current_depth + 1, max_depth
                    )
                )
            return sanitized_list

        return val

    def validate_tool_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        strict_shell_check: bool = True,
    ) -> Dict[str, Any]:
        """Validate argument dictionary, detecting prompt injections and dangerous shell payloads."""
        t0 = time.perf_counter()
        violations: List[str] = []
        sanitized_args: Dict[str, Any] = {}

        for key, val in arguments.items():
            sanitized_args[key] = self._validate_node(
                key, val, violations, strict_shell_check, current_depth=0
            )

        is_safe = len(violations) == 0

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "allowed": is_safe,
            "tool_name": tool_name,
            "violations": violations,
            "sanitized_arguments": sanitized_args,
            "latency_ms": latency_ms,
        }
