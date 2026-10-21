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

    def validate_tool_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        strict_shell_check: bool = True,
    ) -> Dict[str, Any]:
        """Validate argument dictionary, detecting prompt injections and dangerous shell payloads."""
        t0 = time.perf_counter()
        violations: List[str] = []
        is_safe = True
        sanitized_args: Dict[str, Any] = {}

        for key, val in arguments.items():
            if isinstance(val, str):
                # 1. Scan for prompt injection directives
                obs = self.guard.process_observation(val)
                if obs["is_untrusted"]:
                    violations.append(f"Prompt injection in argument '{key}': {obs['threat_categories']}")
                    is_safe = False
                    sanitized_args[key] = obs["clean_text"]
                else:
                    sanitized_args[key] = val

                # 2. Check sensitive arguments for dangerous shell escapes or path traversal
                if strict_shell_check and key.lower() in self.sensitive_arg_keys:
                    # Detect path traversal
                    if "../" in val or "..\\" in val or "/etc/" in val:
                        violations.append(f"Path traversal detected in argument '{key}': {val}")
                        is_safe = False

                    # Detect command chaining
                    if key.lower() in {"cmd", "command"} and any(
                        p.search(val) for p in self.DANGEROUS_SHELL_PATTERNS
                    ):
                        violations.append(f"Dangerous command chaining syntax in argument '{key}'")
                        is_safe = False
            else:
                sanitized_args[key] = val

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "allowed": is_safe,
            "tool_name": tool_name,
            "violations": violations,
            "sanitized_arguments": sanitized_args,
            "latency_ms": latency_ms,
        }
