import ipaddress
import re
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set

from lightguard.core import LightGuardAgent


class StructuredOutputGuard:
    """Enforces boundary safety and parameter validation on structured tool calls."""

    DANGEROUS_SHELL_PATTERNS = [
        re.compile(r"[;&|`$><]"),
        re.compile(r"\b(rm|cat|curl|wget|nc|bash|sh|powershell|cmd\.exe)\b", re.IGNORECASE),
        re.compile(r"\.\./|\.\.\\"),  # Path traversal
    ]

    DANGEROUS_SQL_PATTERNS = [
        re.compile(r"(?i)\b(union\s+select|drop\s+table|alter\s+table|truncate\s+table|insert\s+into|delete\s+from|sleep\s*\(|benchmark\s*\()\b"),
        re.compile(r"(?i)('\s*or\s*'1'\s*=\s*'1'|\b1\s*=\s*1\b|--|;\s*drop)"),
    ]

    SHELL_KEYS: Set[str] = {
        "cmd", "command", "exec", "script", "code", "bash", "sh", "shell", "eval", "raw_args"
    }
    PATH_KEYS: Set[str] = {
        "path", "filepath", "filename", "file", "dest", "destination", "directory", "dir", "folder"
    }
    URL_KEYS: Set[str] = {
        "url", "uri", "endpoint", "webhook", "target_url", "destination_url", "callback_url"
    }
    SQL_KEYS: Set[str] = {
        "query", "sql", "stmt", "statement"
    }

    def __init__(
        self,
        guard: Optional[LightGuardAgent] = None,
        sensitive_arg_keys: Optional[Set[str]] = None,
        max_depth: int = 10,
        max_elements: int = 1000,
    ) -> None:
        self.guard = guard if guard is not None else LightGuardAgent()
        self.max_depth = max_depth
        self.max_elements = max_elements
        self.sensitive_arg_keys = sensitive_arg_keys or (
            self.SHELL_KEYS | self.PATH_KEYS | self.URL_KEYS | self.SQL_KEYS
        )

    @classmethod
    def validate_url_ssrf(cls, url_str: str) -> Optional[str]:
        """Validates that a URL does not attempt SSRF against cloud metadata or private networks."""
        try:
            parsed = urllib.parse.urlparse(url_str)
            if not parsed.scheme:
                return None
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                return f"SSRF protection blocked unsafe URL scheme '{scheme}': only http and https are permitted."

            hostname = parsed.hostname
            if not hostname:
                return None
            hostname_lower = hostname.lower()

            if hostname_lower in ("localhost", "0.0.0.0", "127.0.0.1", "::1", "metadata.google.internal"):
                return f"SSRF protection blocked URL accessing internal/loopback host: '{hostname}'."

            if "169.254.169.254" in hostname_lower:
                return "SSRF protection blocked URL accessing cloud metadata service (169.254.169.254)."

            try:
                ip = ipaddress.ip_address(hostname_lower)
                if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                    return f"SSRF protection blocked URL accessing private/internal IP '{ip}'."
            except ValueError:
                pass
        except Exception as e:
            return f"Malformed URL rejected: {e}"
        return None

    def _validate_node(
        self,
        key: str,
        val: Any,
        violations: List[str],
        strict_shell_check: bool,
        current_depth: int,
        path_ids: Set[int],
        total_nodes: List[int],
    ) -> Any:
        total_nodes[0] += 1
        if total_nodes[0] > self.max_elements:
            violations.append(f"Max argument payload complexity ({self.max_elements} nodes) exceeded at '{key}'")
            return val

        if current_depth > self.max_depth:
            violations.append(f"Max argument nesting depth ({self.max_depth}) exceeded at '{key}'")
            return val

        if isinstance(val, (dict, list)):
            val_id = id(val)
            if val_id in path_ids:
                violations.append(f"Cyclic data structure detected in argument under '{key}'")
                return val
            path_ids.add(val_id)

            try:
                if isinstance(val, dict):
                    sanitized_dict = {}
                    for sub_k, sub_v in val.items():
                        sanitized_dict[sub_k] = self._validate_node(
                            sub_k, sub_v, violations, strict_shell_check, current_depth + 1, path_ids, total_nodes
                        )
                    return sanitized_dict
                else:
                    sanitized_list = []
                    for item in val:
                        sanitized_list.append(
                            self._validate_node(
                                key, item, violations, strict_shell_check, current_depth + 1, path_ids, total_nodes
                            )
                        )
                    return sanitized_list
            finally:
                path_ids.remove(val_id)

        if isinstance(val, str):
            # 1. Scan for prompt injection directives
            obs = self.guard.process_observation(val)
            clean_val = val
            if obs["is_untrusted"]:
                violations.append(f"Prompt injection in argument '{key}': {obs['threat_categories']}")
                clean_val = obs["clean_text"]

            # 2. Path traversal check on any string
            if "../" in val or "..\\" in val or "/etc/" in val:
                violations.append(f"Path traversal detected in argument '{key}': {val}")

            # 3. Shell and command chaining checks
            if strict_shell_check and (key.lower() in self.SHELL_KEYS or key.lower() in {"path", "filepath", "filename"}):
                if key.lower() in self.SHELL_KEYS and any(
                    p.search(val) for p in self.DANGEROUS_SHELL_PATTERNS
                ):
                    violations.append(f"Dangerous command chaining syntax in argument '{key}'")

            # 4. SSRF URL check
            if key.lower() in self.URL_KEYS:
                ssrf_err = self.validate_url_ssrf(val)
                if ssrf_err:
                    violations.append(ssrf_err)

            # 5. SQL Injection heuristic check
            if key.lower() in self.SQL_KEYS:
                if any(p.search(val) for p in self.DANGEROUS_SQL_PATTERNS):
                    violations.append(f"Dangerous SQL injection syntax in argument '{key}'")

            return clean_val

        return val

    def validate_tool_arguments(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        strict_shell_check: bool = True,
    ) -> Dict[str, Any]:
        """Validate argument dictionary, detecting prompt injections, shell escapes, SSRF, and SQLi."""
        t0 = time.perf_counter()
        violations: List[str] = []
        sanitized_args: Dict[str, Any] = {}
        path_ids: Set[int] = set()
        total_nodes = [0]

        if isinstance(arguments, dict):
            for key, val in arguments.items():
                sanitized_args[key] = self._validate_node(
                    key, val, violations, strict_shell_check, current_depth=0, path_ids=path_ids, total_nodes=total_nodes
                )
        else:
            violations.append(f"Tool arguments must be a dictionary, got {type(arguments).__name__}")

        is_safe = len(violations) == 0
        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "allowed": is_safe,
            "tool_name": tool_name,
            "violations": violations,
            "sanitized_arguments": sanitized_args,
            "latency_ms": latency_ms,
        }
