import functools
import inspect
from typing import Any, Callable, Optional

from lightguard.core import LightGuardAgent


class SecurityViolationError(Exception):
    """Raised when an action is blocked by the LightGuard Action Firewall."""

    def __init__(self, message: str, tool_name: str, reason: str):
        super().__init__(message)
        self.tool_name = tool_name
        self.reason = reason


def protect_tool(
    func: Optional[Callable[..., Any]] = None,
    *,
    guard: Optional[LightGuardAgent] = None,
    tool_name: Optional[str] = None,
    block_on_untrusted: bool = True,
    sanitize_output: bool = True,
    raise_on_blocked: bool = True,
) -> Callable[..., Any]:
    """Decorator to secure agent tools and external functions with LightGuard.

    Validates parameters against secret leakage and high-stakes execution policies
    before execution, and sanitizes untrusted string outputs.
    """

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        agent_guard = guard if guard is not None else LightGuardAgent()
        effective_name = tool_name if tool_name is not None else fn.__name__

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            clean_kwargs = dict(kwargs)
            is_untrusted = clean_kwargs.pop("__untrusted_context", False)

            # Bind arguments to inspect parameters
            sig = inspect.signature(fn)
            bound_args = sig.bind_partial(*args, **clean_kwargs)
            bound_args.apply_defaults()
            all_kwargs = dict(bound_args.arguments)

            # Verify action with Tier 3 Firewall
            action_verif = agent_guard.verify_action(
                proposed_tool=effective_name,
                tool_args=all_kwargs,
                is_untrusted=bool(is_untrusted and block_on_untrusted),
            )

            if not action_verif["allowed"]:
                if raise_on_blocked:
                    raise SecurityViolationError(
                        f"LightGuard Blocked execution of '{effective_name}': {action_verif['reason']}",
                        tool_name=effective_name,
                        reason=action_verif["reason"],
                    )
                return {
                    "status": "blocked",
                    "tool": effective_name,
                    "reason": action_verif["reason"],
                }

            # Execute the underlying function
            result = fn(*args, **clean_kwargs)

            # Sanitize output if enabled and result is a string
            if sanitize_output and isinstance(result, str):
                obs = agent_guard.process_observation(result)
                return obs["sanitized_observation"]

            return result

        return wrapper

    if func is not None:
        return decorator(func)
    return decorator
