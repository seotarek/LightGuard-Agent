"""Asynchronous Non-Blocking Agent Security Engine.

Provides native AsyncIO bindings and coroutines for high-throughput AI gateways
and async web microservices (FastAPI, aiohttp, Starlette).
"""

import asyncio
from typing import Any, Dict, Optional

from lightguard.core import LightGuardAgent
from lightguard.policy import SecurityPolicyConfig


class AsyncLightGuardAgent:
    """Asynchronous wrapper for LightGuard multi-tier defense pipeline."""

    def __init__(
        self,
        policy: Optional[SecurityPolicyConfig] = None,
        enable_telemetry: bool = True,
    ) -> None:
        self.sync_agent = LightGuardAgent(policy=policy, enable_telemetry=enable_telemetry)

    async def process_observation(self, raw_observation: str) -> Dict[str, Any]:
        """Asynchronously process and sanitize an observation without blocking the loop."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self.sync_agent.process_observation,
            raw_observation,
        )

    async def verify_action(
        self,
        proposed_tool: str,
        tool_args: Dict[str, Any],
        is_untrusted: bool,
    ) -> Dict[str, Any]:
        """Asynchronously verify proposed tool action against policy firewall."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            self.sync_agent.verify_action,
            proposed_tool,
            tool_args,
            is_untrusted,
        )

    @property
    def telemetry(self):
        return self.sync_agent.telemetry

    @property
    def policy(self):
        return self.sync_agent.policy
