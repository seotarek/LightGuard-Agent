import dataclasses
import time
from typing import Any, Optional

from lightguard.core import LightGuardAgent


@dataclasses.dataclass
class ConversationTurn:
    turn_index: int
    timestamp: float
    user_input: str
    risk_score: float
    is_untrusted: bool
    agent_output: Optional[str] = None
    tool_calls: Optional[list[dict[str, Any]]] = None


@dataclasses.dataclass
class SessionEvaluation:
    session_id: str
    turn_index: int
    turn_risk_score: float
    cumulative_momentum: float
    risk_velocity: float
    is_compromised: bool
    is_crescendo_attack: bool
    quarantined: bool
    reason: str
    elapsed_ms: float


class StatefulSessionGuard:
    """
    Multi-Turn Conversation Guard against Crescendo, Many-Shot, and Velocity Attacks.
    Maintains a temporal sliding window of interaction turns to detect progressive
    adversarial escalation, cumulative risk drift, and subtle authority erosion across turns.
    """

    def __init__(
        self,
        session_id: str = "default_session",
        momentum_decay: float = 0.85,
        max_momentum_threshold: float = 1.40,
        velocity_threshold: float = 0.55,
        guard: Optional[LightGuardAgent] = None,
    ):
        self.session_id = session_id
        self.momentum_decay = momentum_decay
        self.max_momentum_threshold = max_momentum_threshold
        self.velocity_threshold = velocity_threshold
        self.guard = guard if guard is not None else LightGuardAgent()
        self.turns: list[ConversationTurn] = []
        self.cumulative_momentum: float = 0.0
        self.is_quarantined: bool = False

    def inspect_turn(
        self,
        user_input: str,
        agent_output: Optional[str] = None,
        tool_calls: Optional[list[dict[str, Any]]] = None,
    ) -> SessionEvaluation:
        """
        Evaluates the current conversational turn in the context of previous session turns.
        Detects Crescendo escalation patterns and velocity spikes.
        """
        start_t = time.perf_counter()
        now = time.time()
        turn_idx = len(self.turns) + 1

        if self.is_quarantined:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            return SessionEvaluation(
                session_id=self.session_id,
                turn_index=turn_idx,
                turn_risk_score=1.0,
                cumulative_momentum=self.cumulative_momentum,
                risk_velocity=0.0,
                is_compromised=True,
                is_crescendo_attack=False,
                quarantined=True,
                reason="Session is already quarantined due to prior security violations.",
                elapsed_ms=elapsed_ms,
            )

        # 1. Tier 0 & 1 & 2 inspection on current turn user input
        obs_res = self.guard.process_observation(user_input)
        turn_risk = obs_res["t2_risk_score"]
        if obs_res["t1_flagged"]:
            turn_risk = max(turn_risk, 0.85)

        # Inspect tool calls if present
        if tool_calls:
            for tc in tool_calls:
                t_name = tc.get("name", "")
                t_args = tc.get("args", {})
                act_res = self.guard.verify_action(t_name, t_args, obs_res["is_untrusted"])
                if not act_res["allowed"]:
                    turn_risk = 1.0

        # 2. Compute Risk Velocity compared to immediate previous turn
        prev_risk = self.turns[-1].risk_score if self.turns else 0.0
        risk_velocity = max(0.0, turn_risk - prev_risk)

        # 3. Update Exponential Cumulative Momentum: M_t = gamma * M_{t-1} + R_t
        self.cumulative_momentum = (
            self.momentum_decay * self.cumulative_momentum + turn_risk
        )

        # 4. Check for Crescendo Multi-Turn Escalation pattern:
        # A crescendo attack consists of 3+ consecutive turns with monotonically increasing risk
        is_crescendo = False
        if len(self.turns) >= 2:
            last_two_risks = [t.risk_score for t in self.turns[-2:]]
            if (
                last_two_risks[0] < last_two_risks[1] < turn_risk
                and turn_risk >= 0.40
            ):
                is_crescendo = True

        # Check breach conditions
        reason = "Clean"
        is_compromised = False

        if turn_risk >= 0.80:
            is_compromised = True
            reason = f"High single-turn adversarial risk ({turn_risk:.2f})."
        elif self.cumulative_momentum >= self.max_momentum_threshold:
            is_compromised = True
            reason = f"Cumulative risk momentum exceeded threshold ({self.cumulative_momentum:.2f} >= {self.max_momentum_threshold:.2f})."
        elif is_crescendo:
            is_compromised = True
            reason = "Crescendo multi-turn attack escalation detected across consecutive turns."
        elif risk_velocity >= self.velocity_threshold and turn_risk >= 0.50:
            is_compromised = True
            reason = f"Adversarial risk velocity spike detected (delta={risk_velocity:.2f})."

        if is_compromised:
            self.is_quarantined = True

        # Record turn
        turn_record = ConversationTurn(
            turn_index=turn_idx,
            timestamp=now,
            user_input=user_input,
            risk_score=turn_risk,
            is_untrusted=obs_res["is_untrusted"],
            agent_output=agent_output,
            tool_calls=tool_calls,
        )
        self.turns.append(turn_record)

        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        return SessionEvaluation(
            session_id=self.session_id,
            turn_index=turn_idx,
            turn_risk_score=turn_risk,
            cumulative_momentum=self.cumulative_momentum,
            risk_velocity=risk_velocity,
            is_compromised=is_compromised,
            is_crescendo_attack=is_crescendo,
            quarantined=self.is_quarantined,
            reason=reason,
            elapsed_ms=elapsed_ms,
        )

    def reset(self) -> None:
        """Resets session history and lifts quarantine."""
        self.turns.clear()
        self.cumulative_momentum = 0.0
        self.is_quarantined = False
