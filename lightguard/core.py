import re
import time
from typing import Any, ClassVar, Optional

from lightguard.adversarial_suffix import AdversarialSuffixDetector
from lightguard.audit import AuditEvent, SecurityReasonCode
from lightguard.canary import CanaryGuard
from lightguard.fast_matcher import FastPatternMatcher
from lightguard.obfuscation import Tier0ObfuscationShield
from lightguard.policy import AuthorizationContext, SecurityPolicyConfig
from lightguard.privacy import PrivacyGuard
from lightguard.telemetry import SecurityTelemetryCollector
from lightguard.threat_intel import ThreatIntelRegistry


class Tier1SyntacticSanitizer:
    """
    Tier 1: High-speed deterministic syntactic and boundary sanitization.
    Escapes dangerous delimiters via Aho-Corasick multi-pattern automaton,
    neutralizes known imperative attack patterns, and isolates untrusted external data.
    """

    KNOWN_INJECTION_PATTERNS: ClassVar[list[re.Pattern]] = [
        re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above|these)?\s*(instructions|constraints|rules|directives|prompts)\b"),
        re.compile(r"(?i)\bdisregard\s+(all\s+|the\s+)?(system|previous|prior)\s+(prompt|instructions|rules|constraints)\b"),
        re.compile(r"(?i)\byou\s+are\s+now\s+(a\s+)?new\s+(ai|assistant|model)\b"),
        re.compile(r"(?i)\bsystem\s*(:|\b)\s*override\b"),
        re.compile(r"(?i)\b(priority|override)\s+(command|directive|instruction)\s*:\s*\b"),
        re.compile(r"(?i)\bprint\s+(all\s+)?(hidden|secret|api|key|environment|developer)\b"),
        re.compile(r"(?i)\b(output|reveal|dump)\s+(your\s+)?(entire\s+)?(secret\s+)?(system\s+)?(prompt|instructions|keys|tokens)\b"),
        re.compile(r"(?i)\b(forward|exfiltrate|leak)\s+(all\s+)?(system\s+)?(data|secrets|messages|credentials|tokens|keys)\b"),
        re.compile(r"(?i)\bexecute\s+command\s*:\s*\b"),
        re.compile(r"(?i)\badmin\s+mode\s+enabled\b"),
        re.compile(r"(?i)\b(exec_bash|drop_table|delete_file|execute_sql|transfer_funds|delete_database|drop_database|terminate_instance|destroy_cluster)\s*(\(|=)"),
        re.compile(r"(?i)\b(assistant|ai|system)\s*:\s*(you\s+must|please|now)\s+(now\s+)?(invoke|call|execute|run)\b"),
    ]

    DELIMITER_TAGS: ClassVar[list[tuple[str, str]]] = [
        ("```system", "```escaped_system"),
        ("<system>", "&lt;system&gt;"),
        ("</system>", "&lt;/system&gt;"),
        ("<!-- system", "&lt;!-- escaped_system"),
        ("<!--system", "&lt;!--escaped_system"),
        ("<user_input>", "&lt;user_input&gt;"),
        ("</user_input>", "&lt;/user_input&gt;"),
        ("<im_start>", "&lt;im_start&gt;"),
        ("<im_end>", "&lt;im_end&gt;"),
    ]
    DELIMITER_DICT: ClassVar[dict[str, str]] = dict(DELIMITER_TAGS)
    AUTOMATON: ClassVar[FastPatternMatcher] = FastPatternMatcher([tag for tag, _ in DELIMITER_TAGS])

    @staticmethod
    def sanitize(raw_text: str) -> tuple[str, bool, float]:
        start_t = time.perf_counter()
        flagged = False
        cleaned = raw_text

        # Check against deterministic injection signatures
        for pattern in Tier1SyntacticSanitizer.KNOWN_INJECTION_PATTERNS:
            if pattern.search(cleaned):
                flagged = True
                cleaned = pattern.sub("[REDACTED_INJECTION_DIRECTIVE]", cleaned)

        # High-speed Aho-Corasick automaton for delimiter neutralization
        if Tier1SyntacticSanitizer.AUTOMATON.contains_any(cleaned):
            flagged = True
            matches = Tier1SyntacticSanitizer.AUTOMATON.search(cleaned)
            for _, _, tag in matches:
                replacement = Tier1SyntacticSanitizer.DELIMITER_DICT.get(tag)
                if replacement:
                    pattern = re.compile(re.escape(tag), re.IGNORECASE)
                    cleaned = pattern.sub(replacement, cleaned)

        # Encapsulate untrusted data into strict bounded observation tags
        bounded_content = (
            f"<untrusted_observation origin='external_tool'>\n{cleaned}\n</untrusted_observation>"
        )

        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        return bounded_content, flagged, elapsed_ms


class Tier2SemanticClassifier:
    """
    Tier 2: Lightweight Semantic Intent Analyzer (Sub-10ms).
    Extracts imperative intent density, instruction hijacking cues,
    and exfiltration semantics without full LLM generation overhead.
    """

    IMPERATIVE_VERBS: ClassVar[set[str]] = {
        "send", "email", "delete", "post", "curl", "fetch", "forward",
        "drop", "exfiltrate", "transmit", "modify", "update", "execute",
        "transfer", "leak", "dump"
    }
    TARGET_ENTITIES: ClassVar[set[str]] = {
        "password", "secret", "token", "credential", "api_key", "database",
        "private", "auth", "session", "user_data", "cookie", "account",
        "funds", "keys", "table"
    }
    AUTHORITY_OVERRIDE_TERMS: ClassVar[set[str]] = {
        "emergency", "urgent", "administrator", "root", "developer_mode",
        "override", "priority_command", "jailbreak", "instruction"
    }

    @staticmethod
    def analyze(text: str) -> tuple[float, bool, float]:
        start_t = time.perf_counter()
        lowered = text.lower()
        tokens = set(re.findall(r"\b\w+\b", lowered))

        imperative_count = len(tokens.intersection(Tier2SemanticClassifier.IMPERATIVE_VERBS))
        target_count = len(tokens.intersection(Tier2SemanticClassifier.TARGET_ENTITIES))
        override_count = len(tokens.intersection(Tier2SemanticClassifier.AUTHORITY_OVERRIDE_TERMS))

        score = 0.0
        if override_count > 0:
            score += 0.45 * min(override_count, 2)
        if imperative_count > 0 and target_count > 0:
            score += 0.50
        elif imperative_count > 0:
            score += 0.20
        elif target_count > 0:
            score += 0.15

        if re.search(r'https?://[^\s<>"]+|www\.[^\s<>"]+', lowered) and imperative_count > 0:
            score += 0.35

        score = min(score, 1.0)
        is_suspicious = score >= 0.50
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        return score, is_suspicious, elapsed_ms


class Tier3ActionFirewall:
    """
    Tier 3: Execution Policy & Action Firewall.
    Validates agent proposed tool calls against security policies and
    flags high-stakes operations if previous observations were untrusted.
    """

    HIGH_STAKES_TOOLS: ClassVar[set[str]] = {
        "send_email", "delete_file", "drop_table", "execute_sql",
        "http_post", "transfer_funds", "modify_permissions", "exec_bash",
        "delete_database", "drop_database", "terminate_instance", "destroy_cluster",
    }

    @staticmethod
    def validate_action(
        proposed_tool: str,
        tool_args: dict[str, Any],
        is_observation_untrusted: bool
    ) -> tuple[bool, str, float]:
        start_t = time.perf_counter()

        # Policy 1: Block High-Stakes tools automatically if triggered by untrusted observation
        if is_observation_untrusted and proposed_tool in Tier3ActionFirewall.HIGH_STAKES_TOOLS:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            return (
                False,
                f"Action Firewall Blocked: Tool '{proposed_tool}' is high-stakes and untrusted context was detected.",
                elapsed_ms
            )

        # Policy 2: Check for exfiltration payloads in tool arguments
        for k, v in tool_args.items():
            val_str = str(v).lower()
            if any(term in val_str for term in ["apikey", "password", "bearer ", "token="]) and proposed_tool in ["http_post", "send_email", "fetch"]:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                return False, f"Action Firewall Blocked: Detected potential secret leakage in parameter '{k}'.", elapsed_ms

        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        return True, "Allowed", elapsed_ms


class LightGuardAgent:
    """
    Unified LightGuard-Agent Orchestrator.
    Combines Tier 0 (Steganography/Obfuscation), Tier 1 (Syntactic Delimiter Shield),
    Tier 2 (Semantic Intent Heuristics), Tier 3 (Action Firewall),
    Cryptographic Canary verification, and optional DLP Privacy Redaction into
    a sub-millisecond enterprise defense pipeline.
    """

    def __init__(
        self,
        canary_guard: Optional[CanaryGuard] = None,
        policy: Optional[SecurityPolicyConfig] = None,
        enable_telemetry: bool = True,
        audit_logger: Optional[Any] = None,
    ):
        self.policy = policy if policy is not None else SecurityPolicyConfig.balanced()
        self.t0 = Tier0ObfuscationShield()
        self.t1 = Tier1SyntacticSanitizer()
        self.t2 = Tier2SemanticClassifier()
        self.t3 = Tier3ActionFirewall()
        self.canary = canary_guard if canary_guard is not None else CanaryGuard()
        self.enable_telemetry = enable_telemetry
        self.telemetry = SecurityTelemetryCollector.get_instance() if enable_telemetry else None
        self.audit_logger = audit_logger or getattr(self.policy, "audit_logger", None)

        self.suffix_detector = (
            AdversarialSuffixDetector()
            if self.policy.enable_adversarial_suffix_detector
            else None
        )
        self.threat_intel = (
            ThreatIntelRegistry.get_instance()
            if self.policy.enable_threat_intel_matcher
            else None
        )
        self._structured_guard = None

    @property
    def structured_guard(self) -> Any:
        if self._structured_guard is None:
            from lightguard.structured import StructuredOutputGuard

            self._structured_guard = StructuredOutputGuard(guard=self)
        return self._structured_guard

    def process_observation(self, raw_observation: Any) -> dict[str, Any]:
        if raw_observation is None:
            raw_text = ""
        elif not isinstance(raw_observation, str):
            raw_text = str(raw_observation)
        else:
            raw_text = raw_observation

        # Optional DLP / PII redaction
        dlp_redacted = raw_text
        dlp_mapping: dict[str, str] = {}
        if self.policy.enable_dlp_redaction:
            dlp_redacted, dlp_mapping, _ = PrivacyGuard.redact(raw_text)
            if self.enable_telemetry and self.telemetry and dlp_mapping:
                self.telemetry.record_pii_redaction(len(dlp_mapping))

        # Tier 0 Normalization
        if self.policy.enable_obfuscation_shield:
            t0_res = self.t0.normalize(dlp_redacted)
            inspection_buffer = t0_res["inspection_buffer"]
        else:
            t0_res = {
                "was_obfuscated": False,
                "entropy": 0.0,
                "decoded_payloads": [],
                "elapsed_ms": 0.0,
            }
            inspection_buffer = dlp_redacted

        sanitized_text, t1_flagged, t1_ms = self.t1.sanitize(inspection_buffer)
        risk_score, t2_flagged, t2_ms = self.t2.analyze(inspection_buffer)

        # Check for Canary token leak inside observation
        canary_leaked = False
        leaked_token = None
        if self.policy.enable_canary_guard:
            canary_leaked, leaked_token = self.canary.check_leakage(raw_observation)
            if canary_leaked:
                t1_flagged = True
                risk_score = 1.0

        # Check Adversarial Suffixes (GCG gradient perturbations)
        suffix_ms = 0.0
        adversarial_hit = False
        if self.suffix_detector:
            s_res = self.suffix_detector.analyze(inspection_buffer)
            suffix_ms = s_res.get("latency_ms", 0.0)
            if s_res.get("is_adversarial"):
                t1_flagged = True
                adversarial_hit = True
                risk_score = max(risk_score, 0.85)

        # Check Offline Threat Intelligence Signatures
        intel_ms = 0.0
        threat_intel_hit = False
        if self.threat_intel and self.threat_intel.total_signatures > 0:
            t_intel_s = time.perf_counter()
            for sig in self.threat_intel._signatures.values():
                matcher = getattr(sig, "compiled", None)
                matched = matcher.search(inspection_buffer) if matcher is not None else re.search(sig.pattern, inspection_buffer, re.IGNORECASE)
                if matched:
                    t1_flagged = True
                    threat_intel_hit = True
                    risk_score = max(risk_score, 0.95 if sig.severity == "CRITICAL" else 0.80)
                    break
            intel_ms = (time.perf_counter() - t_intel_s) * 1000.0

        # Recursively inspect hidden payloads decoded from steganography
        if t0_res.get("decoded_payloads"):
            for payload in t0_res["decoded_payloads"]:
                _, sub_t1, _ = self.t1.sanitize(payload)
                sub_risk, _, _ = self.t2.analyze(payload)
                p_lower = payload.lower()
                if (
                    sub_t1
                    or sub_risk >= 0.35
                    or any(w in p_lower for w in ["ignore", "disregard", "override", "system", "prompt", "exec", "drop"])
                ):
                    t1_flagged = True
                    risk_score = max(risk_score, 0.90)

        is_untrusted = (
            t1_flagged
            or (risk_score >= self.policy.risk_threshold)
            or canary_leaked
        )

        total_ms = t0_res["elapsed_ms"] + t1_ms + t2_ms + suffix_ms + intel_ms

        if self.enable_telemetry and self.telemetry:
            self.telemetry.record_observation(
                is_blocked=is_untrusted,
                was_obfuscated=t0_res["was_obfuscated"],
                canary_violated=canary_leaked,
                latency_ms=total_ms,
            )

        threat_categories: list[str] = []
        if is_untrusted and t0_res["was_obfuscated"]:
            threat_categories.append("Obfuscation / Steganography")
        if t1_flagged:
            threat_categories.append("Syntactic Directive Neutralized")
        if risk_score >= self.policy.risk_threshold:
            threat_categories.append("Semantic Imperative Elevation")
        if canary_leaked:
            threat_categories.append("Canary Leakage Attempt")

        if canary_leaked:
            reason_code = SecurityReasonCode.LG_CANARY_LEAK
        elif threat_intel_hit:
            reason_code = SecurityReasonCode.LG_THREAT_INTEL_MATCH
        elif adversarial_hit:
            reason_code = SecurityReasonCode.LG_ADVERSARIAL_SUFFIX
        elif is_untrusted and t0_res["was_obfuscated"]:
            reason_code = SecurityReasonCode.LG_OBFUSCATION_DETECTED
        elif t1_flagged:
            reason_code = SecurityReasonCode.LG_PI_SYNTACTIC
        elif risk_score >= self.policy.risk_threshold:
            reason_code = SecurityReasonCode.LG_PI_SEMANTIC
        else:
            reason_code = SecurityReasonCode.LG_OK

        if self.audit_logger:
            self.audit_logger.log(
                AuditEvent(
                    event_id=f"obs-{time.time_ns()}",
                    timestamp=time.time(),
                    event_type="observation",
                    decision="BLOCK" if is_untrusted else "ALLOW",
                    reason_code=reason_code,
                    reason="; ".join(threat_categories) if threat_categories else "Clean observation verified",
                    latency_ms=total_ms,
                    metadata={"text_length": len(raw_text)},
                )
            )

        return {
            "sanitized_observation": sanitized_text,
            "t0_was_obfuscated": t0_res["was_obfuscated"],
            "t0_entropy": t0_res["entropy"],
            "decoded_payloads": t0_res["decoded_payloads"],
            "t1_flagged": t1_flagged,
            "t2_risk_score": risk_score,
            "risk_score": risk_score,
            "reason_code": reason_code.value,
            "canary_leaked": canary_leaked,
            "leaked_token": leaked_token,
            "dlp_redacted": self.policy.enable_dlp_redaction and bool(dlp_mapping),
            "dlp_mapping": dlp_mapping,
            "is_untrusted": is_untrusted,
            "total_latency_ms": total_ms,
            "latency_ms": total_ms,
            "clean_text": sanitized_text,
            "threat_categories": threat_categories,
            "latency_breakdown": {
                "t0_ms": t0_res["elapsed_ms"],
                "t1_ms": t1_ms,
                "t2_ms": t2_ms,
            },
        }


    def _log_action_audit(
        self,
        tool_name: str,
        caller_role: str,
        caller_id: str,
        allowed: bool,
        code: SecurityReasonCode,
        reason: str,
        latency_ms: float,
        is_untrusted: bool,
    ) -> None:
        if self.audit_logger:
            self.audit_logger.log(
                AuditEvent(
                    event_id=f"act-{time.time_ns()}",
                    timestamp=time.time(),
                    event_type="action_verification",
                    decision="ALLOW" if allowed else "BLOCK",
                    reason_code=code,
                    reason=reason,
                    target_tool=tool_name,
                    caller_role=caller_role,
                    caller_id=caller_id,
                    latency_ms=latency_ms,
                    metadata={"is_untrusted": is_untrusted},
                )
            )

    def verify_action(
        self,
        proposed_tool: str,
        tool_args: dict[str, Any],
        is_untrusted: bool,
        context: Optional[AuthorizationContext] = None,
    ) -> dict[str, Any]:
        start_t = time.perf_counter()

        caller_role = context.caller_role if context else "user"
        caller_id = context.caller_id if context else ""
        effective_untrusted = (is_untrusted or (context.is_untrusted if context else False)) and self.policy.block_on_untrusted

        # Authorization Rule 1: Explicit Denylist (Highest Precedence - Unconditional Block)
        if proposed_tool in self.policy.denied_tools:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            if self.enable_telemetry and self.telemetry:
                self.telemetry.record_action_block()
            reason = f"Authorization Policy Blocked: Tool '{proposed_tool}' is explicitly denied by policy."
            code = SecurityReasonCode.LG_TOOL_EXPLICIT_DENY
            self._log_action_audit(proposed_tool, caller_role, caller_id, False, code, reason, elapsed_ms, effective_untrusted)
            return {
                "allowed": False,
                "reason": reason,
                "reason_code": code.value,
                "t3_latency_ms": elapsed_ms,
            }

        # Authorization Rule 2: Explicit Allowlist (Default-Deny least privilege)
        if self.policy.allowed_tools and proposed_tool not in self.policy.allowed_tools:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            if self.enable_telemetry and self.telemetry:
                self.telemetry.record_action_block()
            reason = f"Authorization Policy Blocked: Tool '{proposed_tool}' is not in allowed_tools (default-deny policy)."
            code = SecurityReasonCode.LG_TOOL_NOT_IN_ALLOWLIST
            self._log_action_audit(proposed_tool, caller_role, caller_id, False, code, reason, elapsed_ms, effective_untrusted)
            return {
                "allowed": False,
                "reason": reason,
                "reason_code": code.value,
                "t3_latency_ms": elapsed_ms,
            }

        # Authorization Rule 3: Tool Registry and RBAC / Capabilities Check
        if self.policy.tool_registry:
            tool_meta = self.policy.tool_registry.get_tool(proposed_tool)
            if tool_meta:
                # Required role enforcement
                if tool_meta.required_role and caller_role.lower() != "admin" and caller_role.lower() != tool_meta.required_role.lower():
                    elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                    if self.enable_telemetry and self.telemetry:
                        self.telemetry.record_action_block()
                    reason = f"RBAC Policy Blocked: Tool '{proposed_tool}' requires role '{tool_meta.required_role}' but caller has role '{caller_role}'."
                    code = SecurityReasonCode.LG_TOOL_ROLE_UNAUTHORIZED
                    self._log_action_audit(proposed_tool, caller_role, caller_id, False, code, reason, elapsed_ms, effective_untrusted)
                    return {
                        "allowed": False,
                        "reason": reason,
                        "reason_code": code.value,
                        "t3_latency_ms": elapsed_ms,
                    }

                # Role capabilities enforcement
                if self.policy.role_permissions and caller_role.lower() != "admin":
                    role_caps = self.policy.role_permissions.get(caller_role, [])
                    if "*" not in role_caps:
                        for cap in tool_meta.capabilities:
                            cap_val = cap.value if hasattr(cap, "value") else str(cap)
                            if cap_val not in role_caps and "*" not in role_caps:
                                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                                if self.enable_telemetry and self.telemetry:
                                    self.telemetry.record_action_block()
                                reason = f"RBAC Capability Blocked: Tool '{proposed_tool}' requires capability '{cap_val}' which is not granted to role '{caller_role}'."
                                code = SecurityReasonCode.LG_TOOL_CAPABILITY_UNAUTHORIZED
                                self._log_action_audit(proposed_tool, caller_role, caller_id, False, code, reason, elapsed_ms, effective_untrusted)
                                return {
                                    "allowed": False,
                                    "reason": reason,
                                    "reason_code": code.value,
                                    "t3_latency_ms": elapsed_ms,
                                }

                # Approval hook enforcement
                if tool_meta.requires_approval or (self.policy.approval_hook and tool_meta.risk_level in ("high", "critical")):
                    if self.policy.approval_hook:
                        ctx_obj = context or AuthorizationContext(caller_id=caller_id, caller_role=caller_role, is_untrusted=is_untrusted)
                        approved = self.policy.approval_hook(proposed_tool, tool_args, ctx_obj)
                        if not approved:
                            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                            if self.enable_telemetry and self.telemetry:
                                self.telemetry.record_action_block()
                            reason = f"Action Approval Required: Execution of high-impact tool '{proposed_tool}' was rejected by approval hook."
                            code = SecurityReasonCode.LG_TOOL_APPROVAL_REJECTED
                            self._log_action_audit(proposed_tool, caller_role, caller_id, False, code, reason, elapsed_ms, effective_untrusted)
                            return {
                                "allowed": False,
                                "reason": reason,
                                "reason_code": code.value,
                                "t3_latency_ms": elapsed_ms,
                            }
                    else:
                        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                        if self.enable_telemetry and self.telemetry:
                            self.telemetry.record_action_block()
                        reason = f"Action Approval Required: Tool '{proposed_tool}' requires explicit approval hook which is not configured."
                        code = SecurityReasonCode.LG_TOOL_APPROVAL_REQUIRED
                        self._log_action_audit(proposed_tool, caller_role, caller_id, False, code, reason, elapsed_ms, effective_untrusted)
                        return {
                            "allowed": False,
                            "reason": reason,
                            "reason_code": code.value,
                            "t3_latency_ms": elapsed_ms,
                        }

        # Mandatory Security Step 1: Verify tool arguments against active Canary tokens
        if self.policy.enable_canary_guard:
            canary_safe, canary_reason = self.canary.verify_action_arguments(proposed_tool, tool_args)
            if not canary_safe:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                if self.enable_telemetry and self.telemetry:
                    self.telemetry.record_action_block()
                code = SecurityReasonCode.LG_CANARY_LEAK
                self._log_action_audit(proposed_tool, caller_role, caller_id, False, code, canary_reason, elapsed_ms, effective_untrusted)
                return {
                    "allowed": False,
                    "reason": canary_reason,
                    "reason_code": code.value,
                    "t3_latency_ms": elapsed_ms,
                }

        # Mandatory Security Step 2: Validate structured tool arguments against injections, command chaining, and path traversal
        if isinstance(tool_args, dict) and tool_args:
            struct_res = self.structured_guard.validate_tool_arguments(
                tool_name=proposed_tool,
                arguments=tool_args,
                strict_shell_check=True,
            )
            if not struct_res["allowed"]:
                elapsed_ms = (time.perf_counter() - start_t) * 1000.0
                if self.enable_telemetry and self.telemetry:
                    self.telemetry.record_action_block()
                violations = struct_res.get("violations", [])
                v_lower = " ".join(violations).lower()
                if "ssrf" in v_lower or "loopback" in v_lower or "169.254" in v_lower or "metadata" in v_lower:
                    code = SecurityReasonCode.LG_TOOL_SSRF
                elif "traversal" in v_lower:
                    code = SecurityReasonCode.LG_TOOL_PATH_TRAVERSAL
                elif "command" in v_lower or "shell" in v_lower or "pipe" in v_lower or "chaining" in v_lower:
                    code = SecurityReasonCode.LG_TOOL_COMMAND_INJECTION
                elif "sql" in v_lower:
                    code = SecurityReasonCode.LG_TOOL_SQLI
                elif "depth" in v_lower or "element" in v_lower or "complexity" in v_lower:
                    code = SecurityReasonCode.LG_TOOL_PAYLOAD_LIMIT
                else:
                    code = SecurityReasonCode.LG_TOOL_ARG_INJECTION
                violations_str = "; ".join(violations)
                reason = f"Structured Output Policy Blocked: {violations_str}"
                self._log_action_audit(proposed_tool, caller_role, caller_id, False, code, reason, elapsed_ms, effective_untrusted)
                return {
                    "allowed": False,
                    "reason": reason,
                    "reason_code": code.value,
                    "t3_latency_ms": elapsed_ms,
                }

        # Whitelist override (Bypasses untrusted observation restriction for permitted tools)
        if proposed_tool in self.policy.whitelisted_tools:
            code = SecurityReasonCode.LG_WHITELISTED
            reason = "Whitelisted tool"
            self._log_action_audit(proposed_tool, caller_role, caller_id, True, code, reason, 0.001, effective_untrusted)
            return {"allowed": True, "reason": reason, "reason_code": code.value, "t3_latency_ms": 0.001}

        # Check custom high-stakes tools from policy
        if effective_untrusted and proposed_tool in self.policy.custom_high_stakes_tools:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            if self.enable_telemetry and self.telemetry:
                self.telemetry.record_action_block()
            reason = f"Action Firewall Blocked: Tool '{proposed_tool}' is designated as high-stakes by policy."
            code = SecurityReasonCode.LG_TOOL_HIGH_STAKES
            self._log_action_audit(proposed_tool, caller_role, caller_id, False, code, reason, elapsed_ms, effective_untrusted)
            return {
                "allowed": False,
                "reason": reason,
                "reason_code": code.value,
                "t3_latency_ms": elapsed_ms,
            }

        # Step 2: Validate against Action Firewall security policies
        allowed, reason, t3_ms = self.t3.validate_action(proposed_tool, tool_args, effective_untrusted)
        if not allowed and self.enable_telemetry and self.telemetry:
            self.telemetry.record_action_block()
        code = SecurityReasonCode.LG_ALLOWED if allowed else SecurityReasonCode.LG_TOOL_HIGH_STAKES
        self._log_action_audit(proposed_tool, caller_role, caller_id, allowed, code, reason, t3_ms, effective_untrusted)

        return {
            "allowed": allowed,
            "reason": reason,
            "reason_code": code.value,
            "t3_latency_ms": t3_ms,
        }

