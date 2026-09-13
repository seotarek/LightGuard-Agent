import re
import time
from typing import Dict, Any, List, Tuple

class Tier1SyntacticSanitizer:
    """
    Tier 1: High-speed deterministic syntactic and boundary sanitization.
    Escapes dangerous delimiters, neutralizes known imperative attack patterns,
    and isolates untrusted external data into strict XML-style observation blocks.
    """
    KNOWN_INJECTION_PATTERNS = [
        re.compile(r'(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b'),
        re.compile(r'(?i)\bdisregard\s+(the\s+)?(system|previous|prior)\s+(prompt|instructions)\b'),
        re.compile(r'(?i)\byou\s+are\s+now\s+(a\s+)?new\s+(ai|assistant|model)\b'),
        re.compile(r'(?i)\bsystem\s*:\s*override\b'),
        re.compile(r'(?i)\bpriority\s+command\s*:\s*\b'),
        re.compile(r'(?i)\bprint\s+(all\s+)?(hidden|secret|api|key|environment|developer)\b'),
        re.compile(r'(?i)\bforward\s+(all\s+)?(data|secrets|messages|credentials)\b'),
        re.compile(r'(?i)\bexecute\s+command\s*:\s*\b'),
        re.compile(r'(?i)\badmin\s+mode\s+enabled\b'),
        re.compile(r'(?i)\b(exec_bash|drop_table|delete_file|execute_sql|transfer_funds)\s*\(')
    ]

    DELIMITER_TAGS = [
        ("```system", "```escaped_system"),
        ("<system>", "&lt;system&gt;"),
        ("</system>", "&lt;/system&gt;"),
        ("<im_start>", "&lt;im_start&gt;"),
        ("<im_end>", "&lt;im_end&gt;"),
    ]

    @staticmethod
    def sanitize(raw_text: str) -> Tuple[str, bool, float]:
        start_t = time.perf_counter()
        flagged = False
        cleaned = raw_text

        # Check against deterministic injection signatures
        for pattern in Tier1SyntacticSanitizer.KNOWN_INJECTION_PATTERNS:
            if pattern.search(cleaned):
                flagged = True
                cleaned = pattern.sub("[REDACTED_INJECTION_DIRECTIVE]", cleaned)

        # Delimiter neutralization
        for tag, replacement in Tier1SyntacticSanitizer.DELIMITER_TAGS:
            if tag in cleaned.lower():
                flagged = True
                pattern = re.compile(re.escape(tag), re.IGNORECASE)
                cleaned = pattern.sub(replacement, cleaned)

        # Encapsulate untrusted data into strict bounded observation tags
        bounded_content = f"<untrusted_observation origin='external_tool'>\n{cleaned}\n</untrusted_observation>"
        
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        return bounded_content, flagged, elapsed_ms


class Tier2SemanticClassifier:
    """
    Tier 2: Lightweight Semantic Intent Analyzer (Sub-10ms).
    Extracts imperative intent density, instruction hijacking cues,
    and exfiltration semantics without full LLM generation overhead.
    """
    IMPERATIVE_VERBS = {
        "send", "email", "delete", "post", "curl", "fetch", "forward",
        "drop", "exfiltrate", "transmit", "modify", "update", "execute",
        "transfer", "leak", "dump"
    }
    TARGET_ENTITIES = {
        "password", "secret", "token", "credential", "api_key", "database",
        "private", "auth", "session", "user_data", "cookie", "account",
        "funds", "keys", "table"
    }
    AUTHORITY_OVERRIDE_TERMS = {
        "emergency", "urgent", "administrator", "root", "developer_mode",
        "override", "priority_command", "jailbreak", "instruction"
    }

    @staticmethod
    def analyze(text: str) -> Tuple[float, bool, float]:
        start_t = time.perf_counter()
        lowered = text.lower()
        tokens = set(re.findall(r'\b\w+\b', lowered))

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
    HIGH_STAKES_TOOLS = {
        "send_email", "delete_file", "drop_table", "execute_sql",
        "http_post", "transfer_funds", "modify_permissions", "exec_bash"
    }

    @staticmethod
    def validate_action(
        proposed_tool: str,
        tool_args: Dict[str, Any],
        is_observation_untrusted: bool
    ) -> Tuple[bool, str, float]:
        start_t = time.perf_counter()
        
        # Policy 1: Block High-Stakes tools automatically if triggered by untrusted observation
        if is_observation_untrusted and proposed_tool in Tier3ActionFirewall.HIGH_STAKES_TOOLS:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            return False, f"Action Firewall Blocked: Tool '{proposed_tool}' is high-stakes and untrusted context was detected.", elapsed_ms

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
    Combines Tier 1, Tier 2, and Tier 3 into an integrated defense pipeline.
    """
    def __init__(self):
        self.t1 = Tier1SyntacticSanitizer()
        self.t2 = Tier2SemanticClassifier()
        self.t3 = Tier3ActionFirewall()

    def process_observation(self, raw_observation: str) -> Dict[str, Any]:
        sanitized_text, t1_flagged, t1_ms = self.t1.sanitize(raw_observation)
        risk_score, t2_flagged, t2_ms = self.t2.analyze(raw_observation)

        is_untrusted = t1_flagged or t2_flagged

        return {
            "sanitized_observation": sanitized_text,
            "t1_flagged": t1_flagged,
            "t2_risk_score": risk_score,
            "is_untrusted": is_untrusted,
            "total_latency_ms": t1_ms + t2_ms,
            "latency_breakdown": {"t1_ms": t1_ms, "t2_ms": t2_ms}
        }

    def verify_action(self, proposed_tool: str, tool_args: Dict[str, Any], is_untrusted: bool) -> Dict[str, Any]:
        allowed, reason, t3_ms = self.t3.validate_action(proposed_tool, tool_args, is_untrusted)
        return {
            "allowed": allowed,
            "reason": reason,
            "t3_latency_ms": t3_ms
        }
