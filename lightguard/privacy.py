import dataclasses
import re
import time
from typing import Any, ClassVar


class RedactionResult(tuple):
    """Hybrid result container for DLP & PII redaction.

    Supports:
    1. Tuple unpacking: `cleaned, mapping, ms = guard.redact(text)`
    2. Dict item access: `res['redacted_text']`, `res['entities_found']`, `res['latency_ms']`, `res['entity_map']`
    3. Attribute access: `res.redacted_text`, `res.entity_map`, `res.latency_ms`, `res.entities_found`
    """

    def __new__(cls, redacted_text: str, entity_map: dict[str, str], latency_ms: float):
        return super().__new__(cls, (redacted_text, entity_map, latency_ms))

    @property
    def redacted_text(self) -> str:
        return self[0]

    @property
    def entity_map(self) -> dict[str, str]:
        return self[1]

    @property
    def latency_ms(self) -> float:
        return self[2]

    @property
    def entities_found(self) -> int:
        return len(self[1])

    def __getitem__(self, item: Any) -> Any:
        if isinstance(item, str):
            if item == "redacted_text":
                return self[0]
            elif item in ("entity_map", "entities", "mapping"):
                return self[1]
            elif item in ("latency_ms", "elapsed_ms"):
                return self[2]
            elif item == "entities_found":
                return len(self[1])
            raise KeyError(f"RedactionResult has no key '{item}'")
        return super().__getitem__(item)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def to_dict(self) -> dict[str, Any]:
        return {
            "redacted_text": self[0],
            "entity_map": self[1],
            "entities_found": len(self[1]),
            "latency_ms": self[2],
        }


@dataclasses.dataclass
class PIIDetectionResult:
    entity_type: str
    original_value: str
    redacted_value: str
    start_index: int
    end_index: int
    confidence: float


class PrivacyGuard:
    """
    Sub-millisecond Data Loss Prevention (DLP) & PII Redaction Engine.
    Detects and sanitizes secret credentials, API keys, private keys, credit cards (Luhn-verified),
    social security numbers, email addresses, and phone numbers before data enters LLM context
    or leaves through external tool calls.
    """

    # Secret / Credential patterns
    PATTERNS_SECRETS: ClassVar[dict[str, re.Pattern]] = {
        "OPENAI_KEY": re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b"),
        "ANTHROPIC_KEY": re.compile(r"\bsk-ant-api03-[A-Za-z0-9_-]{30,}\b"),
        "GOOGLE_API_KEY": re.compile(r"\bAIza[A-Za-z0-9_-]{35,40}\b"),
        "HUGGINGFACE_TOKEN": re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"),
        "STRIPE_KEY": re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{20,}\b"),
        "AWS_KEY_ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "GITHUB_TOKEN": re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})\b"),
        "SLACK_TOKEN": re.compile(r"\bxoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{20,}\b"),
        "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA )?PRIVATE KEY-----"),
        "JWT_TOKEN": re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    }

    # PII patterns
    PATTERNS_PII: ClassVar[dict[str, re.Pattern]] = {
        "EMAIL": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "IPV4": re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
        "CREDIT_CARD_CANDIDATE": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        "PHONE_NUMBER": re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    }

    @staticmethod
    def validate_luhn(card_number_str: str) -> bool:
        """Validates credit card checksum using the standard Luhn algorithm."""
        digits = [int(c) for c in card_number_str if c.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        total = 0
        reverse_digits = digits[::-1]
        for idx, digit in enumerate(reverse_digits):
            if idx % 2 == 1:
                doubled = digit * 2
                total += doubled - 9 if doubled > 9 else doubled
            else:
                total += digit
        return total % 10 == 0

    @classmethod
    def scan(cls, text: str) -> list[PIIDetectionResult]:
        """Scans text and returns all detected PII entities and secrets with positions."""
        results: list[PIIDetectionResult] = []

        # 1. Scan API keys & credentials
        for label, pattern in cls.PATTERNS_SECRETS.items():
            for match in pattern.finditer(text):
                val = match.group()
                results.append(
                    PIIDetectionResult(
                        entity_type=label,
                        original_value=val,
                        redacted_value=f"[REDACTED_{label}]",
                        start_index=match.start(),
                        end_index=match.end(),
                        confidence=0.99,
                    )
                )

        # 2. Scan standard PII
        for label, pattern in cls.PATTERNS_PII.items():
            for match in pattern.finditer(text):
                val = match.group()
                # Special validation for credit cards to eliminate false positives
                if label == "CREDIT_CARD_CANDIDATE":
                    if cls.validate_luhn(val):
                        results.append(
                            PIIDetectionResult(
                                entity_type="CREDIT_CARD",
                                original_value=val,
                                redacted_value="[REDACTED_CREDIT_CARD]",
                                start_index=match.start(),
                                end_index=match.end(),
                                confidence=0.98,
                            )
                        )
                else:
                    results.append(
                        PIIDetectionResult(
                            entity_type=label,
                            original_value=val,
                            redacted_value=f"[REDACTED_{label}]",
                            start_index=match.start(),
                            end_index=match.end(),
                            confidence=0.95,
                        )
                    )

        return results

    @classmethod
    def redact(
        cls,
        text: str,
        reversible: bool = True,
        counter_start: int = 1,
    ) -> RedactionResult:
        """
        Redacts all credentials and PII.
        If reversible=True, provides a token substitution mapping to restore the data later.
        Returns a RedactionResult (tuple of sanitized_text, reverse_mapping, elapsed_ms, supporting dict and attribute access).
        """
        start_t = time.perf_counter()
        detections = cls.scan(text)
        if not detections:
            elapsed_ms = (time.perf_counter() - start_t) * 1000.0
            return RedactionResult(text, {}, elapsed_ms)

        # Filter overlapping detections: prioritize earlier start and longer span
        sorted_by_span = sorted(detections, key=lambda d: (d.start_index, -(d.end_index - d.start_index)))
        non_overlapping: list[PIIDetectionResult] = []
        last_end = -1
        for d in sorted_by_span:
            if d.start_index >= last_end:
                non_overlapping.append(d)
                last_end = d.end_index

        # Sort detections in reverse order of appearance to replace without offsetting indices
        sorted_detections = sorted(non_overlapping, key=lambda d: d.start_index, reverse=True)

        mapping: dict[str, str] = {}
        cleaned = text
        token_counter = counter_start - 1

        for item in sorted_detections:
            token_counter += 1
            placeholder = (
                f"[LG_DLP_{item.entity_type}_{token_counter:03d}]"
                if reversible
                else item.redacted_value
            )
            cleaned = cleaned[:item.start_index] + placeholder + cleaned[item.end_index:]
            if reversible:
                mapping[placeholder] = item.original_value

        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        return RedactionResult(cleaned, mapping, elapsed_ms)

    @staticmethod
    def restore(redacted_text: str, mapping: dict[str, str]) -> str:
        """Restores redacted placeholders back to original values."""
        restored = redacted_text
        for placeholder, original in mapping.items():
            restored = restored.replace(placeholder, original)
        return restored

    @classmethod
    def redact_structured(
        cls, data: Any, reversible: bool = True
    ) -> tuple[Any, dict[str, str], float]:
        """Recursively scans and redacts PII/secrets inside nested dictionaries, lists, and strings."""
        start_t = time.perf_counter()
        combined_mapping: dict[str, str] = {}
        current_counter = [1]

        def _walk(node: Any) -> Any:
            if isinstance(node, str):
                res = cls.redact(node, reversible=reversible, counter_start=current_counter[0])
                current_counter[0] += len(res.entity_map)
                combined_mapping.update(res.entity_map)
                return res.redacted_text
            elif isinstance(node, dict):
                return {k: _walk(v) for k, v in node.items()}
            elif isinstance(node, list):
                return [_walk(item) for item in node]
            return node

        redacted_data = _walk(data)
        elapsed_ms = (time.perf_counter() - start_t) * 1000.0
        return redacted_data, combined_mapping, elapsed_ms

    @classmethod
    def restore_structured(cls, data: Any, mapping: dict[str, str]) -> Any:
        """Recursively restores redacted placeholders in nested structures back to original values."""
        def _walk(node: Any) -> Any:
            if isinstance(node, str):
                return cls.restore(node, mapping)
            elif isinstance(node, dict):
                return {k: _walk(v) for k, v in node.items()}
            elif isinstance(node, list):
                return [_walk(item) for item in node]
            return node

        return _walk(data)
