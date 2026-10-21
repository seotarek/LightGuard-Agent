"""
LightGuard Audit Trail & Security Reason Codes.
Provides tamper-evident, structured audit events with normalized security reason codes
for enterprise compliance, SIEM ingestion, and automated incident response.
"""

import json
import threading
from collections import deque
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional


class SecurityReasonCode(str, Enum):
    """Normalized security reason codes across all inspection engines."""

    # Success / Allowed
    LG_OK = "LG_OK"
    LG_ALLOWED = "LG_ALLOWED"
    LG_WHITELISTED = "LG_WHITELISTED"

    # Prompt Injections & Obfuscations
    LG_PI_SYNTACTIC = "LG_PI_SYNTACTIC"
    LG_PI_SEMANTIC = "LG_PI_SEMANTIC"
    LG_PI_OVERRIDE = "LG_PI_OVERRIDE"
    LG_PI_DELIMITER = "LG_PI_DELIMITER"
    LG_OBFUSCATION_DETECTED = "LG_OBFUSCATION_DETECTED"
    LG_ADVERSARIAL_SUFFIX = "LG_ADVERSARIAL_SUFFIX"
    LG_THREAT_INTEL_MATCH = "LG_THREAT_INTEL_MATCH"

    # Canaries
    LG_CANARY_LEAK = "LG_CANARY_LEAK"
    LG_CANARY_TAMPER = "LG_CANARY_TAMPER"

    # Tool Authorization & RBAC
    LG_TOOL_EXPLICIT_DENY = "LG_TOOL_EXPLICIT_DENY"
    LG_TOOL_NOT_IN_ALLOWLIST = "LG_TOOL_NOT_IN_ALLOWLIST"
    LG_TOOL_NOT_REGISTERED = "LG_TOOL_NOT_REGISTERED"
    LG_TOOL_SCHEMA_INVALID = "LG_TOOL_SCHEMA_INVALID"
    LG_TOOL_ROLE_UNAUTHORIZED = "LG_TOOL_ROLE_UNAUTHORIZED"
    LG_TOOL_CAPABILITY_UNAUTHORIZED = "LG_TOOL_CAPABILITY_UNAUTHORIZED"
    LG_TOOL_APPROVAL_REJECTED = "LG_TOOL_APPROVAL_REJECTED"
    LG_TOOL_APPROVAL_REQUIRED = "LG_TOOL_APPROVAL_REQUIRED"
    LG_TOOL_HIGH_STAKES = "LG_TOOL_HIGH_STAKES"

    # Structured Argument Security
    LG_TOOL_SSRF = "LG_TOOL_SSRF"
    LG_TOOL_PATH_TRAVERSAL = "LG_TOOL_PATH_TRAVERSAL"
    LG_TOOL_RESOURCE_ROOT_VIOLATION = "LG_TOOL_RESOURCE_ROOT_VIOLATION"
    LG_TOOL_COMMAND_INJECTION = "LG_TOOL_COMMAND_INJECTION"
    LG_TOOL_SQLI = "LG_TOOL_SQLI"
    LG_TOOL_PAYLOAD_LIMIT = "LG_TOOL_PAYLOAD_LIMIT"
    LG_TOOL_ARG_INJECTION = "LG_TOOL_ARG_INJECTION"

    # RAG & Context
    LG_RAG_METADATA_INJECTION = "LG_RAG_METADATA_INJECTION"
    LG_RAG_BEACON = "LG_RAG_BEACON"
    LG_RAG_DOC_LIMIT = "LG_RAG_DOC_LIMIT"
    LG_RAG_UNTRUSTED_CONTENT = "LG_RAG_UNTRUSTED_CONTENT"

    # Model Context Protocol (MCP)
    LG_MCP_MSG_SIZE = "LG_MCP_MSG_SIZE"
    LG_MCP_TOOL_DENIED = "LG_MCP_TOOL_DENIED"
    LG_MCP_MALFORMED = "LG_MCP_MALFORMED"
    LG_MCP_RESPONSE_LEAK = "LG_MCP_RESPONSE_LEAK"

    # DLP / Privacy
    LG_DLP_SECRET_REDACTED = "LG_DLP_SECRET_REDACTED"


@dataclass
class AuditEvent:
    """Structured security audit event record."""

    event_id: str
    timestamp: float
    event_type: (
        str  # "observation", "action_verification", "mcp_request", "rag_ingest", "dlp_redact"
    )
    decision: str  # "ALLOW", "BLOCK", "REDACT", "WARN"
    reason_code: SecurityReasonCode
    reason: str
    rule_triggered: Optional[str] = None
    caller_role: Optional[str] = None
    caller_id: Optional[str] = None
    target_tool: Optional[str] = None
    latency_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Converts event to dictionary with serializable reason code."""
        d = asdict(self)
        d["reason_code"] = (
            self.reason_code.value if hasattr(self.reason_code, "value") else str(self.reason_code)
        )
        return d

    def to_json(self) -> str:
        """Converts event to serialized JSON string."""
        return json.dumps(self.to_dict())


class AuditLogger:
    """
    Thread-safe audit logger with bounded in-memory ring buffer
    and optional append-only JSON-lines file sink.
    """

    def __init__(self, max_events: int = 1000, file_path: Optional[str] = None):
        self.max_events = max_events
        self.file_path = file_path
        self._lock = threading.Lock()
        self._events: deque[AuditEvent] = deque(maxlen=max_events)

    def log(self, event: AuditEvent) -> None:
        """Appends an event to the in-memory buffer and writes to file if configured."""
        with self._lock:
            self._events.append(event)
            if self.file_path:
                try:
                    with open(self.file_path, "a", encoding="utf-8") as f:
                        f.write(event.to_json() + "\n")
                except OSError:
                    # Fail-safe: do not crash agent on local disk logging error
                    pass

    def get_events(
        self,
        limit: Optional[int] = None,
        event_type: Optional[str] = None,
    ) -> list[AuditEvent]:
        """Returns copies of audit events, optionally filtered by event type and limit."""
        with self._lock:
            events = list(self._events)

        if event_type:
            events = [e for e in events if e.event_type == event_type]

        if limit is not None and limit > 0:
            events = events[-limit:]

        return events

    def export_events(self) -> list[dict[str, Any]]:
        """Exports all events as a list of dictionaries."""
        with self._lock:
            return [e.to_dict() for e in self._events]

    def to_json_lines(self) -> str:
        """Exports events as newline-delimited JSON strings."""
        with self._lock:
            return "\n".join(e.to_json() for e in self._events)

    def clear(self) -> None:
        """Clears the in-memory event buffer."""
        with self._lock:
            self._events.clear()
