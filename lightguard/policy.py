import contextlib
import contextvars
import dataclasses
import enum
import json
import re
from typing import Any, Optional


class PolicyProfile(str, enum.Enum):
    STRICT = "strict"          # Financial, medical, high-security infrastructure
    BALANCED = "balanced"      # Standard production deployment (Default)
    PERMISSIVE = "permissive"  # Telemetry, auditing, monitoring mode (no active blocks)


class AuthorizationMode(str, enum.Enum):
    PRODUCTION_SECURE = "production_secure"
    STRICT = "strict"
    COMPATIBILITY = "compatibility"
    PERMISSIVE = "permissive"


def validate_json_schema(schema: Any, data: Any) -> tuple[bool, Optional[str]]:
    """Pure-Python standard-library JSON schema validator.

    Validates types, required fields, properties, additionalProperties, array items,
    enum, numeric bounds (minimum, maximum), string constraints (minLength, maxLength, pattern),
    and array bounds (minItems, maxItems).
    Rejects malformed or non-dictionary schema specifications.
    """
    if not isinstance(schema, dict):
        return False, "Invalid schema: schema must be a dictionary"

    expected_type = schema.get("type")
    if expected_type:
        type_checks = {
            "string": lambda d: isinstance(d, str),
            "number": lambda d: isinstance(d, (int, float)) and not isinstance(d, bool),
            "integer": lambda d: isinstance(d, int) and not isinstance(d, bool),
            "boolean": lambda d: isinstance(d, bool),
            "array": lambda d: isinstance(d, list),
            "object": lambda d: isinstance(d, dict),
            "null": lambda d: d is None,
        }
        check_fn = type_checks.get(expected_type)
        if check_fn and not check_fn(data):
            actual_type = type(data).__name__
            return False, f"Type mismatch: expected '{expected_type}', got '{actual_type}'"

    # Enum constraint
    if "enum" in schema:
        allowed_enum = schema["enum"]
        if isinstance(allowed_enum, (list, tuple, set)) and data not in allowed_enum:
            return False, f"Value '{data}' is not in allowed enum values: {list(allowed_enum)}"

    # Numeric bounds
    if isinstance(data, (int, float)) and not isinstance(data, bool):
        if "minimum" in schema and data < schema["minimum"]:
            return False, f"Value {data} is less than minimum {schema['minimum']}"
        if "maximum" in schema and data > schema["maximum"]:
            return False, f"Value {data} is greater than maximum {schema['maximum']}"

    # String constraints
    if isinstance(data, str):
        if "minLength" in schema and len(data) < schema["minLength"]:
            return False, f"String length {len(data)} is less than minLength {schema['minLength']}"
        if "maxLength" in schema and len(data) > schema["maxLength"]:
            return False, f"String length {len(data)} is greater than maxLength {schema['maxLength']}"
        if "pattern" in schema:
            try:
                if not re.search(schema["pattern"], data):
                    return False, f"String '{data}' does not match pattern: {schema['pattern']}"
            except re.error as e:
                return False, f"Invalid regex pattern in schema: {e}"

    # Object properties & required fields
    if isinstance(data, dict):
        required_fields = schema.get("required", [])
        if isinstance(required_fields, (list, tuple, set)):
            for req in required_fields:
                if req not in data:
                    return False, f"Missing required property: '{req}'"

        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False and isinstance(properties, dict):
            for key in data:
                if key not in properties:
                    return False, f"Additional property '{key}' not allowed by schema"

        if isinstance(properties, dict):
            for key, prop_schema in properties.items():
                if key in data and isinstance(prop_schema, dict):
                    ok, err = validate_json_schema(prop_schema, data[key])
                    if not ok:
                        return False, f"Property '{key}': {err}"

    # Array items & bounds
    elif isinstance(data, list):
        if "minItems" in schema and len(data) < schema["minItems"]:
            return False, f"Array length {len(data)} is less than minItems {schema['minItems']}"
        if "maxItems" in schema and len(data) > schema["maxItems"]:
            return False, f"Array length {len(data)} is greater than maxItems {schema['maxItems']}"

        items_schema = schema.get("items")
        if isinstance(items_schema, dict):
            for i, item in enumerate(data):
                ok, err = validate_json_schema(items_schema, item)
                if not ok:
                    return False, f"Array items at index [{i}]: {err}"

    return True, None


class ToolCapability(str, enum.Enum):
    FS_READ = "fs:read"
    FS_WRITE = "fs:write"
    SHELL_EXEC = "shell:exec"
    NETWORK_OUTBOUND = "net:outbound"
    DB_QUERY = "db:query"
    SYSTEM_ADMIN = "system:admin"
    CUSTOM = "custom"


@dataclasses.dataclass
class ToolMetadata:
    name: str
    description: str = ""
    capabilities: set[Any] = dataclasses.field(default_factory=set)
    risk_level: str = "low"  # low, medium, high, critical
    required_role: str = ""  # e.g. "admin", "operator"
    requires_approval: bool = False
    parameters_schema: Optional[dict[str, Any]] = None

    def __post_init__(self):
        # Convert any string capabilities to ToolCapability or keep string
        norm_caps = set()
        for cap in self.capabilities:
            if isinstance(cap, ToolCapability):
                norm_caps.add(cap)
            elif isinstance(cap, str):
                try:
                    norm_caps.add(ToolCapability(cap))
                except ValueError:
                    norm_caps.add(cap)
            else:
                norm_caps.add(cap)
        self.capabilities = norm_caps


class ToolPolicyRegistry:
    """Central registry for tool capabilities, risk profiles, and RBAC requirements."""

    def __init__(self):
        self._tools: dict[str, ToolMetadata] = {}

    def register_tool(self, metadata: ToolMetadata) -> None:
        self._tools[metadata.name] = metadata

    register = register_tool

    def get_tool(self, name: str) -> Optional[ToolMetadata]:
        return self._tools.get(name)

    def has_capability(self, tool_name: str, capability: Any) -> bool:
        tool = self._tools.get(tool_name)
        if not tool:
            return False
        if isinstance(capability, str):
            try:
                cap_enum = ToolCapability(capability)
                return cap_enum in tool.capabilities or capability in tool.capabilities
            except ValueError:
                return capability in tool.capabilities
        return capability in tool.capabilities

    def list_tools(self, caller_role: str = "") -> list[ToolMetadata]:
        """Returns tools accessible by caller_role. Empty role or admin gets all."""
        if not caller_role or caller_role.lower() == "admin":
            return list(self._tools.values())

        accessible = []
        for tool in self._tools.values():
            if not tool.required_role or tool.required_role.lower() == caller_role.lower():
                accessible.append(tool)
        return accessible


@dataclasses.dataclass
class AuthorizationContext:
    caller_id: str = ""
    caller_role: str = "user"
    is_untrusted: bool = False
    session_id: str = ""
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)


current_authorization_context: contextvars.ContextVar[Optional[AuthorizationContext]] = contextvars.ContextVar(
    "current_authorization_context", default=None
)


def get_current_authorization_context() -> Optional[AuthorizationContext]:
    """Retrieve the active thread-local/coroutine-local authorization context."""
    return current_authorization_context.get()


@contextlib.contextmanager
def authorization_context(ctx: Optional[AuthorizationContext]):
    """Context manager for scoping caller identity and roles to async tasks or threads."""
    token = current_authorization_context.set(ctx)
    try:
        yield ctx
    finally:
        current_authorization_context.reset(token)


@dataclasses.dataclass
class SecurityPolicyConfig:
    profile: PolicyProfile = PolicyProfile.BALANCED
    authorization_mode: AuthorizationMode = AuthorizationMode.PRODUCTION_SECURE
    risk_threshold: float = 0.50
    block_on_untrusted: bool = True
    enable_obfuscation_shield: bool = True
    enable_canary_guard: bool = True
    enable_dlp_redaction: bool = False
    custom_high_stakes_tools: list[str] = dataclasses.field(default_factory=list)
    whitelisted_tools: list[str] = dataclasses.field(default_factory=list)
    allowed_tools: Optional[list[str]] = None
    denied_tools: list[str] = dataclasses.field(default_factory=list)
    require_tool_registration: bool = False
    enable_adversarial_suffix_detector: bool = True
    enable_threat_intel_matcher: bool = True
    tool_registry: Optional[ToolPolicyRegistry] = None
    role_permissions: dict[str, list[str]] = dataclasses.field(default_factory=dict)
    approval_hook: Optional[Any] = None  # Callable[[str, dict, AuthorizationContext], bool]
    resource_roots: list[str] = dataclasses.field(default_factory=list)
    allowed_url_schemes: list[str] = dataclasses.field(default_factory=lambda: ["http", "https"])
    audit_logger: Optional[Any] = None

    @classmethod
    def strict(cls) -> "SecurityPolicyConfig":
        """Pre-configured high-security profile."""
        return cls(
            profile=PolicyProfile.STRICT,
            authorization_mode=AuthorizationMode.STRICT,
            require_tool_registration=True,
            risk_threshold=0.35,
            block_on_untrusted=True,
            enable_obfuscation_shield=True,
            enable_canary_guard=True,
            enable_dlp_redaction=True,
        )

    @classmethod
    def balanced(cls) -> "SecurityPolicyConfig":
        """Default balanced production profile."""
        return cls(
            profile=PolicyProfile.BALANCED,
            authorization_mode=AuthorizationMode.PRODUCTION_SECURE,
            risk_threshold=0.50,
            block_on_untrusted=True,
            enable_obfuscation_shield=True,
            enable_canary_guard=True,
            enable_dlp_redaction=False,
        )

    @classmethod
    def permissive(cls) -> "SecurityPolicyConfig":
        """Observability and auditing only profile; flags without blocking."""
        return cls(
            profile=PolicyProfile.PERMISSIVE,
            authorization_mode=AuthorizationMode.PERMISSIVE,
            risk_threshold=0.70,
            block_on_untrusted=False,
            enable_obfuscation_shield=True,
            enable_canary_guard=True,
            enable_dlp_redaction=False,
        )

    @classmethod
    def compatibility(cls) -> "SecurityPolicyConfig":
        """Permissive execution compatibility profile for legacy workloads allowing unconstrained tools."""
        return cls(
            profile=PolicyProfile.BALANCED,
            authorization_mode=AuthorizationMode.COMPATIBILITY,
            risk_threshold=0.50,
            block_on_untrusted=True,
            enable_obfuscation_shield=True,
            enable_canary_guard=True,
            enable_dlp_redaction=False,
        )

    @classmethod
    def from_profile(cls, profile: Any) -> "SecurityPolicyConfig":
        """Instantiate pre-configured policy from PolicyProfile enum or string name."""
        if isinstance(profile, str):
            try:
                p = PolicyProfile(profile.lower())
            except ValueError:
                p = PolicyProfile.BALANCED
        elif isinstance(profile, PolicyProfile):
            p = profile
        else:
            p = PolicyProfile.BALANCED

        if p == PolicyProfile.STRICT:
            return cls.strict()
        elif p == PolicyProfile.PERMISSIVE:
            return cls.permissive()
        return cls.balanced()

    @property
    def custom_high_stakes(self) -> Any:
        """Set-like proxy allowing .add() and .remove() on custom_high_stakes_tools."""
        class ToolsSetProxy:
            def __init__(self, target_list: list[str]):
                self._list = target_list

            def add(self, item: str) -> None:
                if item not in self._list:
                    self._list.append(item)

            def remove(self, item: str) -> None:
                if item in self._list:
                    self._list.remove(item)

            def discard(self, item: str) -> None:
                if item in self._list:
                    self._list.remove(item)

            def __contains__(self, item: str) -> bool:
                return item in self._list

            def __iter__(self):
                return iter(self._list)

            def __len__(self) -> int:
                return len(self._list)

            def __repr__(self) -> str:
                return repr(set(self._list))

        return ToolsSetProxy(self.custom_high_stakes_tools)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityPolicyConfig":
        profile_str = data.get("profile", "balanced").lower()
        try:
            profile = PolicyProfile(profile_str)
        except ValueError:
            profile = PolicyProfile.BALANCED

        auth_mode_str = data.get("authorization_mode", "production_secure").lower()
        try:
            auth_mode = AuthorizationMode(auth_mode_str)
        except ValueError:
            auth_mode = AuthorizationMode.PRODUCTION_SECURE

        return cls(
            profile=profile,
            authorization_mode=auth_mode,
            risk_threshold=float(data.get("risk_threshold", 0.50)),
            block_on_untrusted=bool(data.get("block_on_untrusted", True)),
            enable_obfuscation_shield=bool(data.get("enable_obfuscation_shield", True)),
            enable_canary_guard=bool(data.get("enable_canary_guard", True)),
            enable_dlp_redaction=bool(data.get("enable_dlp_redaction", False)),
            custom_high_stakes_tools=list(data.get("custom_high_stakes_tools", [])),
            whitelisted_tools=list(data.get("whitelisted_tools", [])),
            allowed_tools=list(data["allowed_tools"]) if data.get("allowed_tools") is not None else None,
            denied_tools=list(data.get("denied_tools", [])),
            require_tool_registration=bool(data.get("require_tool_registration", False)),
            enable_adversarial_suffix_detector=bool(data.get("enable_adversarial_suffix_detector", True)),
            enable_threat_intel_matcher=bool(data.get("enable_threat_intel_matcher", True)),
        )

    @classmethod
    def from_json(cls, json_str_or_path: str) -> "SecurityPolicyConfig":
        """Loads configuration from JSON string or file path."""
        try:
            with open(json_str_or_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = json.loads(json_str_or_path)
        return cls.from_dict(data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile.value,
            "authorization_mode": self.authorization_mode.value,
            "risk_threshold": self.risk_threshold,
            "block_on_untrusted": self.block_on_untrusted,
            "enable_obfuscation_shield": self.enable_obfuscation_shield,
            "enable_canary_guard": self.enable_canary_guard,
            "enable_dlp_redaction": self.enable_dlp_redaction,
            "custom_high_stakes_tools": self.custom_high_stakes_tools,
            "whitelisted_tools": self.whitelisted_tools,
            "allowed_tools": self.allowed_tools,
            "denied_tools": self.denied_tools,
            "require_tool_registration": self.require_tool_registration,
            "enable_adversarial_suffix_detector": self.enable_adversarial_suffix_detector,
            "enable_threat_intel_matcher": self.enable_threat_intel_matcher,
        }
