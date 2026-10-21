# LightGuard-Agent Enterprise AI Security Platform Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform LightGuard-Agent into a production-grade, best-in-class, enterprise AI security platform with centralized tool authorization, deep recursive argument inspection, multi-provider async streaming protection, MCP security, RAG protection, DLP, threat intelligence, and reproducible benchmarks.

**Architecture:** A centralized, modular defense pipeline enforcing: Untrusted Input → Size/Schema Validation → Safe Normalization → Threat Detection → Context/Trust Evaluation → Centralized Policy & Authorization Engine → Controlled Execution → Output Inspection → DLP & Exfiltration Checks → Structured Auditing & Metrics.

**Tech Stack:** Python 3.10+, zero core external runtime dependencies (standard library only), pytest, pytest-cov, ruff, uv.

## Global Constraints
- Zero external runtime dependencies for the core library.
- Sub-millisecond latency for hot-path syntactic and rule checks.
- 100% backward compatibility for existing public APIs.
- Fail-closed security on authorization or inspection errors.
- Never leak sensitive credentials, canaries, or raw payloads in logs or exceptions.

---

### Task 1: Centralized Policy & Tool Authorization Engine
**Files:**
- Modify: `lightguard/policy.py`
- Modify: `lightguard/core.py`
- Test: `tests/test_policy_engine_advanced.py`

**Interfaces:**
- Produces: `PolicyEngine`, `ToolCapability`, `ToolPolicyRegistry`, `ToolMetadata`, `AuthorizationContext`, `PolicyPrecedence`
- Consumes: `SecurityPolicyConfig`, `LightGuardAgent`

- [ ] **Step 1: Write the failing test for advanced policy authorization**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement ToolCapability, ToolPolicyRegistry, RBAC, and approval hooks in policy.py and core.py**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes**

---

### Task 2: Deep Recursive Structured Argument & SSRF/Path Traversal Guard
**Files:**
- Modify: `lightguard/structured.py`
- Test: `tests/test_structured_deep_validation.py`

**Interfaces:**
- Produces: `StructuredOutputGuard.validate_tool_arguments()`, `SSRFValidator`, `PathValidator` with cycle detection, max depth, max elements, and URL/SSRF/SQLi heuristics
- Consumes: `lightguard/core.py`

- [ ] **Step 1: Write failing test for cycle detection, SSRF, SQLi, and path traversal**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement cycle detection, bounded recursion, SSRF and command checks in structured.py**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes**

---

### Task 3: Multi-Provider LLM Integration & Streamed Tool Call Parsing
**Files:**
- Modify: `lightguard/wrapper.py`
- Test: `tests/test_wrapper_multi_provider.py`

**Interfaces:**
- Produces: Robust JSON argument unmarshaling in `_inspect_result`, `LightGuardStreamWrapper`, `LightGuardAsyncStreamWrapper`, multi-tool call validation
- Consumes: `LightGuardAgent.verify_action`, `StructuredOutputGuard`

- [ ] **Step 1: Write failing test for streaming tool call JSON parsing and multi-tool parallel calls**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement JSON argument unmarshaling and parallel tool call inspection in wrapper.py**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes**

---

### Task 4: Advanced RAG Context & Metadata Security
**Files:**
- Modify: `lightguard/rag.py`
- Test: `tests/test_rag_advanced_security.py`

**Interfaces:**
- Produces: `RAGContextShield.sanitize_document()`, metadata validation, source trust levels, markdown beacon exfiltration detection
- Consumes: `LightGuardAgent`, `CanaryGuard`

- [ ] **Step 1: Write failing test for metadata injection, source trust, and markdown beacons in RAG**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement metadata inspection, source trust levels, and beacon detection in rag.py**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes**

---

### Task 5: Hardened MCP Gateway & Capability Discovery Filtering
**Files:**
- Modify: `lightguard/mcp_gateway.py`
- Modify: `lightguard/mcp.py`
- Test: `tests/test_mcp_hardened.py`

**Interfaces:**
- Produces: `MCPSecurityGateway` with `tools/list` capability filtering, message size limits, request ID tracking, and response inspection
- Consumes: `PolicyEngine`, `LightGuardAgent`

- [ ] **Step 1: Write failing test for MCP tools/list filtering, message size limits, and response inspection**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement capability discovery filtering and bounds in mcp_gateway.py**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes**

---

### Task 6: DLP, Secret Detection & Canary Registry Lifecycle
**Files:**
- Modify: `lightguard/privacy.py`
- Modify: `lightguard/canary.py`
- Test: `tests/test_privacy_lifecycle.py`

**Interfaces:**
- Produces: Extended secret patterns (Google Cloud, HuggingFace, Stripe), structured content redaction, Canary TTL expiration & cleanup
- Consumes: `RedactionResult`

- [ ] **Step 1: Write failing test for structured redaction and canary TTL cleanup**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement structured redaction and TTL cache in privacy.py and canary.py**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes**

---

### Task 7: Structured Audit Trail & Reason Codes
**Files:**
- Modify: `lightguard/telemetry.py`
- Create: `lightguard/audit.py`
- Test: `tests/test_audit_trail.py`

**Interfaces:**
- Produces: `AuditEvent`, `AuditLogger`, `SecurityReasonCode` enum, bounded in-memory audit log, JSONL exporter
- Consumes: `SecurityTelemetryCollector`, `LightGuardAgent`

- [ ] **Step 1: Write failing test for structured audit events and reason codes**
- [ ] **Step 2: Run test to verify it fails**
- [ ] **Step 3: Implement AuditEvent, AuditLogger, and reason codes in lightguard/audit.py**
- [ ] **Step 4: Run test to verify it passes**
- [ ] **Step 5: Commit changes**

---

### Task 8: Public API Exports, Documentation, Benchmarks & Smoke Test
**Files:**
- Modify: `lightguard/__init__.py`
- Modify: `README.md`
- Test: `tests/test_smoke_install.py`

**Interfaces:**
- Produces: Clean public exports, verified README examples, reproducible benchmark commands
- Consumes: All modules

- [ ] **Step 1: Run comprehensive test suite and verify 100% pass rate and >80% coverage**
- [ ] **Step 2: Build package wheel and run clean install smoke test**
- [ ] **Step 3: Update documentation and README with verified examples**
- [ ] **Step 4: Commit and push changes**
