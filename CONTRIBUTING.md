# Contributing to LightGuard-Agent

We welcome contributions from security researchers, AI engineers, and systems architects to keep autonomous AI agents secure against adversarial attacks.

## Architectural Mandates

1. **Zero External Dependencies**:
   Core runtime modules in `lightguard/` MUST NOT import external third-party dependencies (e.g., PyTorch, transformers, pydantic, numpy). Everything must run on the hardened Python standard library.
2. **Sub-Millisecond Execution Budget**:
   Every added heuristic or sanitization rule must be benchmarked. The total evaluation latency for all 4 tiers combined must remain `< 0.2 ms`.
3. **Deterministic Defense**:
   All mitigation gates must be deterministic and testable without stochastic API calls.

## Developer Workflow

### 1. Environment Setup
```bash
git clone https://github.com/seotarek/LightGuard-Agent.git
cd LightGuard-Agent

# Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Running Test Suites & Benchmarks
```bash
# Run unit test suite (162 tests)
pytest tests/ -v

# Run adversarial benchmark suite
python -m benchmark.run_benchmark
```

### 3. Code Quality & Formatting
```bash
ruff check .
ruff format .
```

## Submitting Pull Requests

1. Fork the repo and create your feature branch: `git checkout -b feat/new-evasion-defense`.
2. Add comprehensive unit tests covering the new attack pattern and edge cases.
3. Ensure 100% of tests pass and no latency regressions occur.
4. Open a pull request with an explanation of the threat vector and benchmark comparison.
