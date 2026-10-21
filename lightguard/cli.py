"""Command Line Interface (CLI) for LightGuard-Agent.

Subcommands:
- scan: Inspect and sanitize input for indirect prompt injection
- redact: Redact PII, credit cards (Luhn validated), and API keys
- rag-scan: Inspect retrieved RAG chunks and drop poisoned documents
- metrics: Export Prometheus metrics to stdout
- audit / redteam: Run automated penetration testing suite
- benchmark: Run empirical latency and mitigation benchmark
- report: Generate executive compliance audit report (OWASP & MITRE ATLAS)
- mcp-gateway: Run interactive stdio proxy for upstream MCP servers
- version: Print version and DOI
"""

import argparse
import json
import sys
from pathlib import Path

from lightguard.core import LightGuardAgent


def cmd_scan(args: argparse.Namespace) -> int:
    text = args.text
    if not text and not sys.stdin.isatty():
        text = sys.stdin.read()
    if not text:
        sys.stderr.write("Error: No text provided. Pass text as argument or via stdin.\n")
        return 1

    guard = LightGuardAgent()
    res = guard.process_observation(text)

    print("=" * 60)
    print("🛡️  LightGuard-Agent Inspection Report")
    print("=" * 60)
    print(f"Status           : {'🚨 UNTRUSTED / SUSPICIOUS (ATTACK DETECTED)' if res['is_untrusted'] else '✅ CLEAN / BENIGN (SAFE)'}")
    print(f"Risk Score       : {res['risk_score']:.2f} / 1.00")
    print(f"Engine Latency   : {res['latency_ms']:.4f} ms")
    if res["threat_categories"]:
        print("Threat Categories:", ", ".join(res["threat_categories"]))
    print("-" * 60)
    print("Sanitized Output Preview:")
    print(res["sanitized_observation"][:300])
    print("=" * 60)
    return 0 if not res["is_untrusted"] else 2


def cmd_redact(args: argparse.Namespace) -> int:
    text = args.text
    if not text and not sys.stdin.isatty():
        text = sys.stdin.read()
    if not text:
        sys.stderr.write("Error: No text provided to redact.\n")
        return 1

    from lightguard.privacy import PrivacyGuard
    guard = PrivacyGuard()
    res = guard.redact(text, reversible=not args.irreversible)

    print("=" * 60)
    print("🔒 LightGuard-Agent DLP & PII Redaction")
    print("=" * 60)
    print(f"Entities Redacted: {res['entities_found']}")
    print(f"Latency          : {res['latency_ms']:.4f} ms")
    print("-" * 60)
    print(res["redacted_text"])
    print("=" * 60)
    return 0


def cmd_rag_scan(args: argparse.Namespace) -> int:
    text = args.text
    if not text and not sys.stdin.isatty():
        text = sys.stdin.read()
    if not text:
        sys.stderr.write("Error: No text provided.\n")
        return 1

    from lightguard.rag import RAGContextShield
    shield = RAGContextShield()
    res = shield.sanitize_chunk(text)

    print("=" * 60)
    print("📚 LightGuard-Agent RAG Chunk Poisoning Scan")
    print("=" * 60)
    print(f"Poisoning Detected : {'🚨 YES (UNTRUSTED)' if res.is_poisoned else '✅ NO (SAFE)'}")
    print(f"Risk Score         : {res.risk_score:.2f} / 1.00")
    print(f"Latency            : {res.latency_ms:.4f} ms")
    if res.detected_threats:
        print("Threats Identified :", ", ".join(res.detected_threats))
    print("-" * 60)
    print("Sanitized Chunk Preview:")
    print(res.sanitized_text[:300])
    print("=" * 60)
    return 0 if not res.is_poisoned else 2


def cmd_metrics(args: argparse.Namespace) -> int:
    from lightguard.telemetry import SecurityTelemetryCollector
    collector = SecurityTelemetryCollector.get_instance()
    sys.stdout.write(collector.export_prometheus())
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    from lightguard.reporting import ComplianceReportGenerator
    gen = ComplianceReportGenerator()
    if args.format == "json":
        out = json.dumps(gen.generate_audit_data(), indent=2)
    else:
        out = gen.generate_html_report()

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        print(f"✅ Compliance report successfully saved to: {args.output}")
    else:
        sys.stdout.write(out + "\n")
    return 0


def cmd_mcp_gateway(args: argparse.Namespace) -> int:
    from lightguard.mcp_gateway import run_stdio_gateway
    if not args.cmd:
        sys.stderr.write("Error: Must provide command to run upstream MCP server.\n")
        return 1
    run_stdio_gateway(args.cmd)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    from lightguard.redteam.engine import run_redteam_audit
    audit = run_redteam_audit()
    print("=" * 65)
    print("⚔️  LightGuard-Agent Automated Adversarial Red-Team Audit")
    print("=" * 65)
    print(f"Total Vectors Audited   : {audit['total_vectors']}")
    print(f"Vectors Mitigated       : {audit['mitigated']}")
    print(f"Defense Rate            : {audit['defense_rate_pct']:.1f}%")
    print(f"False Positive Rate     : {audit['false_positive_rate_pct']:.1f}%")
    print(f"Mean Mitigation Latency : {audit['mean_latency_ms']:.4f} ms")
    print("=" * 65)
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    import time
    guard = LightGuardAgent()
    rounds = 100
    t0 = time.perf_counter()
    for _ in range(rounds):
        guard.process_observation("Normal benign status report.")
    elapsed_ms = ((time.perf_counter() - t0) / rounds) * 1000.0
    print("=" * 60)
    print(f"🚀 LightGuard-Agent Benchmark ({rounds} rounds)")
    print(f"Mean Latency: {elapsed_ms:.4f} ms per observation")
    print("=" * 60)
    return 0


def cmd_version(args: argparse.Namespace) -> int:
    from lightguard import __version__
    print(f"LightGuard-Agent v{__version__}")
    print("A Lightweight Defense Architecture Against Indirect Prompt Injection")
    print("Permanent DOI: https://doi.org/10.5281/zenodo.22731104")
    print("Author: Tarek Mohamed (seotarek@gmail.com)")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="lightguard",
        description="LightGuard-Agent: Sub-millisecond defense against Indirect Prompt Injection.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # scan
    scan_p = subparsers.add_parser("scan", help="Scan and sanitize text for prompt injection")
    scan_p.add_argument("text", nargs="?", default="", help="Text to scan")

    # redact
    redact_p = subparsers.add_parser("redact", help="Redact PII, credit cards, and API keys")
    redact_p.add_argument("text", nargs="?", default="", help="Text to redact")
    redact_p.add_argument("--irreversible", action="store_true", help="Mask irreversibly")

    # rag-scan
    rag_p = subparsers.add_parser("rag-scan", help="Scan a RAG retrieval chunk for indirect injection")
    rag_p.add_argument("text", nargs="?", default="", help="RAG chunk text to scan")

    # metrics
    subparsers.add_parser("metrics", help="Export Prometheus telemetry metrics")

    # report
    report_p = subparsers.add_parser("report", help="Generate executive compliance audit report")
    report_p.add_argument("--format", choices=["html", "json"], default="html", help="Report format")
    report_p.add_argument("--output", "-o", help="Filepath to save report")

    # mcp-gateway
    mcp_p = subparsers.add_parser("mcp-gateway", help="Run standalone MCP security gateway")
    mcp_p.add_argument("cmd", nargs=argparse.REMAINDER, help="Upstream MCP server command")

    # audit / redteam
    subparsers.add_parser("audit", help="Run automated adversarial red-team penetration audit")
    subparsers.add_parser("redteam", help="Alias for audit")

    # benchmark
    subparsers.add_parser("benchmark", help="Run empirical benchmark suite")

    # version
    subparsers.add_parser("version", help="Show version and DOI information")

    args = parser.parse_args()

    dispatch = {
        "scan": cmd_scan,
        "redact": cmd_redact,
        "rag-scan": cmd_rag_scan,
        "metrics": cmd_metrics,
        "report": cmd_report,
        "mcp-gateway": cmd_mcp_gateway,
        "audit": cmd_audit,
        "redteam": cmd_audit,
        "benchmark": cmd_benchmark,
        "version": cmd_version,
    }

    if args.subcommand in dispatch:
        sys.exit(dispatch[args.subcommand](args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
