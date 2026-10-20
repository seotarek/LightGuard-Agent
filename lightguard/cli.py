import argparse
import sys
import time

from lightguard.core import LightGuardAgent


def cmd_scan(args: argparse.Namespace) -> int:
    text = args.text
    if not text and not sys.stdin.isatty():
        text = sys.stdin.read()

    if not text:
        sys.stderr.write("Error: No text provided. Pass text as argument or pipe via stdin.\n")
        return 1

    guard = LightGuardAgent()
    t0 = time.perf_counter()
    res = guard.process_observation(text)
    total_cli_ms = (time.perf_counter() - t0) * 1000.0

    print("=" * 60)
    print("🛡️  LightGuard-Agent Security Audit Report")
    print("=" * 60)
    print(f"Status           : {'🚨 UNTRUSTED / SUSPICIOUS' if res['is_untrusted'] else '✅ CLEAN / BENIGN'}")
    print(f"Tier 0 Obfuscated: {res.get('t0_was_obfuscated', False)} (Entropy: {res.get('t0_entropy', 0.0):.2f})")
    if res.get("decoded_payloads"):
        print(f"Decoded Payloads : {res['decoded_payloads']}")
    print(f"Tier 1 Flagged   : {res['t1_flagged']} (Syntactic / Delimiter neutralization)")
    print(f"Tier 2 Risk Score: {res['t2_risk_score']:.2f} / 1.00 (Semantic intent density)")
    print(f"Engine Latency   : {res['total_latency_ms']:.4f} ms ({res['total_latency_ms'] * 1000.0:.1f} µs)")
    print(f"Total Overhead   : {total_cli_ms:.4f} ms")
    print("-" * 60)
    print("Sanitized Observation Preview:")
    preview = res["sanitized_observation"]
    if len(preview) > 300:
        preview = preview[:300] + "... [TRUNCATED]"
    print(preview)
    print("=" * 60)
    return 0 if not res["is_untrusted"] else 2


def cmd_benchmark(args: argparse.Namespace) -> int:
    try:
        from benchmark.run_benchmark import run_evaluation
    except ImportError:
        sys.stderr.write("Benchmark module not found in the current environment.\n")
        return 1

    print("Running LightGuard-Agent standardized 50-vector benchmark suite...")
    run_evaluation()
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    from lightguard.redteam import format_audit_report, run_redteam_audit

    print("Executing LightGuard-Agent Adversarial Red-Team Penetration Simulation...")
    report = run_redteam_audit()
    print(format_audit_report(report))
    return 0 if report.failed_vectors == 0 else 1


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

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan and sanitize text for prompt injection")
    scan_parser.add_argument("text", nargs="?", default="", help="Text to scan (or pass via stdin)")

    # audit / redteam subcommand
    subparsers.add_parser("audit", help="Run automated adversarial red-team penetration audit")
    subparsers.add_parser("redteam", help="Alias for audit: run adversarial penetration suite")

    # benchmark subcommand
    subparsers.add_parser("benchmark", help="Run empirical benchmark suite")

    # version subcommand
    subparsers.add_parser("version", help="Show version and DOI information")

    args = parser.parse_args()

    if args.subcommand == "scan":
        sys.exit(cmd_scan(args))
    elif args.subcommand in ("audit", "redteam"):
        sys.exit(cmd_audit(args))
    elif args.subcommand == "benchmark":
        sys.exit(cmd_benchmark(args))
    elif args.subcommand == "version":
        sys.exit(cmd_version(args))
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
