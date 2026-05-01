import argparse
import sys
import time

# ── Graceful import check ──────────────────────────────────────────────────

def _require(module: str, install: str):
    try:
        __import__(module)
    except ImportError:
        print(f"[!] Missing dependency: {install}")
        print(f"    Run: pip install {install}")
        sys.exit(1)

_require("requests", "requests")

# Optional but recommended
try:
    from colorama import Fore, Style
except ImportError:
    class _NoColor:
        def __getattr__(self, _): return ""
    Fore = Style = _NoColor()

from payloads  import generate_payloads, CATEGORIES
from sender    import FuzzSender
from analyzer  import ResponseAnalyzer
from reporter  import Reporter


# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parser
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webfuzz",
        description=(
            "WebFuzz – A CLI Web Fuzzing Tool\n"
            "Test web parameters for SQLi, XSS, path traversal, and more.\n\n"
            "⚠  Use only on systems you own or have explicit permission to test."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --url 'http://demo.testfire.net/search.aspx' --param query\n"
            "  python main.py --url 'http://target/login' --param user --method POST\n"
            "  python main.py --url 'http://target/page' --param id --categories 'SQL Injection' XSS\n"
            "  python main.py --url 'http://target/page' --param id --encode --mutations --delay 0.5\n"
        ),
    )

    # Target
    p.add_argument("--url", required=True,
                   help="Target URL (e.g. http://target.com/page.php)")
    p.add_argument("--param", required=True,
                   help="Parameter to fuzz (e.g. id, q, username)")
    p.add_argument("--method", default="GET", choices=["GET", "POST"],
                   help="HTTP method (default: GET)")
    p.add_argument("--data", nargs="*", metavar="KEY=VALUE",
                   help="Extra POST fields (e.g. --data submit=1 token=abc)")

    # Payload options
    p.add_argument("--categories", nargs="+",
                   choices=list(CATEGORIES.keys()) + ["Random Inputs"],
                   help="Payload categories to use (default: all)")
    p.add_argument("--encode", action="store_true",
                   help="URL-encode all payloads before sending")
    p.add_argument("--mutations", action="store_true",
                   help="Enable payload mutations (UPPER, prefix, number append)")
    p.add_argument("--prefix", default="",
                   help="Prefix to prepend to every payload (with --mutations)")
    p.add_argument("--suffix", default="",
                   help="Suffix to append to every payload (with --mutations)")
    p.add_argument("--max-per-category", type=int, default=0, metavar="N",
                   help="Limit payloads per category (0 = all)")
    p.add_argument("--random-count", type=int, default=5, metavar="N",
                   help="Number of random-string payloads (default: 5)")

    # Request options
    p.add_argument("--timeout", type=float, default=10.0,
                   help="HTTP timeout in seconds (default: 10)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Delay between requests in seconds (default: 0)")
    p.add_argument("--no-verify-ssl", action="store_true",
                   help="Disable SSL certificate verification")
    p.add_argument("--proxy", metavar="URL",
                   help="HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)")

    # Output options
    p.add_argument("--log", metavar="FILE",
                   help="Write findings log to file")
    p.add_argument("--verbose", action="store_true",
                   help="Show all requests, not just flagged ones")
    p.add_argument("--show-findings-inline", action="store_true", default=True,
                   help="Print full finding cards as they are discovered (default: on)")

    return p


# ─────────────────────────────────────────────────────────────────────────────
# Main fuzzing loop
# ─────────────────────────────────────────────────────────────────────────────

def run(args: argparse.Namespace):

    # ── Parse extra POST data ─────────────────────────────────────────────────
    extra_data: dict = {}
    if args.data:
        for kv in args.data:
            if "=" in kv:
                k, v = kv.split("=", 1)
                extra_data[k] = v
            else:
                print(f"[!] Ignoring malformed --data entry: {kv!r}")

    # ── Build payload list ────────────────────────────────────────────────────
    payloads = list(generate_payloads(
        categories=args.categories,
        url_encode=args.encode,
        enable_mutations=args.mutations,
        mutation_prefix=args.prefix,
        mutation_suffix=args.suffix,
        random_count=args.random_count,
        max_per_category=args.max_per_category,
    ))

    if not payloads:
        print("[!] No payloads generated – check your --categories flag.")
        sys.exit(1)

    # ── Initialise components ──────────────────────────────────────────────────
    reporter = Reporter(log_file=args.log, verbose=args.verbose)
    reporter.banner(args.url, args.param, args.method, len(payloads))

    sender = FuzzSender(
        base_url=args.url,
        param=args.param,
        method=args.method,
        extra_data=extra_data,
        timeout=args.timeout,
        verify_ssl=not args.no_verify_ssl,
        proxy=args.proxy,
    )

    # ── Baseline request ──────────────────────────────────────────────────────
    print(f"  {Fore.WHITE}Capturing baseline … ", end="", flush=True)
    baseline = sender.capture_baseline()
    if not baseline.success:
        print(Fore.RED + f"FAILED ({baseline.error})")
        print(f"  {Fore.RED}Cannot reach target.  Check URL and network connectivity.")
        sys.exit(1)
    print(Fore.GREEN + f"OK  "
          f"[{baseline.status_code}] {baseline.content_length} bytes "
          f"in {baseline.response_time:.2f}s")
    print()

    analyzer = ResponseAnalyzer(
        baseline_length=sender.baseline_length,
        baseline_time=sender.baseline_time,
    )

    # ── Fuzzing loop ──────────────────────────────────────────────────────────
    current_category = None

    try:
        for payload in payloads:

            # Print category header when category changes
            if payload.category != current_category:
                current_category = payload.category
                reporter.category_header(current_category)

            # Send request
            result   = sender.send(payload)
            findings = analyzer.analyze(result)

            # Progress line (always)
            reporter.progress(result, findings)

            # Finding detail cards (inline)
            for f in findings:
                reporter.finding_card(f)

            # Rate limiting
            if args.delay > 0:
                time.sleep(args.delay)

    except KeyboardInterrupt:
        print()
        print(Fore.YELLOW + "\n  [!] Interrupted by user.")

    # ── Final report ──────────────────────────────────────────────────────────
    reporter.final_report()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Ethical guardrail reminder
    print()
    print(Fore.YELLOW +
          "  ⚠  WebFuzz – for authorised security testing only.")
    print(Fore.YELLOW +
          "  ⚠  Ensure you have explicit permission before testing any target.")
    print()

    run(args)


if __name__ == "__main__":
    main()
