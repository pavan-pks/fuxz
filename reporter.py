

import logging
import sys
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False
    # Stub so code below never has to branch
    class _NoColor:
        def __getattr__(self, _): return ""
    Fore = Style = _NoColor()

from analyzer import Finding, Severity
from sender import RequestResult


# ─────────────────────────────────────────────────────────────────────────────
# Severity colour map
# ─────────────────────────────────────────────────────────────────────────────

_SEV_COLOUR = {
    Severity.CRITICAL: Fore.RED,
    Severity.HIGH:     Fore.LIGHTRED_EX,
    Severity.MEDIUM:   Fore.YELLOW,
    Severity.LOW:      Fore.CYAN,
    Severity.INFO:     Fore.WHITE,
}

_SEV_BADGE = {
    Severity.CRITICAL: "[ CRITICAL ]",
    Severity.HIGH:     "[   HIGH   ]",
    Severity.MEDIUM:   "[  MEDIUM  ]",
    Severity.LOW:      "[   LOW   ]",
    Severity.INFO:     "[   INFO   ]",
}

_CAT_COLOUR = {
    "SQL Injection":     Fore.RED,
    "XSS":               Fore.YELLOW,
    "Path Traversal":    Fore.MAGENTA,
    "Long Inputs":       Fore.CYAN,
    "Special Characters":Fore.BLUE,
    "Random Inputs":     Fore.WHITE,
}


# ─────────────────────────────────────────────────────────────────────────────
# Logger setup
# ─────────────────────────────────────────────────────────────────────────────

def setup_logger(log_file: Optional[str]) -> logging.Logger:
    logger = logging.getLogger("webfuzz")
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s",
                             datefmt="%Y-%m-%d %H:%M:%S")
    if log_file:
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.WARNING)   # only warnings+ go to stdout via logger
    sh.setFormatter(fmt)
    logger.addHandler(sh)
    return logger


# ─────────────────────────────────────────────────────────────────────────────
# Reporter
# ─────────────────────────────────────────────────────────────────────────────

class Reporter:

    WIDTH = 72

    def __init__(self, log_file: Optional[str] = None, verbose: bool = False):
        self.logger  = setup_logger(log_file)
        self.verbose = verbose
        self._all_findings: list[Finding] = []
        self._total_sent   = 0
        self._start_time   = datetime.now()

    # ── Banner ────────────────────────────────────────────────────────────────

    def banner(self, target: str, param: str, method: str, total_payloads: int):
        w  = self.WIDTH
        print()
        print(Fore.CYAN + "╔" + "═" * (w-2) + "╗")
        print(Fore.CYAN + "║" + Style.BRIGHT +
              "  WebFuzz – CLI Security Fuzzing Tool".center(w-2) +
              Style.NORMAL + Fore.CYAN + "║")
        print(Fore.CYAN + "╚" + "═" * (w-2) + "╝")
        print(f"  {Fore.WHITE}Target  : {Fore.YELLOW}{target}")
        print(f"  {Fore.WHITE}Param   : {Fore.YELLOW}{param}")
        print(f"  {Fore.WHITE}Method  : {Fore.YELLOW}{method}")
        print(f"  {Fore.WHITE}Payloads: {Fore.YELLOW}{total_payloads}")
        print(f"  {Fore.WHITE}Started : {Fore.YELLOW}{self._start_time.strftime('%H:%M:%S')}")
        print(Fore.CYAN + "─" * w)
        print()

    # ── Category header ───────────────────────────────────────────────────────

    def category_header(self, category: str):
        colour = _CAT_COLOUR.get(category, Fore.WHITE)
        label  = f"  ► {category}  "
        pad    = self.WIDTH - len(label) - 2
        print()
        print(colour + Style.BRIGHT +
              f"┌{'─' * (len(label)-2)}{'─' * pad}┐")
        print(colour + Style.BRIGHT +
              f"│{label}{' ' * pad}│")
        print(colour + Style.BRIGHT +
              f"└{'─' * (len(label)-2)}{'─' * pad}┘")

    # ── Per-request progress line ─────────────────────────────────────────────

    def progress(self, result: RequestResult, findings: list[Finding]):
        self._total_sent += 1

        status_colour = (Fore.GREEN if result.status_code < 400
                         else Fore.RED if result.status_code >= 500
                         else Fore.YELLOW)
        payload_display = result.payload.raw[:48].replace("\n", "\\n")

        # Compact line
        line = (
            f"  {Fore.WHITE}#{self._total_sent:<4d} "
            f"{status_colour}[{result.status_code or 'ERR'}] "
            f"{Fore.WHITE}{result.response_time:>6.2f}s  "
            f"{_CAT_COLOUR.get(result.payload.category, Fore.WHITE)}"
            f"{payload_display:<50}"
        )

        if findings:
            sev = max(findings, key=lambda f: list(Severity).index(f.severity))
            col = _SEV_COLOUR.get(sev.severity, Fore.WHITE)
            line += f"  {col}⚠ {sev.vuln_type}"
        elif self.verbose:
            line += f"  {Fore.GREEN}✓ clean"

        print(line)

        # Log everything
        self.logger.info(
            "payload=%r  status=%s  time=%.2fs  findings=%d",
            result.payload.raw, result.status_code,
            result.response_time, len(findings),
        )

    # ── Finding detail card ───────────────────────────────────────────────────

    def finding_card(self, f: Finding):
        self._all_findings.append(f)
        col = _SEV_COLOUR.get(f.severity, Fore.WHITE)
        w   = self.WIDTH
        sep = col + "═" * w

        print()
        print(sep)
        print(col + Style.BRIGHT +
              f"  {_SEV_BADGE[f.severity]}  {f.vuln_type}")
        print(sep)

        def row(label: str, value: str, value_colour=Fore.WHITE):
            print(f"  {Fore.WHITE}{label:<14}{value_colour}{value}")

        row("Category:",  f.result.payload.category, _CAT_COLOUR.get(f.result.payload.category, Fore.WHITE))
        row("Endpoint:",  f.result.url)
        row("Method:",    f.result.method)
        row("Payload:",   repr(f.result.payload.raw[:80]))
        row("Status:",    str(f.result.status_code))
        row("Resp.time:", f"{f.result.response_time:.2f}s")
        if f.matched:
            row("Matched:",   repr(f.matched[:80]), Fore.RED)

        print()
        print(f"  {Fore.CYAN}⚑  Reason")
        for line in textwrap.wrap(f.reason, width=w-4):
            print(f"     {Fore.WHITE}{line}")

        print()
        print(f"  {Fore.YELLOW}✦  Explanation")
        for line in textwrap.wrap(f.explanation, width=w-4):
            print(f"     {Fore.WHITE}{line}")

        print()
        print(f"  {Fore.GREEN}✔  Recommended Fix")
        for line in textwrap.wrap(f.fix, width=w-4):
            print(f"     {Fore.WHITE}{line}")

        print(sep)

        self.logger.warning(
            "FINDING | %s | %s | payload=%r | reason=%s",
            f.severity.value, f.vuln_type,
            f.result.payload.raw, f.reason,
        )

    # ── Final report ──────────────────────────────────────────────────────────

    def final_report(self):
        elapsed = (datetime.now() - self._start_time).total_seconds()
        w       = self.WIDTH

        from collections import Counter
        sev_counts = Counter(f.severity.value for f in self._all_findings)
        type_counts = Counter(f.vuln_type for f in self._all_findings)

        print()
        print(Fore.CYAN + "╔" + "═" * (w-2) + "╗")
        print(Fore.CYAN + "║" +
              Style.BRIGHT + "  FINAL REPORT".center(w-2) +
              Style.NORMAL + Fore.CYAN + "║")
        print(Fore.CYAN + "╚" + "═" * (w-2) + "╝")

        print(f"  {Fore.WHITE}Payloads sent   : {Fore.YELLOW}{self._total_sent}")
        print(f"  {Fore.WHITE}Findings total  : "
              f"{Fore.RED if self._all_findings else Fore.GREEN}"
              f"{len(self._all_findings)}")
        print(f"  {Fore.WHITE}Elapsed time    : {Fore.YELLOW}{elapsed:.1f}s")
        print()

        if self._all_findings:
            print(f"  {Fore.WHITE}── Severity Breakdown ──────────────────────────────")
            for sev in Severity:
                if sev.value in sev_counts:
                    col = _SEV_COLOUR[sev]
                    bar = "█" * sev_counts[sev.value]
                    print(f"  {col}{sev.value:<10} {bar}  ({sev_counts[sev.value]})")
            print()
            print(f"  {Fore.WHITE}── Vulnerability Types ──────────────────────────────")
            for vtype, count in type_counts.most_common():
                print(f"  {Fore.YELLOW}  {vtype:<35} {count} finding(s)")
        else:
            print(f"  {Fore.GREEN}  No vulnerabilities detected with these payloads.")
            print(f"  {Fore.WHITE}  That does not mean the target is secure – try")
            print(f"  {Fore.WHITE}  more payload categories or a different parameter.")

        print()
        print(Fore.CYAN + "═" * w)
        print()
