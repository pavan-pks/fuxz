
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from sender import RequestResult


# ─────────────────────────────────────────────────────────────────────────────
# Severity & Finding
# ─────────────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class Finding:
    result:      RequestResult
    vuln_type:   str           # "SQL Injection", "XSS", …
    severity:    Severity
    reason:      str           # one-line why we flagged it
    explanation: str           # longer AI-style description
    fix:         str           # remediation advice
    matched:     str = ""      # the specific snippet that triggered the rule


# ─────────────────────────────────────────────────────────────────────────────
# Detection rules
# ─────────────────────────────────────────────────────────────────────────────

# SQL error strings found in real DB error pages
_SQL_ERROR_PATTERNS = re.compile(
    r"(sql syntax|mysql_fetch|ORA-\d{5}|pg_query|sqlite_|"
    r"syntax error|unclosed quotation|division by zero|"
    r"invalid query|mysql error|mssql|odbc driver|"
    r"warning: mysql|warning: pg_|microsoft ole db|"
    r"jdbc|com\.mysql|org\.postgresql|native client)",
    re.IGNORECASE,
)

# Path traversal success indicators
_TRAVERSAL_PATTERNS = re.compile(
    r"(root:x:0:0|daemon:|bin:/bin|nobody:|www-data:|"
    r"\[boot loader\]|for 16-bit app support|"
    r"extension=|zend_extension=)",
    re.IGNORECASE,
)

# Slow-response threshold for time-based blind injection
_SLOW_THRESHOLD_SECONDS = 4.5

# Length delta that suggests conditional response (in bytes)
_LENGTH_DELTA_THRESHOLD = 300


class ResponseAnalyzer:
    """
    Analyze a single RequestResult and return zero or more Findings.
    Pass baseline_length / baseline_time from FuzzSender for delta checks.
    """

    def __init__(self, baseline_length: int = 0, baseline_time: float = 0.0):
        self.baseline_length = baseline_length
        self.baseline_time   = baseline_time

    def analyze(self, result: RequestResult) -> list[Finding]:
        if not result.success:
            return self._handle_network_error(result)

        findings: list[Finding] = []

        findings += self._check_server_error(result)
        findings += self._check_sql_errors(result)
        findings += self._check_xss_reflection(result)
        findings += self._check_path_traversal(result)
        findings += self._check_slow_response(result)
        findings += self._check_length_delta(result)

        return findings

    # ── Individual checks ─────────────────────────────────────────────────────

    def _handle_network_error(self, r: RequestResult) -> list[Finding]:
        return [Finding(
            result=r, vuln_type="Network Error", severity=Severity.INFO,
            reason=f"Request failed: {r.error}",
            explanation=(
                "The server did not respond.  This may indicate the payload "
                "caused a crash, the server rate-limited the request, or the "
                "network is unstable."
            ),
            fix="Check server availability and adjust --timeout / --delay flags.",
        )]

    def _check_server_error(self, r: RequestResult) -> list[Finding]:
        if r.status_code >= 500:
            return [Finding(
                result=r, vuln_type="Server Error / Crash",
                severity=Severity.HIGH,
                reason=f"HTTP {r.status_code} returned for payload in {r.payload.category}",
                explanation=(
                    f"A {r.status_code} status suggests the payload caused an "
                    "unhandled exception on the server.  This is a strong "
                    "indicator of insufficient input validation – and in the "
                    "worst case, a path to Remote Code Execution."
                ),
                fix=(
                    "Wrap all user-supplied input in try/except blocks.  "
                    "Return generic error pages (never stack traces) and log "
                    "details server-side only."
                ),
            )]
        return []

    def _check_sql_errors(self, r: RequestResult) -> list[Finding]:
        m = _SQL_ERROR_PATTERNS.search(r.response_body)
        if m:
            snippet = r.response_body[max(0, m.start()-30): m.end()+30].strip()
            return [Finding(
                result=r, vuln_type="SQL Injection",
                severity=Severity.CRITICAL,
                reason=f'DB error string "{m.group(0)}" found in response',
                explanation=(
                    "The server returned a raw database error message, meaning "
                    "user input reached a SQL query without sanitisation.  An "
                    "attacker can enumerate tables, extract credentials, and "
                    "potentially write files to disk."
                ),
                fix=(
                    "Use parameterised queries (prepared statements) for ALL "
                    "database interactions.  Never concatenate user input into "
                    "SQL strings.  Apply an allowlist for acceptable input "
                    "characters and strip or reject everything else."
                ),
                matched=snippet,
            )]
        return []

    def _check_xss_reflection(self, r: RequestResult) -> list[Finding]:
        raw = r.payload.raw
        # Check if a meaningful portion of the payload appears verbatim in the page
        # Use a distinctive sub-string that wouldn't appear in a normal page
        probe = raw[:40] if len(raw) >= 10 else raw
        if probe and probe.lower() in r.response_body.lower():
            return [Finding(
                result=r, vuln_type="Reflected XSS",
                severity=Severity.MEDIUM,
                reason=f"Payload reflected verbatim in response body",
                explanation=(
                    "The server echoed the payload back into the HTML without "
                    "HTML-encoding it.  A crafted link containing a script tag "
                    "would execute in the victim's browser, enabling session "
                    "hijacking, phishing, and CSRF."
                ),
                fix=(
                    "HTML-encode ALL user-controlled output with a trusted "
                    "library (e.g. Python's `html.escape()`, OWASP Java "
                    "Encoder, or framework auto-escaping).  Apply a strict "
                    "Content-Security-Policy header to block inline scripts."
                ),
                matched=probe,
            )]
        return []

    def _check_path_traversal(self, r: RequestResult) -> list[Finding]:
        m = _TRAVERSAL_PATTERNS.search(r.response_body)
        if m:
            snippet = r.response_body[max(0, m.start()-20): m.end()+40].strip()
            return [Finding(
                result=r, vuln_type="Path Traversal",
                severity=Severity.CRITICAL,
                reason=f'Sensitive file content detected: "{m.group(0)}"',
                explanation=(
                    "The response contains content that matches known system "
                    "files (/etc/passwd, win.ini, etc.).  The application is "
                    "reading files from the filesystem based on user input "
                    "without canonicalising the path first."
                ),
                fix=(
                    "Resolve all file paths with os.path.realpath() / "
                    "Path.resolve() and verify the result starts within the "
                    "intended root directory.  Use an allowlist of permitted "
                    "filenames rather than blocking traversal sequences."
                ),
                matched=snippet[:120],
            )]
        return []

    def _check_slow_response(self, r: RequestResult) -> list[Finding]:
        if r.response_time >= _SLOW_THRESHOLD_SECONDS:
            delta = r.response_time - self.baseline_time
            return [Finding(
                result=r, vuln_type="Time-Based Blind Injection",
                severity=Severity.HIGH,
                reason=(
                    f"Response took {r.response_time:.1f}s "
                    f"(+{delta:.1f}s above baseline)"
                ),
                explanation=(
                    "The server took significantly longer to respond when this "
                    "payload was injected.  Sleep/delay functions in SQL "
                    "(SLEEP, WAITFOR DELAY, pg_sleep) and OS-level commands "
                    "are the most common cause – a classic blind injection "
                    "fingerprint."
                ),
                fix=(
                    "Use parameterised queries to prevent SQL injection.  "
                    "Set query timeouts at the database layer.  Enforce strict "
                    "input validation to reject payloads containing SLEEP, "
                    "WAITFOR, and similar keywords."
                ),
            )]
        return []

    def _check_length_delta(self, r: RequestResult) -> list[Finding]:
        if self.baseline_length == 0:
            return []
        delta = abs(r.content_length - self.baseline_length)
        if delta >= _LENGTH_DELTA_THRESHOLD:
            direction = "larger" if r.content_length > self.baseline_length else "smaller"
            return [Finding(
                result=r, vuln_type="Anomalous Response Length",
                severity=Severity.LOW,
                reason=(
                    f"Response is {delta} bytes {direction} than baseline "
                    f"({r.content_length} vs {self.baseline_length})"
                ),
                explanation=(
                    "A significant size difference suggests the payload changed "
                    "the server's behaviour – possibly revealing extra data, "
                    "triggering a different code path, or being processed as a "
                    "command.  Combined with other findings this is significant."
                ),
                fix=(
                    "Investigate why this payload returns a different amount of "
                    "data.  Ensure error messages and debug output are never "
                    "exposed to end-users."
                ),
            )]
        return []
