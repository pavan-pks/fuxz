

import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from requests.exceptions import RequestException

from payloads import Payload

# Suppress SSL warnings when verify=False is used
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─────────────────────────────────────────────────────────────────────────────
# Result record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RequestResult:
    payload:       Payload
    url:           str            # final URL after injection
    method:        str            # GET / POST
    status_code:   int   = 0
    response_body: str   = ""
    response_time: float = 0.0    # seconds
    content_length: int  = 0
    error:         Optional[str] = None
    success:       bool  = False  # False if network error


# ─────────────────────────────────────────────────────────────────────────────
# Sender
# ─────────────────────────────────────────────────────────────────────────────

class FuzzSender:
    """
    Fires one HTTP request per payload.
    Baseline response (with a benign value) is captured first so the
    analyzer can compare lengths and timings.
    """

    DEFAULT_HEADERS = {
        "User-Agent": (
            "WebFuzz/1.0 (Security Testing Tool - "
            "use only on systems you own or have permission to test)"
        ),
        "Accept": "text/html,application/xhtml+xml,*/*",
    }

    def __init__(
        self,
        base_url:   str,
        param:      str,
        method:     str  = "GET",
        extra_data: dict | None = None,   # other POST fields
        timeout:    float = 10.0,
        verify_ssl: bool  = True,
        proxy:      str | None = None,
    ):
        self.base_url   = base_url.rstrip("/")
        self.param      = param
        self.method     = method.upper()
        self.extra_data = extra_data or {}
        self.timeout    = timeout
        self.verify_ssl = verify_ssl
        self.proxies    = {"http": proxy, "https": proxy} if proxy else {}

        self.session    = requests.Session()
        self.session.headers.update(self.DEFAULT_HEADERS)

        # Populated by capture_baseline()
        self.baseline_length: int   = 0
        self.baseline_time:   float = 0.0
        self.baseline_status: int   = 0

    # ── Baseline ─────────────────────────────────────────────────────────────

    def capture_baseline(self, value: str = "test") -> RequestResult:
        """
        Send a benign request so the analyzer has a reference point.
        Call this once before the fuzzing loop.
        """
        dummy = Payload(category="Baseline", raw=value, encoded=value)
        result = self._send(dummy)
        if result.success:
            self.baseline_length = result.content_length
            self.baseline_time   = result.response_time
            self.baseline_status = result.status_code
        return result

    # ── Single request ────────────────────────────────────────────────────────

    def send(self, payload: Payload) -> RequestResult:
        return self._send(payload)

    def _send(self, payload: Payload) -> RequestResult:
        value = payload.encoded

        try:
            t0 = time.perf_counter()

            if self.method == "GET":
                # Parse existing query string, inject payload, rebuild URL
                from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
                parsed = urlparse(self.base_url)
                params = parse_qs(parsed.query, keep_blank_values=True)
                params[self.param] = [value]
                new_query = urlencode(params, doseq=True)
                final_url = urlunparse(parsed._replace(query=new_query))

                resp = self.session.get(
                    final_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                    allow_redirects=True,
                )
            else:  # POST
                data = dict(self.extra_data)
                data[self.param] = value
                final_url = self.base_url

                resp = self.session.post(
                    final_url,
                    data=data,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    proxies=self.proxies,
                    allow_redirects=True,
                )

            elapsed = time.perf_counter() - t0
            body = resp.text[:8000]   # cap to avoid memory bloat

            return RequestResult(
                payload=payload,
                url=final_url,
                method=self.method,
                status_code=resp.status_code,
                response_body=body,
                response_time=round(elapsed, 3),
                content_length=len(resp.content),
                success=True,
            )

        except requests.exceptions.Timeout:
            return RequestResult(
                payload=payload, url=self.base_url, method=self.method,
                error="Timeout", response_time=self.timeout, success=False,
            )
        except RequestException as exc:
            return RequestResult(
                payload=payload, url=self.base_url, method=self.method,
                error=str(exc), success=False,
            )
