"""
ai_insights.py – Gemini-powered AI analysis with OWASP Top 10 mapping.

This module is ADDITIVE ONLY. It does not touch any existing scan logic.
It accepts already-generated scan findings and sends them to Google Gemini
for structured security analysis.

Usage (Flask route, added in server.py):
    from ai_insights import get_ai_insights
    result = get_ai_insights(findings_list, stats_dict)
"""

import json
import os
import urllib.request
import urllib.error

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) reference – used in the prompt so Gemini can map to it
# ---------------------------------------------------------------------------
OWASP_TOP_10 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable and Outdated Components",
    "A07": "Identification and Authentication Failures",
    "A08": "Software and Data Integrity Failures",
    "A09": "Security Logging and Monitoring Failures",
    "A10": "Server-Side Request Forgery (SSRF)",
}

GEMINI_API_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.5-flash:generateContent"
)


def _build_prompt(findings: list, stats: dict) -> str:
    """Construct the Gemini prompt from scan results."""
    findings_text = json.dumps(findings, indent=2) if findings else "[]"
    stats_text = json.dumps(stats, indent=2) if stats else "{}"

    owasp_list = "\n".join(
        f"  • {code}: {name}" for code, name in OWASP_TOP_10.items()
    )

    return f"""You are a senior application security engineer reviewing automated web fuzzing results.

## Scan Statistics
{stats_text}

## Detected Findings (raw scan output)
{findings_text}

## Your Task
Analyze the findings above and produce a structured security report in **valid JSON only** (no markdown fences, no extra text).

The JSON must follow this exact schema:
{{
  "summary": "<2-3 sentence executive summary of the overall security posture>",
  "overall_risk": "<Critical|High|Medium|Low|Informational>",
  "key_issues": [
    {{
      "title": "<short issue title>",
      "owasp_code": "<e.g. A03>",
      "owasp_name": "<full OWASP name>",
      "risk_level": "<Critical|High|Medium|Low>",
      "explanation": "<clear plain-English explanation of the issue>",
      "fix": "<concrete remediation advice>",
      "code_snippet": "<optional improved/safe code example, or empty string>"
    }}
  ],
  "recommendations": [
    "<top-level recommendation 1>",
    "<top-level recommendation 2>"
  ]
}}

## OWASP Top 10 (2021) – map each issue to the closest category:
{owasp_list}

Rules:
- Every key_issue MUST have a valid owasp_code from A01–A10.
- If no clear mapping exists, choose the closest match.
- risk_level must be one of: Critical, High, Medium, Low.
- Return ONLY the JSON object – no preamble, no markdown, no explanation outside JSON.
- If there are no findings, still produce a valid JSON with a summary stating no issues were detected.
"""


def get_ai_insights(findings: list, stats: dict) -> dict:
    """
    Call the Gemini API with the provided scan findings and return
    a structured AI analysis dict.

    Returns a dict with keys: summary, overall_risk, key_issues, recommendations
    On error, returns a dict with key: error
    """
    api_key = "AIzaSyAZUxwOBLa5SqB-rW3AjWlq4HF1P_9FGWQ"

    prompt = _build_prompt(findings, stats)

    payload = json.dumps(
        {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 4096,
                "responseMimeType": "application/json",
            },
        }
    ).encode("utf-8")

    url = f"{GEMINI_API_URL}?key={api_key}"
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return {"error": f"Gemini API HTTP {exc.code}: {body[:400]}"}
    except urllib.error.URLError as exc:
        return {"error": f"Network error calling Gemini API: {exc.reason}"}

    try:
        gemini_resp = json.loads(raw)
        # Extract the text content from Gemini's response structure
        text = (
            gemini_resp["candidates"][0]["content"]["parts"][0]["text"]
        )
        # Gemini should return pure JSON (we set responseMimeType), but strip fences if present
        text = text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
            if text.endswith("```"):
                text = text[: text.rfind("```")]
        analysis = json.loads(text.strip())
    except (KeyError, IndexError, json.JSONDecodeError) as exc:
        return {
            "error": f"Failed to parse Gemini response: {exc}",
            "raw": raw[:800],
        }

    return analysis
