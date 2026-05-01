import json
import queue
import sys
import threading
import time
import traceback
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Generator

from flask import Flask, Response, jsonify, render_template_string, request
from flask_cors import CORS
from flask import render_template

# Add webfuzz dir to path so we can import the existing modules
sys.path.insert(0, str(Path(__file__).parent))

from payloads import CATEGORIES, generate_payloads
from sender import FuzzSender
from analyzer import ResponseAnalyzer, Severity

# ── AI Insights (Gemini) ──────────────────────────────────────────────────────
from ai_insights import get_ai_insights
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app)

# ── Active scan registry ──────────────────────────────────────────────────────
# scan_id → {"queue": Queue, "status": str, "findings": [], "stats": {}}
_scans: dict[str, dict] = {}

# ─────────────────────────────────────────────────────────────────────────────
# Severity ordering for JSON
# ─────────────────────────────────────────────────────────────────────────────
_SEV_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1,
              Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


def _finding_to_dict(f) -> dict:
    return {
        "vuln_type": f.vuln_type,
        "severity": f.severity.value,
        "reason": f.reason,
        "explanation": f.explanation,
        "fix": f.fix,
        "matched": f.matched,
        "payload": f.result.payload.raw[:120],
        "category": f.result.payload.category,
        "url": f.result.url,
        "status_code": f.result.status_code,
        "response_time": f.result.response_time,
        "content_length": f.result.content_length,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Background scan worker  (UNCHANGED)
# ─────────────────────────────────────────────────────────────────────────────
def _run_scan(scan_id: str, config: dict):
    scan = _scans[scan_id]
    q = scan["queue"]
    stats = scan["stats"]

    def emit(event: str, data: dict):
        q.put({"event": event, "data": data})

    try:
        scan["status"] = "running"
        emit("status", {"status": "running", "message": "Initialising scan…"})

        payloads = list(generate_payloads(
            categories=config.get("categories") or None,
            url_encode=config.get("url_encode", False),
            enable_mutations=config.get("mutations", False),
            random_count=config.get("random_count", 5),
            max_per_category=config.get("max_per_category", 0),
        ))

        stats["total"] = len(payloads)
        stats["sent"] = 0
        stats["findings"] = 0
        stats["by_severity"] = {s.value: 0 for s in Severity}
        stats["by_category"] = {}

        emit("init", {"total_payloads": len(payloads),
                      "categories": config.get("categories", list(CATEGORIES.keys()))})

        emit("status", {"status": "running", "message": "Capturing baseline…"})
        sender = FuzzSender(
            base_url=config["url"],
            param=config["param"],
            method=config.get("method", "GET").upper(),
            extra_data=config.get("extra_data", {}),
            timeout=config.get("timeout", 10.0),
            verify_ssl=not config.get("no_verify_ssl", False),
        )
        baseline = sender.capture_baseline()
        if not baseline.success:
            emit("error", {"message": f"Baseline failed: {baseline.error}"})
            scan["status"] = "error"
            return

        emit("baseline", {
            "status_code": baseline.status_code,
            "content_length": baseline.content_length,
            "response_time": baseline.response_time,
        })

        analyzer = ResponseAnalyzer(
            baseline_length=sender.baseline_length,
            baseline_time=sender.baseline_time,
        )

        delay = config.get("delay", 0.0)
        for payload in payloads:
            result = sender.send(payload)
            findings = analyzer.analyze(result)

            stats["sent"] += 1
            cat = payload.category
            stats["by_category"].setdefault(cat, {"sent": 0, "findings": 0})
            stats["by_category"][cat]["sent"] += 1

            finding_dicts = []
            for f in findings:
                stats["findings"] += 1
                stats["by_severity"][f.severity.value] += 1
                stats["by_category"][cat]["findings"] += 1
                fd = _finding_to_dict(f)
                finding_dicts.append(fd)
                scan["findings"].append(fd)

            emit("request", {
                "n": stats["sent"],
                "total": stats["total"],
                "category": cat,
                "payload": payload.raw[:80],
                "status_code": result.status_code,
                "response_time": result.response_time,
                "content_length": result.content_length,
                "error": result.error,
                "findings": finding_dicts,
            })

            if delay > 0:
                time.sleep(delay)

        scan["status"] = "done"
        emit("done", {"stats": stats})

    except Exception as exc:
        tb = traceback.format_exc()
        emit("error", {"message": str(exc), "traceback": tb})
        scan["status"] = "error"
    finally:
        q.put(None)  # sentinel


# ─────────────────────────────────────────────────────────────────────────────
# API routes  (existing unchanged + new /api/ai-insights)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/categories")
def api_categories():
    return jsonify(list(CATEGORIES.keys()) + ["Random Inputs"])


@app.route("/api/scan", methods=["POST"])
def api_start_scan():
    config = request.json or {}
    if not config.get("url") or not config.get("param"):
        return jsonify({"error": "url and param are required"}), 400

    scan_id = str(uuid.uuid4())
    _scans[scan_id] = {
        "queue": queue.Queue(),
        "status": "pending",
        "findings": [],
        "stats": {},
        "config": config,
    }
    thread = threading.Thread(target=_run_scan, args=(scan_id, config), daemon=True)
    thread.start()
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>/stream")
def api_stream(scan_id: str):
    scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "scan not found"}), 404

    def generate() -> Generator[str, None, None]:
        q = scan["queue"]
        while True:
            item = q.get()
            if item is None:
                yield "event: close\ndata: {}\n\n"
                break
            yield f"event: {item['event']}\ndata: {json.dumps(item['data'])}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/api/scan/<scan_id>")
def api_scan_status(scan_id: str):
    scan = _scans.get(scan_id)
    if not scan:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status": scan["status"],
        "stats": scan["stats"],
        "findings": scan["findings"],
    })


# ── NEW: AI Insights endpoint ─────────────────────────────────────────────────
@app.route("/api/ai-insights", methods=["POST"])
def api_ai_insights():
    """
    Accept already-generated scan findings and return Gemini AI analysis.
    Body: { "findings": [...], "stats": {...} }
    Does NOT re-run any scan logic.
    """
    body = request.json or {}
    findings = body.get("findings", [])
    stats = body.get("stats", {})
    result = get_ai_insights(findings, stats)
    if "error" in result:
        return jsonify(result), 500
    return jsonify(result)
# ─────────────────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────────────────
# Frontend (single-file, served inline)
# ─────────────────────────────────────────────────────────────────────────────

DASHBOARD_HTML = r""""""


@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
