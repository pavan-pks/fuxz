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

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebFuzz Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;700&family=Syne:wght@400;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --bg: #080b0f;
  --surface: #0d1117;
  --panel: #111820;
  --border: #1e2d3d;
  --accent: #00d4ff;
  --accent2: #ff6b35;
  --green: #39ff85;
  --yellow: #ffd60a;
  --red: #ff3358;
  --magenta: #d63af9;
  --text: #c9d1d9;
  --muted: #495670;
  --mono: 'JetBrains Mono', monospace;
  --display: 'Syne', sans-serif;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: var(--mono);
  font-size: 13px;
  min-height: 100vh;
  overflow-x: hidden;
}
body::before {
  content: '';
  position: fixed; inset: 0;
  background: repeating-linear-gradient(
    0deg, transparent, transparent 2px,
    rgba(0,212,255,.015) 2px, rgba(0,212,255,.015) 4px
  );
  pointer-events: none; z-index: 9999;
}

/* ── Layout ── */
.shell {
  display: grid;
  grid-template-rows: 56px 1fr;
  grid-template-columns: 280px 1fr 320px;
  grid-template-areas:
    "header header header"
    "sidebar main findings";
  height: 100vh;
}

/* ── Header ── */
header {
  grid-area: header;
  display: flex; align-items: center; gap: 16px;
  padding: 0 24px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  position: relative;
}
header::after {
  content: '';
  position: absolute; bottom: 0; left: 0; right: 0; height: 1px;
  background: linear-gradient(90deg, transparent, var(--accent), transparent);
}
.logo {
  font-family: var(--display); font-weight: 800; font-size: 20px;
  letter-spacing: -0.5px; color: #fff;
}
.logo span { color: var(--accent); }
.logo sub {
  font-family: var(--mono); font-size: 10px; font-weight: 400;
  color: var(--muted); vertical-align: middle; margin-left: 6px;
}
.header-status { margin-left: auto; display: flex; align-items: center; gap: 24px; }
.status-dot {
  width: 8px; height: 8px; border-radius: 50%;
  background: var(--muted); box-shadow: 0 0 0 0 var(--muted);
  transition: background .3s, box-shadow .3s;
}
.status-dot.running { background: var(--green); animation: pulse-dot 1.2s infinite; }
.status-dot.done { background: var(--accent); }
.status-dot.error { background: var(--red); }
@keyframes pulse-dot {
  0%,100% { box-shadow: 0 0 0 0 rgba(57,255,133,.6); }
  50% { box-shadow: 0 0 0 6px rgba(57,255,133,0); }
}
.status-label { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }

/* ── Sidebar ── */
.sidebar {
  grid-area: sidebar; background: var(--surface);
  border-right: 1px solid var(--border);
  overflow-y: auto; padding: 20px 16px;
  display: flex; flex-direction: column; gap: 20px;
}
.section-title {
  font-size: 10px; font-weight: 700; letter-spacing: 2px;
  text-transform: uppercase; color: var(--muted);
  padding-bottom: 8px; border-bottom: 1px solid var(--border); margin-bottom: 4px;
}
label { font-size: 11px; color: var(--muted); display: block; margin-bottom: 5px; margin-top: 10px; }
label:first-of-type { margin-top: 0; }
input[type=text], input[type=number], select {
  width: 100%; background: var(--panel); border: 1px solid var(--border);
  color: var(--text); font-family: var(--mono); font-size: 12px;
  padding: 8px 10px; border-radius: 4px; outline: none; transition: border-color .2s;
}
input:focus, select:focus { border-color: var(--accent); }
.category-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; margin-top: 4px; }
.cat-chip {
  display: flex; align-items: center; gap: 6px; padding: 5px 8px;
  background: var(--panel); border: 1px solid var(--border); border-radius: 4px;
  cursor: pointer; font-size: 11px; transition: border-color .2s, background .2s;
  user-select: none;
}
.cat-chip input { width: auto; }
.cat-chip:has(input:checked) { border-color: var(--accent); background: rgba(0,212,255,.07); color: var(--accent); }
.toggle-row { display: flex; align-items: center; justify-content: space-between; padding: 6px 0; }
.toggle-label { font-size: 12px; }
.toggle { position: relative; width: 36px; height: 20px; }
.toggle input { opacity: 0; width: 0; height: 0; }
.slider {
  position: absolute; inset: 0; background: var(--panel); border: 1px solid var(--border);
  border-radius: 20px; cursor: pointer; transition: background .2s;
}
.slider::before {
  content: ''; position: absolute; width: 14px; height: 14px; left: 2px; top: 2px;
  background: var(--muted); border-radius: 50%; transition: transform .2s, background .2s;
}
.toggle input:checked + .slider { background: rgba(0,212,255,.2); border-color: var(--accent); }
.toggle input:checked + .slider::before { transform: translateX(16px); background: var(--accent); }
.btn-scan {
  width: 100%; padding: 12px; background: var(--accent); color: #000; border: none;
  border-radius: 4px; font-family: var(--display); font-weight: 700; font-size: 14px;
  letter-spacing: 1px; cursor: pointer; transition: opacity .2s, transform .1s; margin-top: 4px;
}
.btn-scan:hover { opacity: .85; }
.btn-scan:active { transform: scale(.98); }
.btn-scan:disabled { opacity: .4; cursor: not-allowed; }
.btn-stop {
  width: 100%; padding: 8px; background: transparent; color: var(--red);
  border: 1px solid var(--red); border-radius: 4px; font-family: var(--mono);
  font-size: 12px; cursor: pointer; transition: background .2s; display: none;
}
.btn-stop:hover { background: rgba(255,51,88,.1); }

/* ── Main ── */
.main { grid-area: main; display: flex; flex-direction: column; overflow: hidden; }
.stat-bar {
  display: grid; grid-template-columns: repeat(4, 1fr);
  gap: 1px; background: var(--border); border-bottom: 1px solid var(--border); flex-shrink: 0;
}
.stat-cell { background: var(--surface); padding: 12px 16px; display: flex; flex-direction: column; gap: 2px; }
.stat-value { font-family: var(--display); font-size: 22px; font-weight: 700; color: #fff; line-height: 1; transition: color .3s; }
.stat-value.has-findings { color: var(--red); }
.stat-key { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; }
.progress-bar-wrap { height: 3px; background: var(--border); flex-shrink: 0; }
.progress-bar { height: 100%; width: 0; background: linear-gradient(90deg, var(--accent), var(--green)); transition: width .3s; }
.req-log { flex: 1; overflow-y: auto; padding: 12px; display: flex; flex-direction: column; gap: 3px; }
.req-log::-webkit-scrollbar { width: 4px; }
.req-log::-webkit-scrollbar-track { background: transparent; }
.req-log::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
.req-row {
  display: grid; grid-template-columns: 40px 52px 60px 70px 120px 1fr;
  align-items: center; gap: 10px; padding: 5px 8px; border-radius: 3px;
  font-size: 11.5px; border-left: 2px solid transparent; animation: row-in .15s ease;
}
@keyframes row-in { from { opacity: 0; transform: translateX(-6px); } to { opacity: 1; transform: none; } }
.req-row:hover { background: rgba(255,255,255,.03); }
.req-row.flagged { border-left-color: var(--red); background: rgba(255,51,88,.04); }
.req-row.warning { border-left-color: var(--yellow); background: rgba(255,214,10,.03); }
.req-n { color: var(--muted); }
.req-code { font-weight: 700; }
.code-2xx { color: var(--green); }
.code-3xx { color: var(--yellow); }
.code-4xx { color: var(--accent2); }
.code-5xx { color: var(--red); }
.code-err { color: var(--muted); }
.req-time { color: var(--muted); }
.req-cat { color: var(--muted); font-size: 10px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.req-size { color: var(--muted); }
.req-payload { color: var(--text); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.req-payload.flagged-payload { color: var(--red); }
.log-header {
  display: grid; grid-template-columns: 40px 52px 60px 70px 120px 1fr;
  gap: 10px; padding: 5px 8px; font-size: 10px; color: var(--muted);
  letter-spacing: 1px; text-transform: uppercase; border-bottom: 1px solid var(--border);
  margin-bottom: 4px; flex-shrink: 0;
}
.empty-state { flex: 1; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 12px; color: var(--muted); }
.empty-icon { font-size: 48px; opacity: .3; }
.empty-text { font-size: 13px; }

/* ── Findings panel ── */
.findings-panel {
  grid-area: findings; background: var(--surface);
  border-left: 1px solid var(--border);
  display: flex; flex-direction: column; overflow: hidden;
}
.findings-header {
  padding: 14px 16px; border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 10px; flex-shrink: 0;
}
.findings-title { font-family: var(--display); font-weight: 700; font-size: 14px; }
.findings-count {
  background: var(--red); color: #fff; font-size: 11px; font-weight: 700;
  padding: 2px 8px; border-radius: 10px; display: none;
}
.findings-count.visible { display: block; }
.findings-list { flex: 1; overflow-y: auto; padding: 10px; display: flex; flex-direction: column; gap: 8px; }
.findings-list::-webkit-scrollbar { width: 4px; }
.findings-list::-webkit-scrollbar-thumb { background: var(--border); }
.finding-card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 6px; overflow: hidden; animation: card-in .25s ease; cursor: pointer;
}
@keyframes card-in { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: none; } }
.finding-card:hover { border-color: var(--muted); }
.finding-head { display: flex; align-items: center; gap: 8px; padding: 10px 12px; }
.sev-badge { font-size: 9px; font-weight: 700; letter-spacing: 1px; padding: 2px 7px; border-radius: 3px; white-space: nowrap; }
.sev-CRITICAL { background: rgba(255,51,88,.2); color: var(--red); border: 1px solid var(--red); }
.sev-HIGH { background: rgba(255,107,53,.2); color: var(--accent2); border: 1px solid var(--accent2); }
.sev-MEDIUM { background: rgba(255,214,10,.15); color: var(--yellow); border: 1px solid var(--yellow); }
.sev-LOW { background: rgba(0,212,255,.1); color: var(--accent); border: 1px solid var(--accent); }
.sev-INFO { background: rgba(201,209,217,.1); color: var(--text); border: 1px solid var(--border); }
.finding-type { font-size: 12px; font-weight: 700; flex: 1; }
.finding-body { padding: 0 12px 10px; display: none; }
.finding-card.expanded .finding-body { display: block; }
.finding-row { display: flex; gap: 8px; margin-bottom: 6px; font-size: 11px; }
.finding-key { color: var(--muted); min-width: 72px; flex-shrink: 0; }
.finding-val { color: var(--text); word-break: break-all; }
.finding-val.mono { font-family: var(--mono); background: var(--bg); padding: 2px 6px; border-radius: 3px; font-size: 10.5px; }
.fix-block { margin-top: 8px; padding: 8px 10px; background: rgba(57,255,133,.05); border: 1px solid rgba(57,255,133,.2); border-radius: 4px; font-size: 11px; color: var(--green); line-height: 1.5; }
.sev-summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1px; background: var(--border); border-top: 1px solid var(--border); flex-shrink: 0; }
.sev-cell { background: var(--panel); padding: 10px 8px; text-align: center; }
.sev-cell-val { font-family: var(--display); font-size: 18px; font-weight: 700; }
.sev-cell-key { font-size: 9px; letter-spacing: 1px; text-transform: uppercase; margin-top: 2px; }
.sev-cell:nth-child(1) .sev-cell-val { color: var(--red); }
.sev-cell:nth-child(2) .sev-cell-val { color: var(--accent2); }
.sev-cell:nth-child(3) .sev-cell-val { color: var(--yellow); }
.sev-cell:nth-child(4) .sev-cell-val { color: var(--accent); }
.sev-cell:nth-child(1) .sev-cell-key { color: var(--red); }
.sev-cell:nth-child(2) .sev-cell-key { color: var(--accent2); }
.sev-cell:nth-child(3) .sev-cell-key { color: var(--yellow); }
.sev-cell:nth-child(4) .sev-cell-key { color: var(--accent); }

/* ── Toast ── */
#toast {
  position: fixed; bottom: 20px; right: 20px;
  background: var(--panel); border: 1px solid var(--border);
  color: var(--text); padding: 10px 16px; border-radius: 6px;
  font-size: 12px; z-index: 9998;
  transform: translateY(80px); opacity: 0;
  transition: transform .3s, opacity .3s; pointer-events: none;
}
#toast.show { transform: none; opacity: 1; }
#toast.error { border-color: var(--red); color: var(--red); }

/* ════════════════════════════════════════════════════════════
   AI INSIGHTS – added styles (DO NOT modify anything above)
   ════════════════════════════════════════════════════════════ */

/* AI button in findings header */
.btn-ai {
  margin-left: auto;
  padding: 5px 12px;
  background: linear-gradient(135deg, #7c3aed, #d63af9);
  color: #fff;
  border: none;
  border-radius: 4px;
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .5px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
  transition: opacity .2s, transform .1s;
  white-space: nowrap;
}
.btn-ai:hover { opacity: .85; }
.btn-ai:active { transform: scale(.97); }
.btn-ai:disabled { opacity: .4; cursor: not-allowed; }
.btn-ai .ai-spinner {
  width: 10px; height: 10px; border: 2px solid rgba(255,255,255,.3);
  border-top-color: #fff; border-radius: 50%;
  animation: ai-spin .7s linear infinite; display: none;
}
.btn-ai.loading .ai-spinner { display: block; }
.btn-ai.loading .ai-btn-text { opacity: .6; }
@keyframes ai-spin { to { transform: rotate(360deg); } }

/* AI Insights Modal overlay */
#aiModal {
  display: none;
  position: fixed; inset: 0; z-index: 10000;
  background: rgba(8,11,15,.85);
  backdrop-filter: blur(4px);
  align-items: center; justify-content: center;
}
#aiModal.open { display: flex; }

.ai-modal-box {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  width: min(860px, 95vw);
  max-height: 88vh;
  display: flex; flex-direction: column;
  overflow: hidden;
  box-shadow: 0 0 60px rgba(124,58,237,.25);
  animation: modal-in .2s ease;
}
@keyframes modal-in { from { opacity:0; transform: scale(.96); } to { opacity:1; transform:none; } }

.ai-modal-head {
  padding: 16px 20px;
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; gap: 12px;
  flex-shrink: 0;
}
.ai-modal-title {
  font-family: var(--display); font-weight: 800; font-size: 16px;
  background: linear-gradient(135deg, #a78bfa, #d63af9);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
}
.ai-overall-risk {
  padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 700;
}
.risk-Critical { background: rgba(255,51,88,.2); color: var(--red); border: 1px solid var(--red); }
.risk-High     { background: rgba(255,107,53,.2); color: var(--accent2); border: 1px solid var(--accent2); }
.risk-Medium   { background: rgba(255,214,10,.15); color: var(--yellow); border: 1px solid var(--yellow); }
.risk-Low      { background: rgba(0,212,255,.1); color: var(--accent); border: 1px solid var(--accent); }
.risk-Informational { background: rgba(201,209,217,.1); color: var(--text); border: 1px solid var(--border); }

.ai-modal-close {
  margin-left: auto; background: transparent; border: none;
  color: var(--muted); font-size: 20px; cursor: pointer; line-height: 1;
  transition: color .2s;
}
.ai-modal-close:hover { color: var(--text); }

.ai-modal-body { overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 20px; }
.ai-modal-body::-webkit-scrollbar { width: 4px; }
.ai-modal-body::-webkit-scrollbar-thumb { background: var(--border); }

/* Summary section */
.ai-section-label {
  font-size: 9px; letter-spacing: 2px; text-transform: uppercase;
  color: var(--muted); margin-bottom: 8px; font-weight: 700;
}
.ai-summary-text {
  font-size: 13px; line-height: 1.7; color: var(--text);
  background: var(--panel); padding: 14px 16px; border-radius: 6px;
  border-left: 3px solid #7c3aed;
}

/* Issue cards */
.ai-issue-card {
  background: var(--panel); border: 1px solid var(--border);
  border-radius: 8px; overflow: hidden;
}
.ai-issue-head {
  padding: 12px 16px;
  display: grid;
  grid-template-columns: auto 1fr auto auto;
  align-items: center; gap: 10px;
  cursor: pointer;
  transition: background .15s;
}
.ai-issue-head:hover { background: rgba(255,255,255,.03); }

.owasp-badge {
  font-size: 9px; font-weight: 700; letter-spacing: .5px;
  padding: 3px 8px; border-radius: 3px;
  background: rgba(124,58,237,.2); color: #a78bfa;
  border: 1px solid rgba(124,58,237,.4);
  white-space: nowrap;
}
.ai-issue-title { font-size: 12px; font-weight: 700; }
.ai-issue-chevron { color: var(--muted); font-size: 14px; transition: transform .2s; }
.ai-issue-card.expanded .ai-issue-chevron { transform: rotate(90deg); }

.ai-issue-body { padding: 0 16px 14px; display: none; border-top: 1px solid var(--border); }
.ai-issue-card.expanded .ai-issue-body { display: block; }
.ai-field { margin-top: 12px; }
.ai-field-label { font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; color: var(--muted); margin-bottom: 5px; }
.ai-field-text { font-size: 12px; line-height: 1.6; color: var(--text); }
.ai-fix-block {
  padding: 10px 14px; background: rgba(57,255,133,.05);
  border: 1px solid rgba(57,255,133,.2); border-radius: 5px;
  font-size: 12px; color: var(--green); line-height: 1.6;
}
.ai-code-block {
  padding: 10px 14px; background: var(--bg);
  border: 1px solid var(--border); border-radius: 5px;
  font-family: var(--mono); font-size: 11px; color: var(--accent);
  line-height: 1.6; white-space: pre-wrap; overflow-x: auto;
}

/* Recommendations */
.ai-reco-list { display: flex; flex-direction: column; gap: 8px; }
.ai-reco-item {
  display: flex; align-items: flex-start; gap: 10px;
  padding: 10px 14px; background: var(--panel);
  border: 1px solid var(--border); border-radius: 6px;
  font-size: 12px; line-height: 1.5;
}
.ai-reco-num {
  min-width: 22px; height: 22px; background: rgba(124,58,237,.25);
  color: #a78bfa; border-radius: 50%; display: flex; align-items: center;
  justify-content: center; font-size: 11px; font-weight: 700; flex-shrink: 0;
}

/* Error state */
.ai-error-box {
  padding: 16px; background: rgba(255,51,88,.05);
  border: 1px solid rgba(255,51,88,.3); border-radius: 6px;
  color: var(--red); font-size: 12px; line-height: 1.6;
}

* { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }
</style>
</head>
<body>
<div class="shell">

<!-- ── HEADER ── -->
<header>
  <div class="logo">Web<span>Fuzz</span><sub>v2.0 / dashboard</sub></div>
  <div class="header-status">
    <div class="status-label" id="statusLabel">IDLE</div>
    <div class="status-dot" id="statusDot"></div>
  </div>
</header>

<!-- ── SIDEBAR ── -->
<aside class="sidebar">
  <div>
    <div class="section-title">Target</div>
    <label>URL</label>
    <input type="text" id="cfgUrl" placeholder="http://target.com/page.php" />
    <label>Parameter</label>
    <input type="text" id="cfgParam" placeholder="id, q, username…" />
    <label>Method</label>
    <select id="cfgMethod">
      <option value="GET">GET</option>
      <option value="POST">POST</option>
    </select>
    <label>Extra POST data (key=value, comma-sep)</label>
    <input type="text" id="cfgExtra" placeholder="submit=1, token=abc" />
  </div>
  <div>
    <div class="section-title">Payload Categories</div>
    <div class="category-grid" id="catGrid"></div>
  </div>
  <div>
    <div class="section-title">Options</div>
    <div class="toggle-row">
      <span class="toggle-label">URL Encode</span>
      <label class="toggle"><input type="checkbox" id="optEncode"><span class="slider"></span></label>
    </div>
    <div class="toggle-row">
      <span class="toggle-label">Mutations</span>
      <label class="toggle"><input type="checkbox" id="optMutations"><span class="slider"></span></label>
    </div>
    <div class="toggle-row">
      <span class="toggle-label">Auto-scroll log</span>
      <label class="toggle"><input type="checkbox" id="optAutoScroll" checked><span class="slider"></span></label>
    </div>
    <label>Max per category (0 = all)</label>
    <input type="number" id="optMaxCat" value="0" min="0" max="999" />
    <label>Request delay (seconds)</label>
    <input type="number" id="optDelay" value="0" min="0" max="10" step="0.1" />
    <label>Timeout (seconds)</label>
    <input type="number" id="optTimeout" value="10" min="1" max="60" />
    <label>Random string count</label>
    <input type="number" id="optRandom" value="5" min="0" max="50" />
  </div>
  <button class="btn-scan" id="btnScan" onclick="startScan()">▶ START SCAN</button>
  <button class="btn-stop" id="btnStop" onclick="stopScan()">■ STOP</button>
</aside>

<!-- ── MAIN ── -->
<main class="main">
  <div class="stat-bar">
    <div class="stat-cell">
      <div class="stat-value" id="statSent">0</div>
      <div class="stat-key">Sent</div>
    </div>
    <div class="stat-cell">
      <div class="stat-value" id="statTotal">—</div>
      <div class="stat-key">Total</div>
    </div>
    <div class="stat-cell">
      <div class="stat-value" id="statFindings">0</div>
      <div class="stat-key">Findings</div>
    </div>
    <div class="stat-cell">
      <div class="stat-value" id="statTime">0.00s</div>
      <div class="stat-key">Last resp.</div>
    </div>
  </div>
  <div class="progress-bar-wrap"><div class="progress-bar" id="progress"></div></div>
  <div class="log-header">
    <span>#</span><span>Status</span><span>Time</span><span>Size</span>
    <span>Category</span><span>Payload</span>
  </div>
  <div class="req-log" id="reqLog">
    <div class="empty-state" id="emptyState">
      <div class="empty-icon">⌖</div>
      <div class="empty-text">Configure target and press START SCAN</div>
    </div>
  </div>
</main>

<!-- ── FINDINGS ── -->
<aside class="findings-panel">
  <div class="findings-header">
    <div class="findings-title">Findings</div>
    <div class="findings-count" id="findingsCount">0</div>
    <!-- ══ AI INSIGHTS BUTTON (new) ══ -->
    <button class="btn-ai" id="btnAiInsights" onclick="openAiInsights()" title="Analyze findings with Google Gemini AI + OWASP mapping">
      <span class="ai-spinner"></span>
      <span class="ai-btn-text">✦ AI Insights</span>
    </button>
  </div>
  <div class="findings-list" id="findingsList">
    <div class="empty-state" style="flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;color:var(--muted)">
      <div style="font-size:36px;opacity:.2">⚑</div>
      <div style="font-size:12px">No findings yet</div>
    </div>
  </div>
  <div class="sev-summary">
    <div class="sev-cell"><div class="sev-cell-val" id="svCrit">0</div><div class="sev-cell-key">Critical</div></div>
    <div class="sev-cell"><div class="sev-cell-val" id="svHigh">0</div><div class="sev-cell-key">High</div></div>
    <div class="sev-cell"><div class="sev-cell-val" id="svMed">0</div><div class="sev-cell-key">Medium</div></div>
    <div class="sev-cell"><div class="sev-cell-val" id="svLow">0</div><div class="sev-cell-key">Low</div></div>
  </div>
</aside>

</div><!-- .shell -->

<!-- ══════════════════════════════════════════════════════
     AI INSIGHTS MODAL  (new – appended after .shell)
     ══════════════════════════════════════════════════════ -->
<div id="aiModal" role="dialog" aria-modal="true" aria-label="AI Insights">
  <div class="ai-modal-box">
    <div class="ai-modal-head">
      <div class="ai-modal-title">✦ AI Insights · Gemini</div>
      <div id="aiOverallRisk" class="ai-overall-risk" style="display:none"></div>
      <button class="ai-modal-close" onclick="closeAiModal()" title="Close">✕</button>
    </div>
    <div class="ai-modal-body" id="aiModalBody">
      <!-- content injected by JS -->
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
// ─── State ────────────────────────────────────────────────────────────────
let evtSource   = null;
let scanId      = null;
let stopped     = false;
let findingTotal = 0;
let sevCounts   = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
let sentCount   = 0;
let totalCount  = 0;

// Accumulated findings & stats (used by AI Insights – no re-scan)
let _allFindings = [];
let _lastStats   = {};

// ─── Init: fetch categories ────────────────────────────────────────────────
async function init() {
  const res  = await fetch('/api/categories');
  const cats = await res.json();
  const grid = document.getElementById('catGrid');
  cats.forEach(c => {
    const chip = document.createElement('label');
    chip.className = 'cat-chip';
    chip.innerHTML = `<input type="checkbox" value="${c}" checked> ${c}`;
    grid.appendChild(chip);
  });
}
init();

// ─── Start scan ────────────────────────────────────────────────────────────
async function startScan() {
  const url   = document.getElementById('cfgUrl').value.trim();
  const param = document.getElementById('cfgParam').value.trim();
  if (!url || !param) { toast('URL and parameter are required', true); return; }

  const cats = [...document.querySelectorAll('#catGrid input:checked')].map(i => i.value);
  if (!cats.length) { toast('Select at least one category', true); return; }

  const extraRaw  = document.getElementById('cfgExtra').value.trim();
  const extraData = {};
  if (extraRaw) {
    extraRaw.split(',').forEach(kv => {
      const [k,v] = kv.trim().split('=');
      if (k && v !== undefined) extraData[k.trim()] = v.trim();
    });
  }

  const config = {
    url, param,
    method:           document.getElementById('cfgMethod').value,
    extra_data:       extraData,
    categories:       cats,
    url_encode:       document.getElementById('optEncode').checked,
    mutations:        document.getElementById('optMutations').checked,
    max_per_category: parseInt(document.getElementById('optMaxCat').value) || 0,
    delay:            parseFloat(document.getElementById('optDelay').value) || 0,
    timeout:          parseFloat(document.getElementById('optTimeout').value) || 10,
    random_count:     parseInt(document.getElementById('optRandom').value) || 5,
  };

  resetUI();
  stopped = false;
  setStatus('running');
  document.getElementById('btnScan').disabled = true;
  document.getElementById('btnStop').style.display = 'block';

  const r = await fetch('/api/scan', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify(config)
  });
  const { scan_id, error } = await r.json();
  if (error) { toast(error, true); setStatus('error'); return; }
  scanId = scan_id;

  evtSource = new EventSource(`/api/scan/${scan_id}/stream`);

  evtSource.addEventListener('init', e => {
    const d = JSON.parse(e.data);
    totalCount = d.total_payloads;
    document.getElementById('statTotal').textContent = totalCount;
  });

  evtSource.addEventListener('baseline', e => {
    const d = JSON.parse(e.data);
    toast(`Baseline: ${d.status_code} · ${d.content_length}B · ${d.response_time.toFixed(2)}s`);
  });

  evtSource.addEventListener('request', e => {
    const d = JSON.parse(e.data);
    sentCount = d.n;
    addRequestRow(d);
    updateStats(d);
    if (d.findings && d.findings.length) {
      d.findings.forEach(f => {
        addFinding(f);
        _allFindings.push(f);   // accumulate for AI Insights
      });
    }
  });

  evtSource.addEventListener('done', e => {
    const d = JSON.parse(e.data);
    _lastStats = d.stats;       // store stats for AI Insights
    setStatus('done');
    toast(`Scan complete · ${d.stats.findings} finding(s)`);
    scanFinished();
  });

  evtSource.addEventListener('error_event', e => {
    const d = JSON.parse(e.data);
    toast('Error: ' + d.message, true);
    setStatus('error');
    scanFinished();
  });

  evtSource.addEventListener('close', () => {
    evtSource.close();
    if (!stopped) scanFinished();
  });

  evtSource.onerror = () => {
    if (!stopped) { setStatus('error'); scanFinished(); }
  };
}

function stopScan() {
  stopped = true;
  if (evtSource) evtSource.close();
  setStatus('idle');
  scanFinished();
  toast('Scan stopped');
}

function scanFinished() {
  document.getElementById('btnScan').disabled = false;
  document.getElementById('btnStop').style.display = 'none';
  document.getElementById('progress').style.width = '100%';
}

// ─── UI helpers ────────────────────────────────────────────────────────────
function resetUI() {
  sentCount = 0; totalCount = 0; findingTotal = 0;
  sevCounts = {CRITICAL:0, HIGH:0, MEDIUM:0, LOW:0};
  _allFindings = []; _lastStats = {};
  document.getElementById('statSent').textContent    = '0';
  document.getElementById('statTotal').textContent   = '—';
  document.getElementById('statFindings').textContent = '0';
  document.getElementById('statTime').textContent    = '—';
  document.getElementById('progress').style.width    = '0';
  document.getElementById('reqLog').innerHTML        = '';
  document.getElementById('findingsList').innerHTML  = '';
  document.getElementById('findingsCount').classList.remove('visible');
  document.getElementById('findingsCount').textContent = '0';
  ['svCrit','svHigh','svMed','svLow'].forEach(id =>
    document.getElementById(id).textContent = '0');
  document.getElementById('statFindings').classList.remove('has-findings');
  const es = document.getElementById('emptyState');
  if (es) es.remove();
}

function setStatus(s) {
  document.getElementById('statusDot').className   = `status-dot ${s}`;
  document.getElementById('statusLabel').textContent = s.toUpperCase();
}

function updateStats(d) {
  document.getElementById('statSent').textContent = d.n;
  document.getElementById('statTime').textContent = d.response_time.toFixed(2) + 's';
  if (totalCount > 0)
    document.getElementById('progress').style.width = (d.n / totalCount * 100) + '%';
}

function codeClass(code) {
  if (!code || code === 'ERR') return 'code-err';
  if (code < 300) return 'code-2xx';
  if (code < 400) return 'code-3xx';
  if (code < 500) return 'code-4xx';
  return 'code-5xx';
}

function addRequestRow(d) {
  const log     = document.getElementById('reqLog');
  const flagged = d.findings && d.findings.length > 0;
  const sev     = flagged ? d.findings[0].severity : null;
  const rowCls  = sev === 'CRITICAL' || sev === 'HIGH' ? 'flagged' : sev ? 'warning' : '';
  const row     = document.createElement('div');
  row.className = `req-row ${rowCls}`;
  const size = d.content_length
    ? (d.content_length > 1024
       ? (d.content_length/1024).toFixed(1)+'K'
       : d.content_length+'B')
    : '—';
  row.innerHTML = `
    <span class="req-n">${d.n}</span>
    <span class="req-code ${codeClass(d.status_code)}">${d.error ? 'ERR' : d.status_code}</span>
    <span class="req-time">${d.response_time.toFixed(2)}s</span>
    <span class="req-size">${size}</span>
    <span class="req-cat">${d.category}</span>
    <span class="req-payload ${flagged?'flagged-payload':''}">${escHtml(d.payload)}</span>`;
  log.appendChild(row);
  if (document.getElementById('optAutoScroll').checked)
    log.scrollTop = log.scrollHeight;
}

function addFinding(f) {
  const list = document.getElementById('findingsList');
  // Remove empty-state placeholder
  const es = list.querySelector('.empty-state');
  if (es) es.remove();

  findingTotal++;
  if (sevCounts[f.severity] !== undefined) {
    sevCounts[f.severity]++;
    const idMap = {CRITICAL:'svCrit',HIGH:'svHigh',MEDIUM:'svMed',LOW:'svLow'};
    if (idMap[f.severity])
      document.getElementById(idMap[f.severity]).textContent = sevCounts[f.severity];
  }
  document.getElementById('statFindings').textContent = findingTotal;
  document.getElementById('statFindings').classList.toggle('has-findings', findingTotal > 0);
  const fc = document.getElementById('findingsCount');
  fc.textContent = findingTotal; fc.classList.add('visible');

  const card = document.createElement('div');
  card.className = 'finding-card';
  card.innerHTML = `
    <div class="finding-head" onclick="this.parentElement.classList.toggle('expanded')">
      <span class="sev-badge sev-${f.severity}">${f.severity}</span>
      <span class="finding-type">${escHtml(f.vuln_type)}</span>
    </div>
    <div class="finding-body">
      <div class="finding-row"><span class="finding-key">Reason</span><span class="finding-val">${escHtml(f.reason)}</span></div>
      <div class="finding-row"><span class="finding-key">URL</span><span class="finding-val mono">${escHtml(f.url||'')}</span></div>
      ${f.matched ? `<div class="finding-row"><span class="finding-key">Matched</span><span class="finding-val mono">${escHtml(f.matched)}</span></div>` : ''}
      <div class="finding-row"><span class="finding-key">Payload</span><span class="finding-val mono">${escHtml(f.payload||'')}</span></div>
      <div class="fix-block">💡 ${escHtml(f.fix)}</div>
    </div>`;
  list.appendChild(card);
}

function escHtml(s) {
  return String(s||'')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
    .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function toast(msg, isError=false) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className   = 'show' + (isError ? ' error' : '');
  clearTimeout(el._t);
  el._t = setTimeout(() => el.className = '', 3500);
}

// ════════════════════════════════════════════════════════════════════════
// AI INSIGHTS  – new functions (no changes to anything above this line)
// ════════════════════════════════════════════════════════════════════════

async function openAiInsights() {
  const btn = document.getElementById('btnAiInsights');
  btn.classList.add('loading');
  btn.disabled = true;

  // Show modal with loading state immediately
  showAiModal('<div class="empty-state"><div class="empty-icon" style="font-size:32px;animation:ai-spin 1s linear infinite">✦</div><div class="empty-text">Gemini is analysing your scan results…</div></div>');

  try {
    const resp = await fetch('/api/ai-insights', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ findings: _allFindings, stats: _lastStats })
    });
    const data = await resp.json();

    if (data.error) {
      renderAiError(data.error);
    } else {
      renderAiInsights(data);
    }
  } catch (err) {
    renderAiError('Network error: ' + err.message);
  } finally {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

function showAiModal(innerHtml) {
  document.getElementById('aiModalBody').innerHTML = innerHtml;
  document.getElementById('aiOverallRisk').style.display = 'none';
  document.getElementById('aiModal').classList.add('open');
}

function closeAiModal() {
  document.getElementById('aiModal').classList.remove('open');
}

// Close modal on backdrop click
document.getElementById('aiModal').addEventListener('click', function(e) {
  if (e.target === this) closeAiModal();
});

// Close modal on Escape
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeAiModal();
});

function renderAiError(msg) {
  document.getElementById('aiModalBody').innerHTML =
    `<div class="ai-error-box">⚠ ${escHtml(msg)}</div>`;
}

function renderAiInsights(data) {
  // Show overall risk badge in header
  const riskEl = document.getElementById('aiOverallRisk');
  riskEl.textContent = (data.overall_risk || 'Unknown').toUpperCase();
  riskEl.className   = `ai-overall-risk risk-${data.overall_risk || 'Informational'}`;
  riskEl.style.display = 'block';

  // Build summary
  let html = `
    <div>
      <div class="ai-section-label">Executive Summary</div>
      <div class="ai-summary-text">${escHtml(data.summary || 'No summary provided.')}</div>
    </div>`;

  // Build issue cards
  if (data.key_issues && data.key_issues.length > 0) {
    html += `<div><div class="ai-section-label">Key Issues (${data.key_issues.length})</div>
      <div style="display:flex;flex-direction:column;gap:8px;">`;

    data.key_issues.forEach((issue, i) => {
      const riskClass = `sev-${issue.risk_level ? issue.risk_level.toUpperCase() : 'INFO'}`;
      html += `
        <div class="ai-issue-card" id="ai-issue-${i}">
          <div class="ai-issue-head" onclick="toggleAiIssue(${i})">
            <span class="owasp-badge" title="${escHtml(issue.owasp_name||'')}">
              ${escHtml(issue.owasp_code||'?')}
            </span>
            <span class="ai-issue-title">${escHtml(issue.title||'Unknown Issue')}</span>
            <span class="sev-badge ${riskClass}">${escHtml(issue.risk_level||'?')}</span>
            <span class="ai-issue-chevron">›</span>
          </div>
          <div class="ai-issue-body">
            <div class="ai-field">
              <div class="ai-field-label">OWASP Category</div>
              <div class="ai-field-text">
                <strong style="color:#a78bfa">${escHtml(issue.owasp_code||'')}:</strong>
                ${escHtml(issue.owasp_name||'')}
              </div>
            </div>
            <div class="ai-field">
              <div class="ai-field-label">Explanation</div>
              <div class="ai-field-text">${escHtml(issue.explanation||'')}</div>
            </div>
            <div class="ai-field">
              <div class="ai-field-label">Remediation</div>
              <div class="ai-fix-block">💡 ${escHtml(issue.fix||'')}</div>
            </div>
            ${issue.code_snippet ? `
            <div class="ai-field">
              <div class="ai-field-label">Safe Code Example</div>
              <pre class="ai-code-block">${escHtml(issue.code_snippet)}</pre>
            </div>` : ''}
          </div>
        </div>`;
    });
    html += `</div></div>`;
  } else {
    html += `<div><div class="ai-section-label">Key Issues</div>
      <div style="color:var(--green);font-size:13px;padding:12px 0">
        ✓ No significant issues found in the scan results.
      </div></div>`;
  }

  // Recommendations
  if (data.recommendations && data.recommendations.length > 0) {
    html += `<div><div class="ai-section-label">Recommendations</div>
      <div class="ai-reco-list">`;
    data.recommendations.forEach((r, i) => {
      html += `<div class="ai-reco-item">
        <span class="ai-reco-num">${i+1}</span>
        <span>${escHtml(r)}</span>
      </div>`;
    });
    html += `</div></div>`;
  }

  // Gemini attribution footer
  html += `<div style="text-align:center;color:var(--muted);font-size:10px;padding-top:4px;border-top:1px solid var(--border)">
    Analysis powered by <strong style="color:#a78bfa">Google Gemini</strong> · OWASP Top 10 (2021) mapping
  </div>`;

  document.getElementById('aiModalBody').innerHTML = html;
}

function toggleAiIssue(i) {
  const card = document.getElementById(`ai-issue-${i}`);
  if (card) card.classList.toggle('expanded');
}
</script>
</body>
</html>"""


@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
