"""
WAF PROXY
=========
Sits in front of the vulnerable backend (http://127.0.0.1:5000) and
listens on http://127.0.0.1:8080.

Key feature: a protection ON/OFF switch.
  - WAF ON  -> every request is inspected; malicious-looking ones are
              blocked with 403 before they ever reach the backend.
  - WAF OFF -> requests pass straight through untouched (this simulates
              having no WAF at all, so you can compare before/after).

Admin / control endpoints (used by the dashboard, not by attacks):
  GET  /_waf/status   -> {"enabled": true/false}
  POST /_waf/toggle   -> flips enabled state, returns new status
  GET  /_waf/logs      -> last N request log entries (JSON)
  POST /_waf/reset_logs -> clears the in-memory log

Everything else (any other path) is treated as traffic to inspect and
forward to the backend.
"""
import re
import time
import json
import os
from collections import defaultdict, deque
from urllib.parse import unquote_plus
from flask import Flask, request, jsonify, Response
import requests

BACKEND = "http://127.0.0.1:5000"
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "waf_log.jsonl")

app = Flask(__name__)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
STATE = {"enabled": True}

# in-memory log, most recent last; also appended to LOG_FILE on disk
LOG = deque(maxlen=500)

# rate limiting: ip -> deque of request timestamps
RATE_WINDOW_SECONDS = 10
RATE_MAX_REQUESTS = 20
request_times = defaultdict(lambda: deque())

MAX_BODY_BYTES = 8 * 1024  # oversized payload threshold

# ---------------------------------------------------------------------------
# Layer 1: signature rules (regex blocklists)
# ---------------------------------------------------------------------------
SQLI_PATTERNS = [
    r"(\bunion\b\s+(all\s+)?\bselect\b)",
    r"(\bor\b\s*['\"]?\s*\d+\s*=\s*\d+)",
    r"(\band\b\s*['\"]?\s*\d+\s*=\s*\d+)",
    r"('\s*or\s*'\w*'\s*=\s*'\w*)",
    r"(--|#|\/\*)",                       # SQL comment markers
    r"(;\s*drop\b)",
    r"(\bsleep\s*\(\s*\d+\s*\))",         # timing-based SQLi
    r"(\bxp_cmdshell\b)",
]

XSS_PATTERNS = [
    r"<\s*script[^>]*>",
    r"on(error|load|click|mouseover|focus)\s*=",
    r"javascript\s*:",
    r"<\s*img[^>]+on\w+\s*=",
    r"<\s*svg[^>]*on\w+\s*=",
    r"document\.cookie",
]

PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
]
# Deliberately NOT matching raw "%2e%2e%2f" style tokens here: we rely on the
# single unquote_plus() decode pass (see proxy()) to turn single-encoded
# traversal into the literal "../" this list already catches. A payload
# encoded TWICE will still look like "%2f" after that one decode pass and
# will slip past these two patterns -- that's the intentional bypass to find.

COMPILED_RULES = [
    ("SQLI_SIGNATURE", [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]),
    ("XSS_SIGNATURE", [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]),
    ("PATH_TRAVERSAL_SIGNATURE", [re.compile(p, re.IGNORECASE) for p in PATH_TRAVERSAL_PATTERNS]),
]


def inspect_signatures(text):
    """Return the first matching reason code, or None if clean."""
    if not text:
        return None
    for reason, patterns in COMPILED_RULES:
        for pat in patterns:
            if pat.search(text):
                return reason
    return None


def check_rate_limit(ip):
    now = time.time()
    dq = request_times[ip]
    while dq and now - dq[0] > RATE_WINDOW_SECONDS:
        dq.popleft()
    dq.append(now)
    if len(dq) > RATE_MAX_REQUESTS:
        return True
    return False


def log_entry(entry):
    LOG.append(entry)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Admin endpoints
# ---------------------------------------------------------------------------
@app.route("/_waf/status")
def waf_status():
    return jsonify({"enabled": STATE["enabled"]})


@app.route("/_waf/toggle", methods=["POST"])
def waf_toggle():
    STATE["enabled"] = not STATE["enabled"]
    return jsonify({"enabled": STATE["enabled"]})


@app.route("/_waf/logs")
def waf_logs():
    n = int(request.args.get("n", 100))
    return jsonify(list(LOG)[-n:])


@app.route("/_waf/reset_logs", methods=["POST"])
def waf_reset_logs():
    LOG.clear()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# Main proxy handler
# ---------------------------------------------------------------------------
@app.route("/", defaults={"path": ""}, methods=["GET", "POST", "PUT", "DELETE"])
@app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy(path):
    start = time.time()
    src_ip = request.remote_addr or "unknown"
    full_query = request.query_string.decode("utf-8", errors="ignore")
    body_text = request.get_data(as_text=True) or ""

    # Decode ONE pass of URL-encoding before inspecting. This is realistic
    # (real HTTP clients/browsers percent-encode special characters in query
    # strings and form bodies, so a WAF that never decodes would miss almost
    # everything) but it's also deliberately incomplete: a payload that is
    # percent-encoded TWICE will only get decoded once here and can slip
    # through. That's a genuine, well-documented WAF bypass technique for
    # you to find in Phase 5 (bypass -> patch -> re-test) -- try adding a
    # second decode pass and see what changes.
    decoded_query = unquote_plus(full_query)
    decoded_body = unquote_plus(body_text)
    inspect_blob = f"{path}?{decoded_query} {decoded_body}"

    action = "ALLOWED"
    reason = None
    status_code = None

    if STATE["enabled"]:
        # oversized payload check
        content_length = request.content_length or 0
        if content_length > MAX_BODY_BYTES:
            action, reason, status_code = "BLOCKED", "OVERSIZED_PAYLOAD", 413
        # rate limiting
        elif check_rate_limit(src_ip):
            action, reason, status_code = "BLOCKED", "RATE_LIMIT", 429
        else:
            sig = inspect_signatures(inspect_blob)
            if sig:
                action, reason, status_code = "BLOCKED", sig, 403

    if action == "BLOCKED":
        resp_body = {"blocked": True, "reason": reason}
        latency_ms = round((time.time() - start) * 1000, 2)
        log_entry({
            "ts": time.time(), "ip": src_ip, "method": request.method,
            "path": "/" + path, "query": full_query, "waf_enabled": STATE["enabled"],
            "action": action, "reason": reason, "status_code": status_code,
            "latency_ms": latency_ms,
        })
        return jsonify(resp_body), status_code

    # forward to backend (either WAF is off, or request looked clean)
    try:
        backend_resp = requests.request(
            method=request.method,
            url=f"{BACKEND}/{path}",
            params=request.args,
            data=request.get_data(),
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            timeout=5,
        )
        status_code = backend_resp.status_code
        content_type = backend_resp.headers.get("Content-Type", "application/octet-stream")
        latency_ms = round((time.time() - start) * 1000, 2)
        log_entry({
            "ts": time.time(), "ip": src_ip, "method": request.method,
            "path": "/" + path, "query": full_query, "waf_enabled": STATE["enabled"],
            "action": "ALLOWED", "reason": None, "status_code": status_code,
            "latency_ms": latency_ms,
        })
        return Response(backend_resp.content, status=status_code, content_type=content_type)
    except requests.exceptions.RequestException as e:
        latency_ms = round((time.time() - start) * 1000, 2)
        log_entry({
            "ts": time.time(), "ip": src_ip, "method": request.method,
            "path": "/" + path, "query": full_query, "waf_enabled": STATE["enabled"],
            "action": "ERROR", "reason": str(e), "status_code": 502,
            "latency_ms": latency_ms,
        })
        return jsonify({"error": "backend unreachable", "detail": str(e)}), 502


if __name__ == "__main__":
    print("WAF proxy running on http://127.0.0.1:8080  (forwarding to backend on :5000)")
    app.run(host="127.0.0.1", port=8080, debug=False)
