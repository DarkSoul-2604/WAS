"""
ATTACK DASHBOARD
================
Serves the control-panel UI on http://127.0.0.1:7000

This process is the one that actually fires the crafted attack
payloads. It always sends them to the WAF proxy (127.0.0.1:8080),
never straight to the backend -- the whole point is to see the WAF
catch (or miss) them, and you flip WAF protection on/off from here.

Endpoints consumed by the frontend (static/app.js):
  GET  /api/attacks        -> the attack catalog (id, name, category, description, payload preview)
  GET  /api/status         -> {"waf_enabled": bool, "backend_up": bool}
  POST /api/toggle         -> flips WAF protection, returns new status
  GET  /api/logs?n=100     -> recent request log entries + computed metrics
  POST /api/reset          -> clears the WAF's log
  POST /api/attack         -> body {"id": "<attack id>"} -> fires it, returns the result
"""
import time
import requests
from flask import Flask, request, jsonify, render_template

WAF = "http://127.0.0.1:8080"
BACKEND_HEALTH = "http://127.0.0.1:5000/health"

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Attack catalog: one source of truth, rendered into the UI and executed here
# ---------------------------------------------------------------------------
ATTACKS = [
    {
        "id": "sqli_auth_bypass",
        "category": "SQL injection",
        "name": "Auth bypass via comment",
        "description": "Closes the quote then comments out the password check.",
        "payload": "username=admin'--&password=x",
        "request": {"method": "GET", "path": "/login",
                    "params": {"username": "admin'--", "password": "x"}},
    },
    {
        "id": "sqli_or_true",
        "category": "SQL injection",
        "name": "Tautology (OR 1=1)",
        "description": "Classic always-true clause to fall through the WHERE.",
        "payload": "username=' OR '1'='1&password=' OR '1'='1",
        "request": {"method": "GET", "path": "/login",
                    "params": {"username": "' OR '1'='1", "password": "' OR '1'='1"}},
    },
    {
        "id": "sqli_union",
        "category": "SQL injection",
        "name": "UNION-based probe",
        "description": "Attempts to union in data from the users table via search.",
        "payload": "q=' UNION SELECT username,password FROM users--",
        "request": {"method": "GET", "path": "/search",
                    "params": {"q": "' UNION SELECT username,password FROM users--"}},
    },
    {
        "id": "sqli_obfuscated",
        "category": "SQL injection (obfuscated)",
        "name": "Case-mixed + inline comment",
        "description": "Mixes case and hides a comment token inside the payload.",
        "payload": "username=AdMiN'/**/--&password=x",
        "request": {"method": "GET", "path": "/login",
                    "params": {"username": "AdMiN'/**/--", "password": "x"}},
    },
    {
        "id": "sqli_timing",
        "category": "SQL injection (timing probe)",
        "name": "SLEEP() timing probe",
        "description": "Blind-SQLi probe: if it's not blocked, the response is delayed.",
        "payload": "username=admin' AND SLEEP(3)--&password=x",
        "request": {"method": "GET", "path": "/login",
                    "params": {"username": "admin' AND SLEEP(3)--", "password": "x"}},
    },
    {
        "id": "xss_reflected",
        "category": "XSS",
        "name": "Reflected <script> tag",
        "description": "Plain inline script tag reflected back into the page.",
        "payload": "q=<script>alert(1)</script>",
        "request": {"method": "GET", "path": "/search",
                    "params": {"q": "<script>alert(1)</script>"}},
    },
    {
        "id": "xss_img_onerror",
        "category": "XSS",
        "name": "img onerror handler",
        "description": "Avoids the word 'script' entirely, uses an event handler instead.",
        "payload": "q=<img src=x onerror=alert(1)>",
        "request": {"method": "GET", "path": "/search",
                    "params": {"q": "<img src=x onerror=alert(1)>"}},
    },
    {
        "id": "xss_encoded",
        "category": "XSS (obfuscated)",
        "name": "URL-encoded script tag",
        "description": "Same payload, percent-encoded to test decode-before-inspect.",
        "payload": "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "request": {"method": "GET", "path": "/search",
                    "params": {"q": "%3Cscript%3Ealert(1)%3C%2Fscript%3E"}, "raw_query": True},
    },
    {
        "id": "path_traversal_basic",
        "category": "Path traversal",
        "name": "Plain ../ traversal",
        "description": "Walks up out of public_files to read the secret flag.",
        "payload": "name=../secret_files/flag.txt",
        "request": {"method": "GET", "path": "/file",
                    "params": {"name": "../secret_files/flag.txt"}},
    },
    {
        "id": "path_traversal_encoded",
        "category": "Path traversal (obfuscated)",
        "name": "URL-encoded traversal",
        "description": "Percent-encodes the slashes to dodge a naive '../' string match.",
        "payload": "name=..%2Fsecret_files%2Fflag.txt",
        "request": {"method": "GET", "path": "/file",
                    "params": {"name": "..%2Fsecret_files%2Fflag.txt"}, "raw_query": True},
    },
    {
        "id": "path_traversal_double_encoded",
        "category": "Path traversal (obfuscated)",
        "name": "Double URL-encoded traversal",
        "description": "Encodes the percent sign itself, hoping for a second decode pass.",
        "payload": "name=..%252Fsecret_files%252Fflag.txt",
        "request": {"method": "GET", "path": "/file",
                    "params": {"name": "..%252Fsecret_files%252Fflag.txt"}, "raw_query": True},
    },
    {
        "id": "oversized_payload",
        "category": "Volumetric",
        "name": "Oversized POST body",
        "description": "Sends a body far larger than any legitimate search query.",
        "payload": "(~12 KB of body)",
        "request": {"method": "POST", "path": "/search", "big_body": True},
    },
    {
        "id": "rate_limit_burst",
        "category": "Volumetric",
        "name": "Rapid-fire burst (25 req)",
        "description": "Fires 25 requests back-to-back to trip the rate limiter.",
        "payload": "25x GET /search?q=burst",
        "request": {"method": "BURST", "path": "/search", "params": {"q": "burst"}},
    },
]
ATTACKS_BY_ID = {a["id"]: a for a in ATTACKS}


def fire_single(spec, session=None):
    s = session or requests
    method = spec["request"]["method"]
    path = spec["request"]["path"]
    start = time.time()
    try:
        if spec["request"].get("big_body"):
            body = "q=" + ("A" * 12000)
            r = s.post(f"{WAF}{path}", data=body,
                       headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=8)
        elif spec["request"].get("raw_query"):
            qs = "&".join(f"{k}={v}" for k, v in spec["request"]["params"].items())
            r = s.get(f"{WAF}{path}?{qs}", timeout=8)
        else:
            params = spec["request"].get("params", {})
            if method == "GET":
                r = s.get(f"{WAF}{path}", params=params, timeout=8)
            else:
                r = s.post(f"{WAF}{path}", data=params, timeout=8)
        latency_ms = round((time.time() - start) * 1000, 2)
        try:
            body_json = r.json()
        except ValueError:
            body_json = {"raw": r.text[:300]}
        blocked = isinstance(body_json, dict) and body_json.get("blocked") is True
        return {
            "ok": True,
            "status_code": r.status_code,
            "blocked": blocked,
            "reason": body_json.get("reason") if isinstance(body_json, dict) else None,
            "latency_ms": latency_ms,
            "response_preview": str(body_json)[:300],
        }
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": str(e)}


@app.route("/")
def index():
    return render_template("index.html", attacks=ATTACKS)


@app.route("/api/attacks")
def api_attacks():
    return jsonify(ATTACKS)


@app.route("/api/status")
def api_status():
    waf_enabled = None
    backend_up = False
    try:
        r = requests.get(f"{WAF}/_waf/status", timeout=3)
        waf_enabled = r.json().get("enabled")
    except requests.exceptions.RequestException:
        pass
    try:
        r2 = requests.get(BACKEND_HEALTH, timeout=3)
        backend_up = r2.status_code == 200
    except requests.exceptions.RequestException:
        pass
    return jsonify({"waf_enabled": waf_enabled, "backend_up": backend_up})


@app.route("/api/toggle", methods=["POST"])
def api_toggle():
    try:
        r = requests.post(f"{WAF}/_waf/toggle", timeout=3)
        return jsonify(r.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 502


@app.route("/api/logs")
def api_logs():
    n = request.args.get("n", 100)
    try:
        r = requests.get(f"{WAF}/_waf/logs", params={"n": n}, timeout=3)
        entries = r.json()
    except requests.exceptions.RequestException:
        entries = []
    blocked = sum(1 for e in entries if e.get("action") == "BLOCKED")
    allowed = sum(1 for e in entries if e.get("action") == "ALLOWED")
    total = len(entries)
    return jsonify({
        "entries": list(reversed(entries)),
        "metrics": {
            "total": total, "blocked": blocked, "allowed": allowed,
            "block_rate": round(100 * blocked / total, 1) if total else 0,
        },
    })


@app.route("/api/reset", methods=["POST"])
def api_reset():
    try:
        requests.post(f"{WAF}/_waf/reset_logs", timeout=3)
    except requests.exceptions.RequestException:
        pass
    return jsonify({"ok": True})


@app.route("/api/attack", methods=["POST"])
def api_attack():
    payload = request.get_json(force=True, silent=True) or {}
    attack_id = payload.get("id")
    spec = ATTACKS_BY_ID.get(attack_id)
    if not spec:
        return jsonify({"ok": False, "error": "unknown attack id"}), 400

    if spec["request"]["method"] == "BURST":
        session = requests.Session()
        results = []
        for _ in range(25):
            results.append(fire_single(spec, session))
        blocked_count = sum(1 for r in results if r.get("blocked"))
        return jsonify({
            "ok": True, "burst": True, "count": len(results),
            "blocked_count": blocked_count,
            "last_result": results[-1] if results else None,
        })

    result = fire_single(spec)
    return jsonify(result)


if __name__ == "__main__":
    print("Attack dashboard running on http://127.0.0.1:7000")
    app.run(host="127.0.0.1", port=7000, debug=False)
