# WAF Range

A hands-on target range: a deliberately vulnerable app, a WAF proxy in front
of it with an on/off protection switch, and a dashboard where you pick an
attack, fire it, and watch it get blocked or slip through.

```
Attack Dashboard (:7000)  --fires attacks-->  WAF Proxy (:8080)  -->  Vulnerable Backend (:5000)
        (your browser)                     [Protection: ON/OFF]
```

## 1. Setup

Requires Python 3.9+.

```bash
cd waf_project
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Run all three pieces

Open three terminals (all inside `waf_project/`, with the venv activated):

```bash
# Terminal 1 — the vulnerable target
python3 backend/app.py          # http://127.0.0.1:5000

# Terminal 2 — the WAF proxy sitting in front of it
python3 waf/proxy.py            # http://127.0.0.1:8080

# Terminal 3 — the dashboard you'll actually use
python3 dashboard/app.py        # http://127.0.0.1:7000
```

Open **http://127.0.0.1:7000** in your browser. That's the whole UI: a
protection on/off switch up top, live request metrics, an attack console on
the left, and a live request log on the right.

## 3. How to use it

1. Leave **Protection: on** and fire a few attacks from the console (try
   "Auth bypass via comment" under SQL injection first). Watch them land in
   the log as **Blocked**, with the signature that caught them.
2. Click the toggle to flip **Protection: off**, then fire the same attacks
   again. Now they go straight through to the backend — the login bypass
   actually logs in as `admin`, the path traversal actually reads the flag
   file. This is the before/after comparison the project asks for.
3. Flip protection back **on** and try the "obfuscated" category — see which
   ones the signature rules still catch, and which slip through.
4. Try "Rapid-fire burst" to see the rate limiter kick in independently of
   the signature rules, and "Oversized POST body" to see the size check.

## 4. What's deliberately vulnerable (`backend/app.py`)

| Endpoint  | Flaw                                         | Try |
|-----------|-----------------------------------------------|-----|
| `/login`  | Raw string-concatenated SQL query              | `username=admin'--` |
| `/search` | Unescaped output straight into HTML (XSS)      | `q=<script>alert(1)</script>` |
| `/file`   | Naive path join, no traversal sanitization     | `name=../secret_files/flag.txt` |

`admin`'s real password is `S3cur3AdminPW!` — the point of the SQLi attacks
is that you never need to know it.

## 5. How the WAF decides (`waf/proxy.py`)

Three independent layers, all optional via the single `enabled` switch:

- **Layer 1 — signatures**: regex blocklists for SQLi, XSS, and path
  traversal, checked against the request after **one pass** of URL-decoding.
- **Layer 2 — rate limiting**: more than 20 requests from one IP in a
  10-second window gets a `429`.
- **Oversized payload**: any body over 8 KB gets a `413`.

Every request — blocked or allowed — is logged with a reason code, and the
dashboard's `/api/logs` endpoint is what feeds the live table.

### A bypass that's already built in, on purpose

The "Double URL-encoded traversal" attack percent-encodes the `%` in `%2F`
itself (`%252F`). The WAF only decodes **once**, so after inspection the
string still contains an encoded slash and none of the traversal patterns
match — it sails through with `Protection: on`. This is a real, well-known
WAF evasion technique (attackers rely on WAFs and backends disagreeing about
how many times to decode). Note that in this project the Flask backend also
only decodes once, so the exploit itself doesn't actually succeed here
either — but you got past the WAF's *detection*, which is the point.
That's your starting point for Phase 5 of the project (bypass → patch →
re-test): try adding a second `unquote_plus()` pass in `proxy.py` and watch
that attack start getting blocked, and think about what a *third* encoding
layer would do next.

## 6. Extending it (matches the project's later phases)

- **Phase 7 (ML layer)**: `waf/waf_log.jsonl` accumulates every request with
  its label (blocked/allowed) and reason — a starting point for training a
  benign-vs-malicious classifier instead of relying on regexes alone.
- **Metrics for your write-up (Phase 8)**: the dashboard's metrics strip
  already tracks total/blocked/allowed/block-rate live; `waf/waf_log.jsonl`
  has full detail (latency per request, reason codes) if you want to compute
  false-positive rate against a batch of benign traffic you script yourself.

## 7. Scope

Everything here talks to `127.0.0.1` only. Don't point any of this at a
system you don't own — see the note in the original project brief.
