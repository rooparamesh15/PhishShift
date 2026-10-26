"""Local dashboard server (standard library http.server, bound to 127.0.0.1 only).

NFR-01: this server never fetches, opens or executes any URL found in a message.
It does not import any HTTP-client library.
"""
import json
import mimetypes
import os
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import joblib
import pandas as pd

from . import config, cues, pipeline, sanitize

STATE = {"bundle": None, "status": "idle", "message": ""}
LOCK = threading.Lock()
DOWNLOAD_DIRS = {"outputs": config.OUTPUTS, "processed": config.DATA_PROC, "raw": config.DATA_RAW, "docs": config.DOCS}
MAX_BODY = 20000


def load_bundle():
    p = os.path.join(config.MODELS, f"phishshift_model_{config.MODEL_VERSION}.joblib")
    STATE["bundle"] = joblib.load(p) if os.path.exists(p) else None
    return STATE["bundle"]


def scan(payload):
    b = STATE["bundle"]
    if b is None:
        return {"error": "Model not trained yet. Click 'Re-run pipeline' on the Tests tab."}
    channel = "sms" if str(payload.get("channel", "email")).lower().strip() == "sms" else "email"
    subject = str(payload.get("subject", ""))[:300]
    body = str(payload.get("body", ""))[:MAX_BODY]
    sender = str(payload.get("sender_type", "unknown"))
    if sender not in ("internal", "vendor", "external_free", "unknown", "lookalike"):
        sender = "unknown"
    conf = float(payload.get("abstain_conf", b["abstain_conf"]))
    if not body.strip():
        return {"error": "Paste a message body first."}
    # NFR-02: redact personal data / secrets before anything else touches the text
    subject, f1 = sanitize.redact_pii(subject)
    body, f2 = sanitize.redact_pii(body)
    flags = {k: f1.get(k, 0) + f2.get(k, 0) for k in set(f1) | set(f2)}
    body, n_def = sanitize.defang_text(body)       # links are only ever treated as text
    body, n_att = sanitize.strip_attachments(body)
    feats = sanitize.url_features(body)
    fstr = sanitize.features_string(feats)
    row = pd.DataFrame([dict(message_id="LIVE", channel=channel, subject_or_title=subject, body_text=body,
                             sender_domain_type=sender, sanitized_url_features=fstr, label="legit", campaign_group="live",
                             collected_date="", legit_urgent=0, source="live")])
    row = pipeline.featurise(row)
    P = pipeline.predict_all(b["models"], row)
    probs = {k: float(v[0]) for k, v in P.items()}
    primary = b["primary"]
    p = probs[primary]
    confidence = max(p, 1 - p)
    if confidence < conf:
        verdict, level = "Needs human review", "review"
    elif p >= 0.5:
        verdict, level = "Likely phishing", "phish"
    else:
        verdict, level = "Likely legitimate", "legit"
    score, cs = cues.score_message(channel, subject, body, sender, feats)
    cs.sort(key=lambda c: -abs(c["weight"]))
    terms = pipeline.lr_terms(b["models"]["tfidf_lr"], row["text_full"].iloc[0])
    return {"verdict": verdict, "level": level, "primary_model": primary, "probability_phish": p, "confidence": confidence,
            "abstain_conf": conf, "probabilities": probs, "cues": cs, "rule_score": score, "model_terms": terms,
            "url_features": {k: v for k, v in feats.items() if not k.startswith("_")}, "links_defanged": n_def,
            "attachment_lines_removed": n_att, "redactions": flags, "sanitized_body": body,
            "disclaimer": "Decision support only - this is not a guarantee that a message is safe or malicious. "
                          "Links in the message were never opened."}


def retrain():
    with LOCK:
        STATE["status"], STATE["message"] = "running", "Re-running pipeline ..."
    try:
        pipeline.run()
        load_bundle()
        with LOCK:
            STATE["status"], STATE["message"] = "done", "Pipeline finished. Reload the dashboard data."
    except Exception as e:  # pragma: no cover
        with LOCK:
            STATE["status"], STATE["message"] = "error", str(e)


class Handler(BaseHTTPRequestHandler):
    server_version = "PhishShift/1.0"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str).encode("utf-8")
        elif isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            with open(os.path.join(config.WEB, "dashboard.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if path == "/api/summary":
            p = os.path.join(config.OUTPUTS, "summary.json")
            if not os.path.exists(p):
                return self._send(404, {"error": "summary.json missing - run the pipeline"})
            with open(p, "rb") as f:
                return self._send(200, f.read())
        if path == "/api/status":
            return self._send(200, dict(STATE, bundle=None, has_model=STATE["bundle"] is not None))
        if path == "/api/artifacts":
            out = []
            for key, d in DOWNLOAD_DIRS.items():
                if os.path.isdir(d):
                    for fn in sorted(os.listdir(d)):
                        fp = os.path.join(d, fn)
                        if os.path.isfile(fp):
                            out.append({"group": key, "name": fn, "kb": round(os.path.getsize(fp) / 1024, 1), "url": f"/files/{key}/{fn}"})
            return self._send(200, out)
        if path.startswith("/files/"):
            parts = path[len("/files/"):].split("/", 1)
            if len(parts) == 2 and parts[0] in DOWNLOAD_DIRS:
                base = os.path.realpath(DOWNLOAD_DIRS[parts[0]])
                fp = os.path.realpath(os.path.join(base, os.path.basename(parts[1])))
                if fp.startswith(base) and os.path.isfile(fp):
                    ctype = mimetypes.guess_type(fp)[0] or "application/octet-stream"
                    with open(fp, "rb") as f:
                        return self._send(200, f.read(), ctype, {"Content-Disposition": f'attachment; filename="{os.path.basename(fp)}"'})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if n > 200000:
            return self._send(413, {"error": "too large"})
        try:
            payload = json.loads(self.rfile.read(n) or b"{}")
        except json.JSONDecodeError:
            return self._send(400, {"error": "invalid JSON"})
        if self.path == "/api/scan":
            try:
                return self._send(200, scan(payload))
            except Exception as e:  # graceful error handling (T6)
                return self._send(500, {"error": f"Could not scan this message: {e}"})
        if self.path == "/api/retrain":
            if STATE["status"] == "running":
                return self._send(409, {"error": "already running"})
            threading.Thread(target=retrain, daemon=True).start()
            return self._send(202, {"status": "started"})
        return self._send(404, {"error": "not found"})


def serve(port=8765, open_browser=True):
    load_bundle()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/"
    print(f"\n  PhishShift dashboard running at {url}\n  (press Ctrl+C to stop)\n", flush=True)
    if open_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
