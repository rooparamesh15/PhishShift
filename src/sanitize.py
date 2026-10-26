"""URL defanging, URL feature extraction and PII redaction.

Nothing in this module (or anywhere in the project) opens, fetches or executes a URL (NFR-01).
URLs are treated purely as strings.
"""
import re
from . import config

URL_RE = re.compile(r"(?i)\b(?:https?|hxxps?)://[^\s<>\"']+")
TRAIL = ".,;:!?)"

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"(?<!\w)\+?\d[\d\s\-]{8,}\d(?!\w)")
CARD_RE = re.compile(r"\b(?:\d[ -]?){13,16}\b")
# 'password: xyz' / 'password = xyz' (never a URL) or 'password is <token containing a digit>'
PWD_RE = re.compile(r"(?i)\b(password|passcode|pin|otp)\s*(:|=)\s*(?!(?:https?|hxxps?|www)\b)\S+"
                    r"|\b(password|passcode|pin|otp)\s+(is)\s+(?=\S*\d)\S+")
ATTACH_RE = re.compile(r"(?im)^\s*attachment:.*$")


def refang(s: str) -> str:
    return (s.replace("hxxp", "http").replace("hXXp", "http").replace("HXXP", "http")
             .replace("[.]", ".").replace("(.)", "."))


def defang_url(url: str) -> str:
    """http://a.b/c -> hxxp://a[.]b/c (host dots only)."""
    u = refang(url)
    m = re.match(r"(?i)(https?)://([^/\s?#]+)(.*)", u)
    if not m:
        return url
    scheme, host, rest = m.groups()
    scheme = "hxxps" if scheme.lower() == "https" else "hxxp"
    return f"{scheme}://{host.replace('.', '[.]')}{rest}"


def defang_text(text: str):
    """Defang every live-looking URL in the text. Returns (text, n_changed)."""
    count = 0

    def _sub(m):
        nonlocal count
        raw = m.group(0)
        tail = ""
        while raw and raw[-1] in TRAIL:
            tail = raw[-1] + tail
            raw = raw[:-1]
        if re.match(r"(?i)https?://", raw):
            count += 1
            return defang_url(raw) + tail
        return m.group(0)

    return URL_RE.sub(_sub, text), count


def strip_attachments(text: str):
    new, n = ATTACH_RE.subn("", text)
    return new.strip(), n


def redact_pii(text: str):
    """NFR-02: mask e-mail addresses, phone numbers, card-like numbers and 'password: xxx' strings."""
    flags = {}
    for name, rx, token in (("email", EMAIL_RE, "[EMAIL]"), ("card_number", CARD_RE, "[NUMBER]"),
                            ("phone", PHONE_RE, "[PHONE]")):
        text, n = rx.subn(token, text)
        if n:
            flags[name] = n
    text, n = PWD_RE.subn(lambda m: f"{m.group(1) or m.group(3)} {m.group(2) or m.group(4)} [SECRET]", text)
    if n:
        flags["secret"] = n
    return text, flags


def _parse(u: str):
    u = refang(u)
    m = re.match(r"(?i)(https?)://([^/\s?#]+)([^\s]*)", u)
    if not m:
        return None
    scheme, netloc, rest = m.groups()
    host = netloc.lower().split("@")[-1].split(":")[0]
    return scheme.lower(), host, rest.lower()


def url_features(text: str) -> dict:
    """Features from the (defanged) URLs inside a message. Pure string analysis."""
    urls = []
    for m in URL_RE.finditer(text):
        raw = m.group(0)
        while raw and raw[-1] in TRAIL:
            raw = raw[:-1]
        p = _parse(raw)
        if p:
            urls.append(p)
    f = dict(n_urls=min(len(urls), 3), shortener=0, ip_host=0, lookalike=0, subdomains=0, login_path=0, https=0)
    for scheme, host, rest in urls:
        if host in config.SHORTENER_DOMAINS:
            f["shortener"] = 1
        if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host):
            f["ip_host"] = 1
        is_company = host == config.COMPANY_DOMAIN or host.endswith("." + config.COMPANY_DOMAIN)
        if re.search(r"examp[l1i]e?corp", host) and not is_company:
            f["lookalike"] = 1
        f["subdomains"] = max(f["subdomains"], min(max(host.count(".") - 1, 0), 3))
        if re.search(r"login|verify|secure|account|update|signin|confirm|pay", rest):
            f["login_path"] = 1
        if scheme == "https":
            f["https"] = 1
    f["_hosts"] = [h for _, h, _ in urls]
    return f


def features_string(f: dict) -> str:
    keys = ["n_urls", "shortener", "ip_host", "lookalike", "subdomains", "login_path", "https"]
    return ";".join(f"{k}={f[k]}" for k in keys)


def parse_features_string(s: str) -> dict:
    out = {}
    for kv in str(s).split(";"):
        if "=" in kv:
            k, v = kv.split("=", 1)
            try:
                out[k] = int(v)
            except ValueError:
                out[k] = 0
    return out


def model_text(channel, subject, body, sender_type, feat_str, with_meta=True) -> str:
    """Text fed to the ML models. URLs are replaced by a token so models learn wording,
    not hostnames; URL traits come in through url_features instead."""
    body_nourl = URL_RE.sub(" urltoken ", str(body))
    subject = "" if subject is None else str(subject)
    if not with_meta:
        return f"{subject} . {body_nourl}"
    toks = " ".join("f_" + kv.replace("=", "_") for kv in str(feat_str).split(";"))
    return f"chan_{channel} send_{sender_type} {toks} {subject} . {body_nourl}"
