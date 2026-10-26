"""Transparent rule baseline + safe explanation of risk cues (FR-02, FR-04).

Explanations only quote the message's own words and describe the *pattern*;
they never open links or reveal anything beyond the submitted text.
"""
import math
import re
from . import sanitize

TEXT_CUES = [
    ("Urgency / time pressure", 1.0,
     r"\b(urgent|immediately|right away|asap|within \d+ hours|act now|final notice|final reminder|"
     r"before the end of the day|as soon as you see|expires? (today|in)|hurry|before spots run out|only a few)\b",
     "Pushes the reader to act before thinking or checking."),
    ("Credential / payment-detail request", 1.8,
     r"\b(verify|confirm|re-?enter|enter|submit|keep)\b[^.\n]{0,45}\b(password|login|credentials|bank|card|code|username)\b",
     "Asks the reader to hand over a secret or account detail."),
    ("Threat of loss or penalty", 1.2,
     r"(suspend|deactivat|lock(ed)? ?out|lock your|will be closed|disabled|penalt|legal action|will be returned|cancelled|loss of access)",
     "Warns of a bad outcome to force compliance."),
    ("Generic greeting", 0.6,
     r"^\s*(dear (user|customer|employee|staff)|attention (customer|staff)|notice:|attention:)",
     "Real senders usually know the recipient's name."),
    ("Payment / banking pressure", 0.7,
     r"\b(pay now|pay the|fee|overdue|unpaid|remittance|new account|new bank|beneficiary account|payment details)\b",
     "Money movement is a common phishing goal."),
    ("Secrecy or channel switching", 1.6,
     r"(discreet|between us|quietly|rather than on the company chat|cannot take calls|reply to this message|reply here)",
     "Asks to keep things hidden or move to an unmonitored channel."),
    ("Gift / reward bait", 1.0,
     r"(gift (card|voucher)s?|claim yours|reward|bonus|appreciation draw|thank-you)",
     "Offers something to lower the reader's guard."),
]
URL_CUES = [
    ("Shortened link", 1.5, "shortener", "The real destination of a short link is hidden."),
    ("Look-alike domain", 2.2, "lookalike", "The domain imitates the organisation's real domain."),
    ("Link points to a raw IP address", 2.0, "ip_host", "Legitimate services rarely link to bare IP addresses."),
    ("Login / verify wording in link path", 0.8, "login_path", "Typical of credential-harvesting pages."),
]
NEG_CUES = [
    ("Reassurance: never asks for password", -1.8, r"(never|will not|won't) ask[^.\n]{0,30}password",
     "Genuine IT notices often say this."),
    ("Internal helpdesk extension", -0.9, r"\bext\.? ?\d{4}\b", "Points to an internal phone extension."),
    ("Routine notice wording", -0.6,
     r"(no action (is )?(needed|required)|status page|self-service|intranet|hr portal|expense system|ticket system)",
     "Typical of ordinary internal announcements."),
]
SENDER_WEIGHTS = {"lookalike": 1.0, "external_free": 0.6, "unknown": 0.4, "internal": -0.5, "vendor": 0.0}


def score_message(channel, subject, body, sender_type, feats):
    """Return (score, cue list). Positive cues push toward phishing, negative toward legitimate."""
    text = f"{subject or ''}\n{body or ''}"
    low = text.lower()
    cues = []
    score = 0.0
    for name, w, rx, why in TEXT_CUES:
        m = re.search(rx, low, flags=re.M)
        if m:
            snippet = text[m.start():m.end()] if len(m.group(0)) < 70 else text[m.start():m.start() + 70]
            cues.append({"cue": name, "weight": w, "evidence": snippet.strip(), "why": why})
            score += w
    for name, w, key, why in URL_CUES:
        if feats.get(key):
            cues.append({"cue": name, "weight": w, "evidence": "(link feature, link not opened)", "why": why})
            score += w
    if feats.get("n_urls", 0) and sender_type in ("external_free", "unknown", "lookalike"):
        cues.append({"cue": "Link from an unfamiliar sender", "weight": 0.6,
                     "evidence": f"sender type: {sender_type}", "why": "Links from unknown senders deserve extra care."})
        score += 0.6
    sw = SENDER_WEIGHTS.get(sender_type, 0.0)
    if sw > 0 and sender_type == "lookalike":
        cues.append({"cue": "Look-alike sender domain", "weight": sw, "evidence": "sender type: lookalike",
                     "why": "Sender domain imitates the organisation."})
        score += sw
    for name, w, rx, why in NEG_CUES:
        m = re.search(rx, low)
        if m:
            cues.append({"cue": name, "weight": w, "evidence": text[m.start():m.end()], "why": why})
            score += w
    if sw < 0:
        cues.append({"cue": "Internal sender", "weight": sw, "evidence": "sender type: internal",
                     "why": "Internal senders are usually legitimate (but accounts can be compromised)."})
        score += sw
    if feats.get("n_urls", 0) and feats.get("_hosts"):
        if all(h.endswith(".examplecorp.test") for h in feats["_hosts"]):
            cues.append({"cue": "Link stays on the company domain", "weight": -1.2,
                         "evidence": ", ".join(feats["_hosts"][:2]), "why": "Destination host belongs to the organisation."})
            score -= 1.2
    return score, cues


def rule_prob(score: float) -> float:
    return 1.0 / (1.0 + math.exp(-1.1 * (score - 2.4)))


def rule_predict(df):
    out = []
    for r in df.itertuples():
        feats = sanitize.url_features(str(r.body_text))
        s, _ = score_message(r.channel, r.subject_or_title, r.body_text, r.sender_domain_type, feats)
        out.append(rule_prob(s))
    return out
