"""Controlled, harmless text perturbations used for robustness checks (FR-05, AT-03, CP-5)."""
import random
import re


def defang_alt(subject, body):
    return subject, body.replace("[.]", "(.)").replace("hxxp", "hXXp")


def defang_dot(subject, body):
    """Unsupported defang style on purpose: shows a limitation of the URL parser."""
    return subject, body.replace("[.]", "[dot]")


def punct_noise(subject, body):
    b = body.replace(". ", "... ").replace(":", " :").replace(",", " ,")
    return subject, b.rstrip() + " !!"


def case_upper(subject, body):
    return subject.upper(), body.upper()


def char_sub(subject, body):
    rng = random.Random(len(body) * 31 + len(subject))
    table = {"o": "0", "l": "1", "a": "@", "e": "3", "i": "1"}

    def sub(text):
        out, in_url = [], False
        for tok in re.split(r"(\s+)", text):
            if "xx" in tok.lower() or "://" in tok:
                out.append(tok)
                continue
            out.append("".join(table[ch] if ch in table and rng.random() < 0.12 else ch for ch in tok))
        return "".join(out)

    return sub(subject), sub(body)


def benign_pad(subject, body):
    return subject, body.rstrip() + "\n\nThank you for your time. Have a lovely day."


def urgency_add(subject, body):
    return subject, "Please respond today. " + body


PERTURBATIONS = {
    "defang_alt": ("Defang style: [.] -> (.), hxxp -> hXXp", defang_alt),
    "defang_dot": ("Defang style: [.] -> [dot] (unsupported)", defang_dot),
    "punct_noise": ("Punctuation noise: '...', spaced colons, '!!'", punct_noise),
    "case_upper": ("ALL CAPS", case_upper),
    "char_sub": ("Character substitution (o->0, l->1, a->@ ...)", char_sub),
    "benign_pad": ("Benign padding sentence appended", benign_pad),
    "urgency_add": ("Harmless urgency cue prepended", urgency_add),
}
