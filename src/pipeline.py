"""End-to-end training / evaluation pipeline for PhishShift (ML-07).

Run:  python -m src.pipeline        (or just run.py)
Outputs go to outputs/ (JSON + CSV evidence), data/processed/ and models/.
"""
import datetime as dt
import hashlib
import json
import os
import platform
import re
import sys
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from scipy.sparse import csr_matrix
from scipy.sparse.csgraph import connected_components
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

from . import config, cues, generate_data, sanitize
from .perturb import PERTURBATIONS

MODEL_LABELS = {"rules": "Rule-based cues", "tfidf_lr": "TF-IDF + Logistic Regression",
                "char_svm": "Char n-gram TF-IDF + calibrated Linear SVM"}


# ----------------------------------------------------------------------------- helpers
def _j(o):
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, (np.ndarray,)):
        return o.tolist()
    if isinstance(o, (dt.date, dt.datetime)):
        return o.isoformat()
    raise TypeError(type(o))


def save_json(obj, name):
    os.makedirs(config.OUTPUTS, exist_ok=True)
    with open(os.path.join(config.OUTPUTS, name), "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, default=_j)


def log(msg):
    print(f"[phishshift] {msg}", flush=True)


# ----------------------------------------------------------------------------- 1. clean (T2)
def clean_raw(raw: pd.DataFrame):
    df = raw.copy()
    L = []

    def add(step, n, note):
        L.append({"step": step, "rows_affected": int(n), "note": note})

    add("load_raw", len(df), "raw_messages.csv left unchanged on disk (data/raw/); all fixes applied to a copy")
    before = df["channel"].astype(str)
    df["channel"] = before.str.strip().str.lower()
    add("normalise_channel", (before != df["channel"]).sum(), "trim + lowercase (Email/EMAIL/' sms ' -> email/sms)")

    labmap = {"phish": 1, "phishing": 1, "1": 1, "legit": 0, "benign": 0, "0": 0}
    lab = df["label"].astype(str).str.strip().str.lower().map(labmap)
    bad = lab.isna().sum()
    spelling = (df["label"].astype(str) != df["label"].astype(str).str.strip().str.lower()).sum() + \
        df["label"].astype(str).str.strip().str.lower().isin(["phishing", "1", "benign", "0"]).sum()
    df["label_num"] = lab
    df = df[df["label_num"].notna()].copy()
    add("map_labels", spelling, "label spellings (Phish/PHISHING/1, Legit/benign/0) -> {phish, legit}")
    add("drop_unknown_label", bad, "rows with unmappable label removed")
    df["label"] = np.where(df["label_num"] == 1, "phish", "legit")

    def pdate(s):
        for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%b %d, %Y"):
            try:
                return dt.datetime.strptime(str(s).strip(), fmt).date()
            except ValueError:
                pass
        return pd.NaT

    parsed = df["collected_date"].map(pdate)
    add("parse_dates", (df["collected_date"].astype(str) != parsed.astype(str)).sum(), "3 date formats -> ISO yyyy-mm-dd")
    df["collected_date"] = parsed
    add("drop_bad_dates", df["collected_date"].isna().sum(), "rows with unparseable date")
    df = df[df["collected_date"].notna()].copy()

    miss = df["sender_domain_type"].isna() | (df["sender_domain_type"].astype(str).str.strip() == "")
    df.loc[miss, "sender_domain_type"] = "unknown"
    add("fill_missing_sender_type", miss.sum(), "missing sender_domain_type -> 'unknown' (kept as its own category)")

    df["subject_or_title"] = df["subject_or_title"].fillna("").astype(str).str.strip()
    em = ((df["channel"] == "email") & (df["subject_or_title"] == "")).sum()
    df.loc[(df["channel"] == "email") & (df["subject_or_title"] == ""), "subject_or_title"] = "(no subject)"
    add("fill_missing_subject", em, "empty e-mail subject -> '(no subject)'; SMS keeps empty subject by design")

    body0 = df["body_text"].astype(str)
    df["body_text"] = body0.str.replace(r"[ \t]+\n", "\n", regex=True).str.replace(r"\n{3,}", "\n\n", regex=True).str.strip()
    add("normalise_whitespace", (body0 != df["body_text"]).sum(), "trailing spaces / blank lines trimmed")

    res = df["body_text"].map(sanitize.strip_attachments)
    df["body_text"] = res.map(lambda t: t[0])
    add("strip_attachment_lines", res.map(lambda t: t[1]).sum(), "'Attachment: file.pdf' lines removed (attachments excluded by SRS)")

    res = df["body_text"].map(sanitize.defang_text)
    df["body_text"] = res.map(lambda t: t[0])
    add("defang_urls", res.map(lambda t: t[1]).sum(), "live-looking http(s):// URLs rewritten to hxxp(s)://host[.]tld (inert strings)")

    res = df["body_text"].map(sanitize.redact_pii)
    df["body_text"] = res.map(lambda t: t[0])
    add("redact_pii", res.map(lambda t: sum(t[1].values())).sum(), "e-mails / phones / card-like numbers / 'password: x' redacted (NFR-02)")

    feats = df["body_text"].map(sanitize.url_features)
    df["sanitized_url_features"] = feats.map(sanitize.features_string)
    add("extract_url_features", (feats.map(lambda f: f["n_urls"]) > 0).sum(), "URL traits derived from strings only; links never opened (NFR-01)")

    df["legit_urgent"] = df["legit_urgent"].astype(int)
    df["campaign_group"] = df["campaign_group"].astype(str)
    cols = config.SCHEMA + ["legit_urgent", "source"]
    return df[cols].reset_index(drop=True), L


def featurise(df, with_meta=True):
    df = df.copy()
    df["text_full"] = [sanitize.model_text(r.channel, r.subject_or_title, r.body_text, r.sender_domain_type,
                                           r.sanitized_url_features, True) for r in df.itertuples()]
    df["text_only"] = [sanitize.model_text(r.channel, r.subject_or_title, r.body_text, r.sender_domain_type,
                                           r.sanitized_url_features, False) for r in df.itertuples()]
    return df


# ----------------------------------------------------------------------------- 2. dedup (FR-01)
def norm_for_dedup(subject, body):
    t = f"{subject} {body}".lower()
    t = sanitize.URL_RE.sub(" urltoken ", t)
    for n in generate_data.NAMES:
        t = re.sub(rf"\b{n.lower()}\b", " nametoken ", t)
    return re.sub(r"\d+", " 0 ", t)


def dedup(df):
    texts = [norm_for_dedup(s, b) for s, b in zip(df["subject_or_title"], df["body_text"])]
    X = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True).fit_transform(texts)
    sim = (X @ X.T).toarray()
    y = df["label"].to_numpy(dtype=object)
    same = (y[:, None] == y[None, :])
    cross_label = int(((sim >= config.DEDUP_THRESHOLD) & ~same).sum() // 2)
    adj = csr_matrix((sim >= config.DEDUP_THRESHOLD) & same)
    n_comp, comp = connected_components(adj, directed=False)
    df = df.copy()
    df["dup_group"] = comp
    order = df.sort_values("message_id").groupby("dup_group").head(1).index
    df["is_kept"] = df.index.isin(order)
    groups = df.groupby("dup_group").agg(group_size=("message_id", "size"), kept_id=("message_id", "min"),
                                         campaign=("campaign_group", "first"), label=("label", "first")).reset_index()
    groups = groups[groups["group_size"] > 1].sort_values("group_size", ascending=False)
    kept = df[df["is_kept"]].drop(columns=["dup_group", "is_kept"]).reset_index(drop=True)
    per_camp = df.groupby("campaign_group").agg(before=("message_id", "size"), after=("is_kept", "sum")).reset_index()
    per_camp["removed"] = per_camp["before"] - per_camp["after"]
    proof = {"threshold": config.DEDUP_THRESHOLD, "method": "TF-IDF (1-2 gram) cosine on text with URLs/numbers/names masked; "
             "connected components within the same label; keep lowest message_id",
             "rows_before": len(df), "rows_after": len(kept), "removed": len(df) - len(kept),
             "duplicate_groups": int(len(groups)), "largest_group": int(groups["group_size"].max()) if len(groups) else 1,
             "cross_label_near_duplicates_not_merged": cross_label,
             "per_campaign": per_camp.to_dict("records")}
    return kept, groups, proof


def max_sim_to_train(df, train_idx, test_idx):
    texts = [norm_for_dedup(s, b) for s, b in zip(df["subject_or_title"], df["body_text"])]
    X = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True).fit_transform(texts)
    S = (X[test_idx] @ X[train_idx].T).toarray()
    return S.max(axis=1)


def sim_report(m):
    bins = [0, .5, .7, .9, config.DEDUP_THRESHOLD, 1.0001]
    h, _ = np.histogram(m, bins=bins)
    labels = ["<0.50", "0.50-0.70", "0.70-0.90", f"0.90-{config.DEDUP_THRESHOLD}", f">={config.DEDUP_THRESHOLD}"]
    return {"n_test": int(len(m)), "n_near_dup_with_train": int((m >= config.DEDUP_THRESHOLD).sum()),
            "max_similarity": float(m.max()), "histogram": dict(zip(labels, h.tolist()))}


# ----------------------------------------------------------------------------- 3. models (FR-02)
def make_models():
    return {
        "tfidf_lr": Pipeline([("tfidf", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2)),
                              ("clf", LogisticRegression(C=4.0, max_iter=3000, class_weight="balanced"))]),
        "char_svm": Pipeline([("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True, min_df=2)),
                              ("clf", CalibratedClassifierCV(LinearSVC(C=0.5), cv=3, method="sigmoid"))]),
    }


def fit_models(train_df, col="text_full"):
    ms = make_models()
    y = (train_df["label"] == "phish").astype(int).values
    for m in ms.values():
        m.fit(train_df[col].values, y)
    return ms


def predict_all(models, df, col="text_full"):
    out = {"rules": np.array(cues.rule_predict(df))}
    for k, m in models.items():
        out[k] = m.predict_proba(df[col].values)[:, 1]
    return out


def metrics(y, p, thr=0.5):
    y = np.asarray(y)
    pred = (np.asarray(p) >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {"n": int(len(y)), "accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
           "recall": recall_score(y, pred, zero_division=0), "f1": f1_score(y, pred, zero_division=0),
           "fpr": fp / (fp + tn) if (fp + tn) else 0.0, "fnr": fn / (fn + tp) if (fn + tp) else 0.0,
           "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}
    out["auc"] = roc_auc_score(y, p) if len(set(y)) == 2 else None
    return out


def abstain_stats(y, p, conf=config.ABSTAIN_CONF):
    y, p = np.asarray(y), np.asarray(p)
    c = np.maximum(p, 1 - p)
    cov = c >= conf
    pred = (p >= 0.5).astype(int)
    return {"conf_threshold": conf, "coverage": float(cov.mean()), "abstained": int((~cov).sum()),
            "accuracy_on_covered": float((pred[cov] == y[cov]).mean()) if cov.any() else None,
            "missed_phish_without_abstain": int(((pred == 0) & (y == 1)).sum()),
            "missed_phish_with_abstain": int(((pred == 0) & (y == 1) & cov).sum()),
            "false_alarms_without_abstain": int(((pred == 1) & (y == 0)).sum()),
            "false_alarms_with_abstain": int(((pred == 1) & (y == 0) & cov).sum())}


def grouped_cv(train_df):
    """Leave-campaign-pair-out CV on TRAINING campaigns only (used to choose the primary model)."""
    ph = sorted(train_df.loc[train_df.label == "phish", "campaign_group"].unique())
    lg = sorted(train_df.loc[train_df.label == "legit", "campaign_group"].unique())
    res = {"rules": [], "tfidf_lr": [], "char_svm": []}
    folds = []
    for a, b in zip(ph, lg):
        te = train_df[train_df.campaign_group.isin([a, b])]
        tr = train_df[~train_df.campaign_group.isin([a, b])]
        ms = fit_models(tr)
        P = predict_all(ms, te)
        y = (te.label == "phish").astype(int).values
        for k in res:
            res[k].append(f1_score(y, (P[k] >= .5).astype(int), zero_division=0))
        folds.append(f"{a}+{b}")
    summ = {k: {"mean_f1": float(np.mean(v)), "std_f1": float(np.std(v)), "folds": [float(x) for x in v]} for k, v in res.items()}
    return summ, folds


def lr_terms(pipe, text, k=5):
    vec, clf = pipe.named_steps["tfidf"], pipe.named_steps["clf"]
    X = vec.transform([text]).tocoo()
    names = vec.get_feature_names_out()
    contrib = [(names[c], float(v * clf.coef_[0][c])) for c, v in zip(X.col, X.data)]
    contrib.sort(key=lambda t: t[1])
    return {"toward_phishing": [t for t in contrib[::-1] if t[1] > 0][:k], "toward_legitimate": [t for t in contrib if t[1] < 0][:k]}


def explain_row(models, row_dict):
    feats = sanitize.url_features(row_dict["body_text"])
    score, cs = cues.score_message(row_dict["channel"], row_dict["subject_or_title"], row_dict["body_text"],
                                   row_dict["sender_domain_type"], feats)
    return {"rule_score": float(score), "cues": cs, "model_terms": lr_terms(models["tfidf_lr"], row_dict["text_full"])}


# ----------------------------------------------------------------------------- 4. robustness (FR-05)
def perturb_df(df, fn):
    d = df.copy()
    new = [fn(s, b) for s, b in zip(d["subject_or_title"], d["body_text"])]
    d["subject_or_title"] = [n[0] for n in new]
    d["body_text"] = [n[1] for n in new]
    d["sanitized_url_features"] = d["body_text"].map(lambda t: sanitize.features_string(sanitize.url_features(t)))
    return featurise(d)


CP5 = [
    ("A. Obvious credential phish", "phish", "email", "lookalike", "Account locked",
     "Dear user,\n\nYour account is locked. Verify your password at hxxp://examplecorp-login[.]test/verify within 24 hours.\n\nSecurity Team"),
    ("B. Subtle shared-file phish", "phish", "email", "unknown", "Meeting notes",
     "Hi Asha,\n\nSharing the notes from the call. Open them here: hxxps://docs-share-hub[.]test/d/k3m9x2\n\nBest"),
    ("C. Conversational favour request", "phish", "email", "external_free", "Quick favour",
     "Hi Ravi,\n\nAre you free? I need a task done discreetly before my next meeting. Reply here and I will explain.\n\nThanks"),
    ("D. Parcel-fee SMS", "phish", "sms", "unknown", "",
     "Your parcel PK-48213 is held. Pay Rs 120 at hxxp://tiny-lnk[.]test/ab12cd to release it."),
    ("E. Legit password-reset notice", "legit", "email", "internal", "Your password reset was completed",
     "Hi Meera,\n\nYour password reset was completed. If this was not you, call the helpdesk on ext 4455. We will never ask for your password by email.\n\nIT Helpdesk"),
    ("F. Legit payslip notice", "legit", "email", "internal", "Your payslip is available",
     "Hello,\n\nYour payslip for October is available on the HR portal: hxxps://intranet[.]examplecorp[.]test/hr/payslip\n\nHR Operations"),
    ("G. Legit urgent timesheet", "legit", "email", "internal", "URGENT: approve timesheets today",
     "Hi team,\n\nTimesheets must be approved by 5 pm today so payroll can run. Approve at hxxps://intranet[.]examplecorp[.]test/hr/approvals\n\nPayroll Team"),
    ("H. Legit security reminder", "legit", "email", "internal", "Security reminder",
     "Hi all,\n\nReminder: report suspicious emails with the report button. IT will never ask for your password.\n\nSecurity Team"),
]


def cp5_table(models, primary):
    rows = []
    for name, lab, ch, snd, subj, body in CP5:
        base = pd.DataFrame([dict(message_id="CP5", channel=ch, subject_or_title=subj, body_text=body, sender_domain_type=snd,
                                  label=lab, campaign_group="cp5", collected_date=dt.date.today(), legit_urgent=0, source="cp5")])
        base["sanitized_url_features"] = base["body_text"].map(lambda t: sanitize.features_string(sanitize.url_features(t)))
        base = featurise(base)
        variants = {"original": base}
        for key, (_, fn) in PERTURBATIONS.items():
            variants[key] = perturb_df(base, fn)
        probs = {}
        for key, d in variants.items():
            P = predict_all(models, d)
            probs[key] = {m: float(P[m][0]) for m in P}
        rows.append({"message": name, "true_label": lab, "channel": ch, "subject": subj, "probs": probs,
                     "primary_original": probs["original"][primary],
                     "flips": [k for k in probs if k != "original" and (probs[k][primary] >= .5) != (probs["original"][primary] >= .5)]})
    return rows


# ----------------------------------------------------------------------------- 5. mentor drop-in (task: unique constraint)
def load_mentor(models, train_df):
    path = os.path.join(config.DATA_MENTOR, "mentor_holdout.csv")
    if not os.path.exists(path):
        return None
    m = pd.read_csv(path)
    need = {"body_text", "label"}
    if not need.issubset(m.columns):
        return {"error": "mentor_holdout.csv needs at least body_text and label columns"}
    m["message_id"] = [f"MENTOR{i:03d}" for i in range(len(m))]
    for col, default in (("channel", "email"), ("subject_or_title", ""), ("sender_domain_type", "unknown"),
                         ("campaign_group", "mentor"), ("collected_date", dt.date.today()), ("legit_urgent", 0), ("source", "mentor")):
        if col not in m.columns:
            m[col] = default
    m, _ = clean_raw(m)
    m = featurise(m)
    P = predict_all(models, m)
    y = (m.label == "phish").astype(int).values
    texts = [norm_for_dedup(s, b) for s, b in zip(pd.concat([train_df.subject_or_title, m.subject_or_title]),
                                                  pd.concat([train_df.body_text, m.body_text]))]
    X = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True).fit_transform(texts)
    ms = (X[len(train_df):] @ X[:len(train_df)].T).toarray().max(axis=1)
    return {"n": int(len(m)), "near_duplicates_of_training": int((ms >= config.DEDUP_THRESHOLD).sum()),
            "metrics": {k: metrics(y, P[k]) for k in P}}


# ----------------------------------------------------------------------------- run
def run(force_regen=False):
    t0 = time.time()
    for d in (config.DATA_RAW, config.DATA_PROC, config.OUTPUTS, config.MODELS, config.DATA_MENTOR):
        os.makedirs(d, exist_ok=True)
    raw_path = os.path.join(config.DATA_RAW, "raw_messages.csv")
    if force_regen or not os.path.exists(raw_path):
        log("generating synthetic corpus ...")
        generate_data.generate()
    raw = pd.read_csv(raw_path, dtype=str, keep_default_na=False)
    raw_hash = hashlib.sha256(open(raw_path, "rb").read()).hexdigest()[:16]

    log("cleaning + sanitising ...")
    clean, clog = clean_raw(raw)
    clean.to_csv(os.path.join(config.DATA_PROC, "clean_messages.csv"), index=False)
    pd.DataFrame(clog).to_csv(os.path.join(config.OUTPUTS, "sanitization_log.csv"), index=False)

    log("near-duplicate removal ...")
    dd, groups, proof = dedup(clean)
    dd = featurise(dd)
    clean_f = featurise(clean)
    dd.drop(columns=["text_full", "text_only"]).to_csv(os.path.join(config.DATA_PROC, "dedup_messages.csv"), index=False)
    groups.to_csv(os.path.join(config.OUTPUTS, "dedup_groups.csv"), index=False)

    dd["y"] = (dd.label == "phish").astype(int)
    clean_f["y"] = (clean_f.label == "phish").astype(int)
    is_test = dd.campaign_group.isin(config.HOLDOUT_CAMPAIGNS)
    train, test = dd[~is_test].reset_index(drop=True), dd[is_test].reset_index(drop=True)
    log(f"rows: raw={len(raw)} clean={len(clean)} dedup={len(dd)} train={len(train)} holdout={len(test)}")

    # --- CP-2 audit of near duplicates across splits
    rs_tr, rs_te = train_test_split(np.arange(len(dd)), test_size=config.RANDOM_TEST_SIZE, stratify=dd.y, random_state=config.SEED)
    nd_tr, nd_te = train_test_split(np.arange(len(clean_f)), test_size=config.RANDOM_TEST_SIZE, stratify=clean_f.y,
                                    random_state=config.SEED)
    tr_idx = np.where(~is_test.values)[0]
    te_idx = np.where(is_test.values)[0]
    proof["cross_split_audit"] = {
        "random_split_WITHOUT_dedup": sim_report(max_sim_to_train(clean_f, nd_tr, nd_te)),
        "random_split_after_dedup": sim_report(max_sim_to_train(dd, rs_tr, rs_te)),
        "campaign_holdout_after_dedup": sim_report(max_sim_to_train(dd, tr_idx, te_idx)),
    }
    save_json(proof, "dedup_proof.json")

    # --- EDA (T3)
    log("EDA + leakage checks ...")
    eda = {"rows": {"raw": len(raw), "clean": len(clean), "dedup": len(dd)},
           "class_balance": dd.label.value_counts().to_dict(),
           "channel_by_label": pd.crosstab(dd.channel, dd.label).to_dict(),
           "sender_by_label": pd.crosstab(dd.sender_domain_type, dd.label).to_dict(),
           "campaigns": dd.groupby(["campaign_group", "label"]).size().reset_index(name="n").assign(
               role=lambda d: np.where(d.campaign_group.isin(config.HOLDOUT_CAMPAIGNS), "held-out", "train")).to_dict("records"),
           "month_by_label": pd.crosstab(pd.to_datetime(dd.collected_date).dt.strftime("%Y-%m"), dd.label).to_dict(),
           "missing_after_cleaning": {c: int(dd[c].isna().sum() + (dd[c].astype(str) == "").sum()) for c in
                                      ["subject_or_title", "body_text", "sender_domain_type"]},
           "missing_raw": {c: int((raw[c].astype(str).str.strip() == "").sum()) for c in ["subject_or_title", "body_text", "sender_domain_type"]},
           "body_length": {l: {"mean": float(dd.loc[dd.label == l, "body_text"].str.len().mean()),
                               "p95": float(dd.loc[dd.label == l, "body_text"].str.len().quantile(.95))} for l in ["phish", "legit"]},
           "length_hist": {l: np.histogram(dd.loc[dd.label == l, "body_text"].str.len(), bins=[0, 60, 100, 150, 200, 300, 500, 2000])[0].tolist()
                           for l in ["phish", "legit"]},
           "length_bins": ["<60", "60-100", "100-150", "150-200", "200-300", "300-500", ">500"],
           "outliers": {"body_len_gt_500": int((dd.body_text.str.len() > 500).sum())}}
    # single-feature leakage probes (train on train campaigns, test on holdout)
    leak = {}
    for name, feat in (("sender_domain_type only", lambda d: d.sender_domain_type), ("URL features only", lambda d: d.sanitized_url_features),
                       ("channel only", lambda d: d.channel), ("campaign_group only (must NOT be a feature)", lambda d: d.campaign_group)):
        try:
            pipe = Pipeline([("v", TfidfVectorizer(analyzer=lambda s: [s])), ("c", LogisticRegression(max_iter=500))])
            pipe.fit(feat(train).values, train.y)
            pr = pipe.predict(feat(test).values)
            leak[name] = {"holdout_accuracy": float(accuracy_score(test.y, pr))}
        except Exception as e:  # pragma: no cover
            leak[name] = {"error": str(e)}
    eda["leakage_probes"] = leak
    eda["leakage_notes"] = [
        "campaign_group perfectly determines the label, so it is excluded from every model input.",
        "sender_domain_type and URL traits are partly informative by construction; the 'text only' ablation shows how much of the "
        "result depends on them.",
        "Holdout campaigns are dated later than most training campaigns (time ordering), so a random split would be optimistic.",
        "Near-identical templates were merged BEFORE splitting (FR-01); see dedup_proof.json for the audit."]
    pw = dd.body_text.str.contains("password", case=False) | dd.subject_or_title.str.contains("password", case=False)
    eda["keyword_overrepresentation"] = {
        "password_mentions_by_label": dd[pw].label.value_counts().to_dict(),
        "payroll_mentions_by_label": dd[dd.body_text.str.contains("payroll|salary|payslip", case=False)].label.value_counts().to_dict(),
        "urgent_words_by_label": dd[dd.body_text.str.contains(r"urgent|immediately|today|asap|final", case=False)].label.value_counts().to_dict(),
        "legit_urgent_flag_rows": int(dd.legit_urgent.sum())}
    eda["train_top_terms"] = {}
    lr0 = fit_models(train)["tfidf_lr"]
    names = lr0.named_steps["tfidf"].get_feature_names_out()
    co = lr0.named_steps["clf"].coef_[0]
    eda["train_top_terms"] = {"phish": [names[i] for i in np.argsort(co)[::-1][:15]], "legit": [names[i] for i in np.argsort(co)[:15]]}
    save_json(eda, "eda.json")

    # --- model selection on training campaigns only
    log("grouped cross-validation on training campaigns ...")
    cv, folds = grouped_cv(train)
    primary = max(("tfidf_lr", "char_svm", "rules"), key=lambda k: (cv[k]["mean_f1"], k == "tfidf_lr"))

    # --- final fit + three evaluation schemes
    log("fitting final models ...")
    models = fit_models(train)
    P_test = predict_all(models, test)
    yt = test.y.values
    schemes = {"campaign_holdout": {k: metrics(yt, P_test[k]) for k in P_test}}
    for tag, (a, b), frame in (("random_split_dedup", (rs_tr, rs_te), dd), ("random_split_NO_dedup", (nd_tr, nd_te), clean_f)):
        ms = fit_models(frame.iloc[a])
        Pr = predict_all(ms, frame.iloc[b])
        schemes[tag] = {k: metrics(frame.iloc[b].y.values, Pr[k]) for k in Pr}
    # ablation: text only (no sender / url metadata)
    ab_models = fit_models(train, "text_only")
    Pab = predict_all(ab_models, test, "text_only")
    schemes["campaign_holdout_text_only"] = {k: metrics(yt, Pab[k]) for k in ("tfidf_lr", "char_svm")}

    # per-campaign table
    camp_rows = []
    for c, g in test.groupby("campaign_group"):
        i = g.index.values
        lab = g.label.iloc[0]
        row = {"campaign": c, "label": lab, "n": int(len(g)), "legit_urgent": int(g.legit_urgent.max())}
        for k in P_test:
            pred = (P_test[k][i] >= .5).astype(int)
            row[k + "_correct"] = float((pred == g.y.values).mean())
            row[k + "_mean_p"] = float(P_test[k][i].mean())
        camp_rows.append(row)

    # holdout predictions
    preds = test[["message_id", "campaign_group", "label", "legit_urgent", "channel", "subject_or_title", "body_text"]].copy()
    for k in P_test:
        preds["p_" + k] = P_test[k]
    preds.to_csv(os.path.join(config.OUTPUTS, "holdout_predictions.csv"), index=False)
    train[["message_id", "campaign_group", "label"]].to_csv(os.path.join(config.OUTPUTS, "train_ids.csv"), index=False)
    test[["message_id", "campaign_group", "label"]].to_csv(os.path.join(config.OUTPUTS, "holdout_ids.csv"), index=False)

    # abstain
    ab = {k: abstain_stats(yt, P_test[k]) for k in P_test}

    # --- robustness
    log("robustness perturbations ...")
    base = {k: metrics(yt, P_test[k]) for k in P_test}
    rob = []
    for key, (desc, fn) in PERTURBATIONS.items():
        d = perturb_df(test, fn)
        Pp = predict_all(models, d)
        for k in Pp:
            m = metrics(yt, Pp[k])
            rob.append({"perturbation": key, "description": desc, "model": k, "f1": m["f1"], "fpr": m["fpr"], "recall": m["recall"],
                        "delta_f1": m["f1"] - base[k]["f1"], "mean_abs_dprob": float(np.abs(Pp[k] - P_test[k]).mean()),
                        "flip_rate": float(((Pp[k] >= .5) != (P_test[k] >= .5)).mean()),
                        "mean_p_shift": float((Pp[k] - P_test[k]).mean())})
    cp5 = cp5_table(models, primary)

    # --- error analysis (CP-4)
    pp = P_test[primary]
    err = test.assign(p=pp)
    fn = err[(err.y == 1) & (pp < .5)].sort_values("p")
    fp = err[(err.y == 0) & (pp >= .5)].sort_values("p", ascending=False)
    picks = []
    if len(fn):
        picks.append(("Missed phishing message (false negative)", fn.iloc[0]))
    if len(fp):
        picks.append(("Legitimate message flagged as phishing (false positive)", fp.iloc[0]))
    rest = pd.concat([fn.iloc[1:], fp.iloc[1:]]).assign(dist=lambda d: (d.p - .5).abs()).sort_values("dist", ascending=False) if len(fn) + len(fp) > 2 else pd.DataFrame()
    if len(rest):
        picks.append(("Another error (second-most-confident mistake)", rest.iloc[0]))
    if len(picks) < 3:   # not enough errors: show lowest-confidence correct predictions
        ok = err[((err.y == 1) & (pp >= .5)) | ((err.y == 0) & (pp < .5))].assign(dist=lambda d: (d.p - .5).abs()).sort_values("dist")
        for _, r in ok.head(3 - len(picks)).iterrows():
            picks.append(("Borderline but correct prediction", r))
    errors = []
    for title, r in picks:
        d = r.to_dict()
        ex = explain_row(models, d)
        errors.append({"title": title, "message_id": d["message_id"], "campaign": d["campaign_group"], "true_label": d["label"],
                       "channel": d["channel"], "subject": d["subject_or_title"], "body": d["body_text"], "sender_type": d["sender_domain_type"],
                       "probabilities": {k: float(P_test[k][int(np.where(test.message_id.values == d["message_id"])[0][0])]) for k in P_test},
                       "explanation": ex})

    # --- acceptance tests (T5)
    lu = test.legit_urgent.values == 1
    leg = yt == 0
    at01 = {"subset": "held-out legitimate urgent messages (password-expiry policy + payroll cut-off campaigns)",
            "n": int((lu & leg).sum()),
            "by_model": {k: {"false_positives": int(((P_test[k] >= .5) & lu & leg).sum()),
                             "fpr": float(((P_test[k] >= .5) & lu & leg).sum() / max((lu & leg).sum(), 1)),
                             "abstained": int(((np.maximum(P_test[k], 1 - P_test[k]) < config.ABSTAIN_CONF) & lu & leg).sum())}
                         for k in P_test}}
    for k in at01["by_model"].values():
        k["false_alarms_per_1000_urgent_legit_messages"] = round(k["fpr"] * 1000)
    at01["note"] = ("Each false alarm costs a helpdesk review and teaches users to ignore warnings; "
                    "see 'abstain' in the dashboard for how many are routed to human review instead of auto-flagged.")
    at02 = {"campaigns_excluded_from_training": [c for c in config.HOLDOUT_CAMPAIGNS if c in set(test[test.label == "phish"].campaign_group)],
            "per_campaign_recall": {r["campaign"]: {k: r[k + "_correct"] for k in P_test} for r in camp_rows if r["label"] == "phish"},
            "overall_recall": {k: schemes["campaign_holdout"][k]["recall"] for k in P_test}}
    at03 = {"primary_model": primary, "rows": [r for r in rob if r["model"] == primary and r["perturbation"] in
                                              ("defang_alt", "defang_dot", "punct_noise")],
            "limitation": "URL traits are parsed only from [.] and (.) defang styles; '[dot]' is not recognised, so link features vanish "
                          "and the probability shifts. Character substitution and padding also move probabilities because the models rely on exact words."}
    acceptance = {"AT-01": at01, "AT-02": at02, "AT-03": at03}

    # --- mentor drop-in
    mentor = load_mentor(models, train)

    # --- save model bundle
    bundle = {"version": config.MODEL_VERSION, "primary": primary, "models": models, "abstain_conf": config.ABSTAIN_CONF,
              "trained_at": dt.datetime.now().isoformat(timespec="seconds"), "train_rows": len(train), "data_hash": raw_hash}
    joblib.dump(bundle, os.path.join(config.MODELS, f"phishshift_model_{config.MODEL_VERSION}.joblib"))
    meta = {"version": config.MODEL_VERSION, "primary": primary, "trained_at": bundle["trained_at"], "train_rows": len(train),
            "holdout_rows": len(test), "data_sha256_prefix": raw_hash, "seed": config.SEED,
            "python": platform.python_version(), "sklearn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__}
    save_json(meta, "model_meta.json")

    # --- traceability
    trace = [
        ("FR-01", "Deduplicate near-identical templates before split", "src/pipeline.py: dedup()", "outputs/dedup_proof.json, dedup_groups.csv", "Data & EDA tab"),
        ("FR-02", "Compare rules, TF-IDF linear model, third model", "src/cues.py + make_models()", "Models tab, outputs/summary.json", "Models tab"),
        ("FR-03", "Campaign-separated holdout", "config.HOLDOUT_CAMPAIGNS; run() split", "outputs/holdout_ids.csv, holdout_predictions.csv", "Models tab"),
        ("FR-04", "Reject/abstain + safe explanation", "abstain_stats(); cues.score_message(); lr_terms()", "Errors tab; Live Scanner", "Live Scanner tab"),
        ("FR-05", "FPR on legit urgent messages + robustness drift", "run(): at01, PERTURBATIONS", "Robustness tab, outputs/summary.json", "Robustness tab"),
        ("NFR-01", "Never click/fetch/execute content", "sanitize.py string-only; no network libs imported", "tests: tests/test_safety.py", "Banner"),
        ("NFR-02", "No real credentials / PII", "sanitize.redact_pii(); synthetic data", "outputs/sanitization_log.csv", "Live Scanner redaction notice"),
        ("NFR-03", "Decision support, not a guarantee", "dashboard banner + scan response", "Dashboard header", "Header"),
        ("AT-01", "Legit password-reset notice: FP impact", "run(): at01", "Tests tab", "Tests tab"),
        ("AT-02", "Phishing with unfamiliar phrasing on excluded campaign", "run(): at02", "Tests tab", "Tests tab"),
        ("AT-03", "Defanged URL / punctuation changes", "run(): at03, perturb.py", "Robustness tab", "Robustness tab"),
        ("CP-1", "Safe corpus handling; URLs inert", "sanitization_log.csv; reserved TLDs", "outputs/sanitization_log.csv", "Data & EDA tab"),
        ("CP-2", "Audit near-duplicate removal across splits", "proof['cross_split_audit']", "outputs/dedup_proof.json", "Data & EDA tab"),
        ("CP-3", "Campaign test + confusion analysis", "schemes + camp_rows", "Models tab", "Models tab"),
        ("CP-4", "Explain a missed phish and a flagged legit message", "errors list", "Errors tab", "Errors tab"),
        ("CP-5", "8 new harmless messages with perturbations", "CP5 + cp5_table()", "Robustness tab", "Robustness tab"),
    ]
    summary = {"meta": meta, "version": config.MODEL_VERSION, "primary": primary, "model_labels": MODEL_LABELS,
               "counts": {"raw": len(raw), "clean": len(clean), "dedup": len(dd), "train": len(train), "holdout": len(test)},
               "sanitization_log": clog, "dedup": proof, "eda": eda, "cv": {"scores": cv, "folds": folds},
               "schemes": schemes, "campaigns": camp_rows, "abstain": ab, "abstain_conf": config.ABSTAIN_CONF,
               "robustness": rob, "cp5": cp5, "errors": errors, "acceptance": acceptance, "mentor": mentor,
               "holdout_preds": [{"id": r.message_id, "campaign": r.campaign_group, "y": int(r.label == "phish"),
                                  "urgent": int(r.legit_urgent), **{k: float(getattr(r, "p_" + k)) for k in P_test}}
                                 for r in preds.itertuples()],
               "trace": [dict(id=a, requirement=b, implemented_in=c, evidence=d, shown_in=e) for a, b, c, d, e in trace],
               "perturbations": {k: v[0] for k, v in PERTURBATIONS.items()}}
    save_json(summary, "summary.json")
    pd.DataFrame([{"scheme": s, "model": m, **{k: v for k, v in r.items()}} for s, d in schemes.items() for m, r in d.items()]
                 ).to_csv(os.path.join(config.OUTPUTS, "results_table.csv"), index=False)
    pd.DataFrame(rob).to_csv(os.path.join(config.OUTPUTS, "robustness_table.csv"), index=False)
    pd.DataFrame(trace, columns=["id", "requirement", "implemented_in", "evidence", "shown_in"]).to_csv(
        os.path.join(config.OUTPUTS, "requirement_traceability.csv"), index=False)
    log(f"done in {time.time() - t0:.1f}s | primary model = {primary} | holdout F1 = {schemes['campaign_holdout'][primary]['f1']:.3f}")
    return summary


if __name__ == "__main__":
    run(force_regen="--regen" in sys.argv)
