# Threat model - PhishShift Message Risk Scanner (ML-07)

**Asset:** the trainee/helpdesk user and the machine running the tool. **Scope:** an educational triage tool over *controlled, synthetic* training messages.

| # | Threat | Where it could occur | Mitigation in this project | Residual risk |
|---|--------|----------------------|----------------------------|---------------|
| T1 | Analyst or tool opens a malicious link | Reading messages, URL feature extraction | URLs are only ever handled as strings (`src/sanitize.py`); no HTTP client library is imported anywhere (`tests/test_safety.py` enforces this); all corpus URLs use reserved `.test`/`.invalid` hosts and TEST-NET IPs and are defanged | A user could copy a defanged link out of the dashboard and re-fang it by hand |
| T2 | Executing attachments / active content | Corpus ingestion | Attachment lines stripped (`strip_attachments`); no attachments in the corpus; dashboard escapes all message text (`esc()`) so message content cannot run as HTML/JS | - |
| T3 | Real credentials or personal data leak into datasets, logs or the model | Live scanner, mentor-supplied data | Corpus is synthetic; `redact_pii` masks e-mails, phone numbers, card-like numbers and `password: x` strings before any processing and the dashboard warns the user; server binds to `127.0.0.1` only; nothing is stored from live scans | Redaction is pattern-based and can miss unusual formats |
| T4 | Training-data poisoning / label noise | Mentor drop-in file, retraining | Raw data kept unchanged, cleaning is logged, dedup audit, data hash recorded with each model version | A malicious mentor file would still be trained on only if added to the training set (it is evaluation-only by default) |
| T5 | Evasion by attacker (new wording, link shorteners, punctuation, character swaps) | Model inference | Campaign-separated holdout, robustness suite (FR-05), abstain option routes low-confidence messages to a human | Measured drift is real - see Robustness tab; the tool is **decision support, not a guarantee** (NFR-03) |
| T6 | Over-blocking legitimate urgent messages (password-expiry, payroll) | Model inference | Legit urgent messages are included in training and in the held-out set; FPR on them is reported (AT-01) | False positives remain; they cost helpdesk time and train users to ignore alerts |
| T7 | Over-trust in the tool | Users | Banner on every page, verdict "Needs human review" band, explanation of cues rather than a bare score | Automation bias is a human-factors risk that no model removes |
| T8 | Local web server abused | Dashboard | Loopback only, file downloads restricted to four whitelisted folders with `realpath` check, request body size limits | Another local user on a shared machine could reach the port |
