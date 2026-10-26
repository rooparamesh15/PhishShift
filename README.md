# PhishShift Message Risk Scanner (Cybernaut ML-07)

Educational triage tool that scores simulated e-mails/SMS for phishing risk, explains the cues, can abstain,
and is evaluated on **whole campaigns the models never saw**.

## Run it (opens the dashboard automatically)

| System  | How |
|---------|-----|
| Windows | double-click **`run.bat`** (or `py -3 run.py`) |
| macOS   | double-click **`run.command`** (or `python3 run.py`) |
| Linux   | `./run.sh` or `python3 run.py` |

The first run installs any missing packages (numpy, pandas, scipy, scikit-learn, joblib), trains the models if
needed (about 10-30 s) and opens **http://127.0.0.1:8765/** in your browser. Press `Ctrl+C` in the terminal to stop.
Options: `--retrain`, `--regen` (regenerate the synthetic corpus), `--no-browser`, `--port 9000`.
Manual install alternative: `pip install -r requirements.txt` or `conda env create -f environment.yml`.

## What is where

```
run.py / run.bat / run.sh     launcher
src/generate_data.py          locally authored synthetic corpus (20 campaigns, seed 7)
src/sanitize.py               URL defanging, URL features, PII redaction (strings only - links never opened)
src/cues.py                   transparent rule baseline + risk-cue explanations
src/pipeline.py               clean -> dedup -> split -> models -> evaluation -> robustness -> outputs
src/perturb.py                controlled text perturbations (AT-03, CP-5)
src/server.py + src/web/      local dashboard (loopback only)
data/raw                      raw_messages.csv (never modified), corpus_provenance.csv, source_manifest.csv
data/processed                clean_messages.csv, dedup_messages.csv
data/mentor                   drop mentor_holdout.csv here (see below)
outputs                       summary.json, results_table.csv, dedup_proof.json, sanitization_log.csv, ...
models                        phishshift_model_v1.0.joblib (versioned, with outputs/model_meta.json)
docs                          SRS.pdf, threat_model.md, AI_USAGE.md, experiment_journal.md
tests                         python -m unittest discover -s tests -v
```

## Requirement coverage

| ID | Where |
|----|-------|
| FR-01 dedup before split | `pipeline.dedup`, `outputs/dedup_proof.json`, dashboard *Data & EDA* |
| FR-02 rules vs TF-IDF linear vs third model | rules (`cues.py`), TF-IDF + Logistic Regression, char n-gram + calibrated SVM |
| FR-03 campaign-separated holdout | `config.HOLDOUT_CAMPAIGNS` (8 campaigns), *Models* tab |
| FR-04 abstain + safe explanation | abstain slider, *Live Scanner*, *Errors* tab |
| FR-05 FPR on legit urgent + robustness drift | *Tests* (AT-01) and *Robustness* tabs |
| NFR-01..03 | string-only URL handling, redaction, banner on every page |
| AT-01..03, CP-1..5 | dashboard *Tests & Traceability* tab; `outputs/requirement_traceability.csv` |

Model selection uses leave-campaign-pair-out cross-validation on **training campaigns only**; the held-out campaigns are
scored once. The dashboard shows random-split scores next to the campaign-holdout scores to expose the optimism of random splits.

## Mentor's unseen variation (Section 08)

Save the mentor's messages as `data/mentor/mentor_holdout.csv` with at least `body_text` and `label`
(`phish`/`legit`; optional `channel`, `subject_or_title`, `sender_domain_type`) and press **Re-run pipeline** on the *Tests* tab.
The file is sanitised the same way, checked for near-duplicates of training data and evaluated as an extra test set.

## Still to do by you (not generated)

`final_report.pdf` (Section 12 format), the 3-5 minute demo video, repo link/history, filling `docs/AI_USAGE.md`, and
screenshots of AT-01..03 from the dashboard. Replace or extend the synthetic corpus with openly licensed data if your mentor asks
(keep the schema and defang URLs).

## Limitations

Synthetic data is cleaner than real mail; hold-out wording is authored by the same team, so real-world performance will be lower.
The tool is decision support, not a guarantee of safety.
