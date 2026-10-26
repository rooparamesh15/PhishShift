"""Central configuration for the PhishShift Message Risk Scanner (ML-07)."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_RAW = os.path.join(ROOT, "data", "raw")
DATA_PROC = os.path.join(ROOT, "data", "processed")
DATA_MENTOR = os.path.join(ROOT, "data", "mentor")
OUTPUTS = os.path.join(ROOT, "outputs")
MODELS = os.path.join(ROOT, "models")
DOCS = os.path.join(ROOT, "docs")
WEB = os.path.join(ROOT, "src", "web")

SEED = 7
MODEL_VERSION = "v1.0"

# FR-03: whole campaigns that are never seen during training or tuning.
HOLDOUT_CAMPAIGNS = [
    # unfamiliar-wording phishing campaigns
    "ceo_favour", "shared_doc", "vendor_bank_change", "survey_gift",
    # different legitimate business message sets (several mention passwords / payroll / urgency)
    "it_pw_expiry_policy", "payroll_cutoff_urgent", "helpdesk_ticket", "security_awareness",
]

DEDUP_THRESHOLD = 0.92      # cosine similarity on masked text; >= means near-identical template
ABSTAIN_CONF = 0.70         # FR-04: abstain when max(p, 1-p) is below this
RANDOM_TEST_SIZE = 0.25

COMPANY_DOMAIN = "examplecorp.test"
SHORTENER_DOMAINS = {"tiny-lnk.test", "s-hrt.test", "go-lnk.invalid"}

SCHEMA = ["message_id", "channel", "subject_or_title", "body_text", "sanitized_url_features",
          "sender_domain_type", "label", "campaign_group", "collected_date"]
