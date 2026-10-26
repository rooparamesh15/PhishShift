"""Safety / unit tests. Run:  python -m unittest discover -s tests -v"""
import os, sys, unittest, re
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src import sanitize, cues, config


class TestSafety(unittest.TestCase):
    def test_no_network_clients_imported(self):          # NFR-01
        banned = re.compile(r"^\s*(import|from)\s+(requests|urllib\.request|urllib3|httpx|aiohttp|selenium|webbrowser_open_url)\b", re.M)
        for fn in os.listdir(config.ROOT + "/src"):
            if fn.endswith(".py"):
                self.assertIsNone(banned.search(open(os.path.join(config.ROOT, "src", fn), encoding="utf-8").read()), fn)

    def test_defang(self):
        t, n = sanitize.defang_text("see http://evil-login.test/verify?id=1, now")
        self.assertEqual(n, 1)
        self.assertIn("hxxp://evil-login[.]test/verify?id=1", t)
        self.assertNotIn("http://", t)

    def test_pii_redaction(self):                          # NFR-02
        t, f = sanitize.redact_pii("mail a@b.com, call +91 98765 43210, card 4111 1111 1111 1111, password: hunter2")
        for leaked in ("a@b.com", "98765", "4111", "hunter2"):
            self.assertNotIn(leaked, t)
        self.assertTrue(f)

    def test_password_cue_keeps_link(self):               # redaction must not hide a phishing link
        t, _ = sanitize.redact_pii("verify your password: hxxp://examplecorp-login[.]test/verify")
        self.assertIn("examplecorp-login", t)

    def test_url_features(self):
        f = sanitize.url_features("go hxxp://tiny-lnk[.]test/ab12cd or hxxp://examplecorp-login[.]test/verify")
        self.assertEqual((f["shortener"], f["lookalike"], f["login_path"]), (1, 1, 1))
        g = sanitize.url_features("hxxps://intranet[.]examplecorp[.]test/hr/payslip")
        self.assertEqual((g["lookalike"], g["shortener"]), (0, 0))

    def test_rule_scores_order(self):
        phish, _ = cues.score_message("email", "URGENT", "Click here immediately to verify your password: hxxp://examplecorp-login[.]test/verify",
                                      "lookalike", sanitize.url_features("hxxp://examplecorp-login[.]test/verify"))
        legit, _ = cues.score_message("email", "Reset done", "We will never ask for your password. Call ext 4455.", "internal", sanitize.url_features(""))
        self.assertGreater(phish, legit)


if __name__ == "__main__":
    unittest.main()
