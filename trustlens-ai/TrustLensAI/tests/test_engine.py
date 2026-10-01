import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server


class TrustLensTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = server.DB
        server.DB = Path(self.tmp.name) / "test.db"

    def tearDown(self):
        server.DB = self.old_db
        self.tmp.cleanup()

    def test_bank_urgency_high(self):
        self.assertIn(server.analyze("Your bank account will be blocked in 10 minutes. Click here") ["risk_level"], {"HIGH", "CRITICAL"})
    def test_harmless_lunch_low(self):
        self.assertEqual(server.analyze("Hey, are you free for lunch?")["risk_level"], "LOW")
    def test_prize_payment(self):
        r = server.analyze("Congratulations! You won ₹50,000. Pay ₹499 processing fee.")
        self.assertTrue({"Reward", "Payment"}.issubset({s["label"] for s in r["signals"]}))
    def test_delivery_payment(self):
        self.assertGreater(server.analyze("Your delivery is pending. Pay ₹25.")["risk_score"], 25)
    def test_otp_detected(self):
        self.assertIn("otp", {s["key"] for s in server.analyze("Send me your OTP to verify your account.")["signals"]})
    def test_urgency_detected(self):
        self.assertIn("urgency", {s["key"] for s in server.analyze("Act now, this expires soon.")["signals"]})
    def test_fear_detected(self):
        self.assertIn("fear", {s["key"] for s in server.analyze("Your account is suspended.")["signals"]})
    def test_threat_detected(self):
        self.assertIn("threat", {s["key"] for s in server.analyze("Your account will be blocked.")["signals"]})
    def test_payment_detected(self):
        self.assertIn("payment", {s["key"] for s in server.analyze("Pay ₹25 processing fee")["signals"]})
    def test_impersonation_detected(self):
        r = server.analyze("Amazon Customer Support: pay ₹25 at http://order-help.top/pay")
        self.assertTrue(r["impersonation"]["detected"])
    def test_no_unfounded_impersonation(self):
        self.assertFalse(server.analyze("I like Amazon's books.")["impersonation"]["detected"])
    def test_risk_caps_at_100(self):
        self.assertEqual(server.analyze("URGENT bank blocked OTP password pay ₹50 legal action don't tell anyone http://10.0.0.1/login")["risk_score"], 100)
    def test_score_is_explainable(self):
        r = server.analyze("Urgent: pay ₹20 immediately")
        self.assertEqual(r["risk_score"], min(100, sum(s["points"] for s in r["signals"])))
    def test_no_fake_confidence(self):
        self.assertIsNone(server.analyze("ordinary text")["confidence"])
    def test_attack_path_generated(self):
        self.assertGreater(len(server.analyze("Share your OTP")["attack_path"]), 1)
    def test_url_http_flag(self):
        self.assertTrue(any("HTTPS" in x for x in server.analyze_url("http://example.com")["signals"]))
    def test_url_ip_flag(self):
        self.assertTrue(any("IP address" in x for x in server.analyze_url("http://192.168.1.2/login")["signals"]))
    def test_url_suspicious_tld(self):
        self.assertTrue(any("TLD" in x for x in server.analyze_url("https://offer.click")["signals"]))
    def test_url_credential_path(self):
        self.assertTrue(any("Path" in x for x in server.analyze_url("https://example.com/login")["signals"]))
    def test_malformed_url_safe(self):
        self.assertFalse(server.analyze_url("http://[bad")["valid"])
    def test_tamil_input_accepted(self):
        self.assertEqual(server.analyze("உங்கள் OTP-ஐ யாரிடமும் பகிர வேண்டாம்.")["risk_level"], "LOW")
    def test_empty_input_rejected(self):
        with self.assertRaises(ValueError): server.analyze("  ")
    def test_too_long_input_rejected(self):
        with self.assertRaises(ValueError): server.analyze("x" * (server.MAX_INPUT + 1))
    def test_local_history_saves_metadata(self):
        server.analyze("A harmless local test")
        with server._db() as con: self.assertEqual(con.execute("SELECT count(*) FROM history").fetchone()[0], 1)
    def test_demo_has_six_examples(self):
        self.assertEqual(len(server.examples()), 6)
    def test_local_privacy_statement(self):
        self.assertIn("not sent", server.analyze("ordinary note")["privacy"])


if __name__ == "__main__":
    unittest.main()
