"""Run from the scanner folder:  python -m unittest discover -s tests -v"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from triage import redact  # noqa: E402
from triage.scan import scan  # noqa: E402
from tests import samples  # noqa: E402


def run(name):
    return scan(samples.ALL[name](), ["example.com"])


class Detection(unittest.TestCase):
    def test_credential_harvest_is_malicious(self):
        r = run("credential_harvest")
        self.assertEqual(r["verdict"], "MALICIOUS")
        self.assertTrue(any("DMARC" in f["reason"] for f in r["findings"]))

    def test_qr_code_inside_image_is_decoded(self):
        r = run("quishing_image")
        self.assertIn("http://mailbox-renew.click/login", r["qr_urls"])
        self.assertNotEqual(r["verdict"], "CLEAN")

    def test_qr_code_inside_pdf_is_decoded(self):
        self.assertIn("https://bit.ly/3payroll", run("pdf_qr")["qr_urls"])

    def test_password_protected_zip_with_exe(self):
        r = run("encrypted_zip")
        self.assertEqual(r["verdict"], "MALICIOUS")
        self.assertTrue(any("Password-protected" in f["reason"] for f in r["findings"]))

    def test_normal_newsletter_stays_clean(self):
        self.assertEqual(run("newsletter")["verdict"], "CLEAN")

    def test_ceo_fraud_needs_the_language_layer(self):
        # No links, no files, passes SPF/DKIM/DMARC. Rules see the warning signs but can't be sure.
        # This is exactly the gap the LLM review closes in the full system.
        r = run("ceo_fraud")
        self.assertGreater(r["score"], 0)
        self.assertNotEqual(r["verdict"], "MALICIOUS")


class Masking(unittest.TestCase):
    def test_personal_details_are_masked(self):
        text = ("Pay to account 0123456789. Call 08031234567 or +234 803 123 4567. "
                "BVN 22123456789, card 4111 1111 1111 1111, email finance.dept@acme-payments.com")
        out = redact.mask(text)
        for secret in ("0123456789", "08031234567", "803 123 4567", "22123456789", "4111 1111", "finance.dept@"):
            self.assertNotIn(secret, out)
        for tag in ("[ACCOUNT-NUMBER]", "[PHONE]", "[ID-NUMBER]", "[CARD-NUMBER]", "[EMAIL]@acme-payments.com"):
            self.assertIn(tag, out)

    def test_normal_text_untouched(self):
        text = "Meeting on 12/10/2026 at 3pm. Invoice INV-2026-0042. See https://example.com/docs?page=2"
        self.assertEqual(redact.mask(text), text)


if __name__ == "__main__":
    unittest.main()
