"""Tests for ingest → analyze → report rules using data/samples (no hardware)."""

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))

import analyze  # noqa: E402
import ingest  # noqa: E402
import report  # noqa: E402

SAMPLES = REPO / "data" / "samples"


def classify(name):
    return analyze.classify(ingest.ingest_file(str(SAMPLES / name)))


class RiskRuleTests(unittest.TestCase):
    def test_expected_risk_per_sample(self):
        expected = {
            "office_badge.rfid": "CRITICAL",    # 125 kHz HID Prox
            "garage_door.sub": "HIGH",          # fixed-code Princeton
            "access_card.nfc": "HIGH",          # Mifare Classic
            "door_key.ibtn": "HIGH",            # Dallas DS1990
            "car_fob.sub": "LOW",               # rolling-code KeeLoq
            "conference_room_tv.ir": "LOW",
        }
        for name, risk in expected.items():
            with self.subTest(sample=name):
                self.assertEqual(classify(name)["overall_risk"], risk)

    def test_all_sample_types_are_ingested(self):
        records = ingest.ingest_directory(str(SAMPLES))
        self.assertEqual({r["type"] for r in records}, {"subghz", "nfc", "rfid", "ibutton", "ir"})

    def test_preset_is_not_mistaken_for_protocol(self):
        rec = ingest.ingest_file(str(SAMPLES / "garage_door.sub"))
        self.assertEqual(rec["protocol"], "Princeton")
        self.assertTrue(rec["preset"].startswith("FuriHal"))

    def test_rolling_code_does_not_trigger_band_warning(self):
        findings = [f["finding"] for f in classify("car_fob.sub")["findings"]]
        self.assertFalse(any("315 MHz" in f for f in findings))

    def test_new_firmware_mifare_naming(self):
        rec = {"type": "nfc", "card_type": "Mifare Classic 1K", "uid": "01 02 03 04"}
        self.assertEqual(analyze.classify(rec)["overall_risk"], "HIGH")

    def test_raw_subghz_is_unidentified(self):
        rec = {"type": "subghz", "protocol": "RAW", "frequency": "315000000", "raw_data": ["100 -200"]}
        findings = [f["finding"] for f in analyze.classify(rec)["findings"]]
        self.assertIn("Unidentified Sub-GHz transmission captured (raw)", findings)


class RedactionTests(unittest.TestCase):
    def test_redact_keeps_last_byte(self):
        self.assertEqual(report.redact("4A 3B 2C 1D"), "** ** ** 1D")

    def test_report_redacts_identifiers(self):
        analysis = analyze.analyze_all([ingest.ingest_file(str(SAMPLES / "access_card.nfc"))])
        full = report.generate_report(analysis)
        masked = report.generate_report(analysis, redacted=True)
        self.assertIn("4A 3B 2C 1D", full)
        self.assertNotIn("4A 3B 2C 1D", masked)
        self.assertIn("** ** ** 1D", masked)


if __name__ == "__main__":
    unittest.main()
