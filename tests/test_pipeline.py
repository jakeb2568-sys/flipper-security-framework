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
            "car_fob_raw_press1.sub": "MEDIUM",  # unidentified raw @ 433 MHz
            "car_fob_raw_press2.sub": "MEDIUM",
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


class ReplayCheckTests(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(REPO / "tests"))
        import replay_check
        import signal_gen
        self.rc, self.sg = replay_check, signal_gen

    def durations(self, sub_text):
        return self.rc.durations_from_raw_lines(sub_text.splitlines())

    def verdict(self, *subs):
        return self.rc.check({f"p{i}": self.durations(s) for i, s in enumerate(subs)})["verdict"]

    def test_fixed_and_rolling_across_many_remotes(self):
        for seed in range(1, 21):
            with self.subTest(seed=seed):
                self.assertEqual(self.verdict(*self.sg.make_pair("fixed", seed)), "fixed")
                self.assertEqual(self.verdict(*self.sg.make_pair("rolling", seed)), "rolling")

    def test_single_press_is_inconclusive(self):
        a, _ = self.sg.make_pair("rolling", 3)
        self.assertEqual(self.verdict(a), "inconclusive")

    def test_two_presses_in_one_recording(self):
        import random
        rng = random.Random(9)
        serial = "0110" * 7
        both = self.sg.press(self.sg.rolling_bits(rng, serial), rng) + self.sg.press(self.sg.rolling_bits(rng, serial), rng)
        self.assertEqual(self.rc.check({"one.sub": both})["verdict"], "rolling")

    def test_different_devices_not_compared(self):
        a, _ = self.sg.make_pair("rolling", 3)
        short = self.sg.to_sub(self.sg.press("1011" * 6, __import__("random").Random(1)))  # 24-bit remote
        self.assertEqual(self.verdict(a, short), "inconclusive")

    def test_samples_show_rolling_in_report(self):
        records = [ingest.ingest_file(str(SAMPLES / n)) for n in ("car_fob_raw_press1.sub", "car_fob_raw_press2.sub")]
        analysis = analyze.analyze_all(records)
        self.assertEqual([c["verdict"] for c in analysis["replay_checks"]], ["rolling"])
        text = report.generate_report(analysis)
        self.assertIn("## Replay-Resistance Checks", text)
        self.assertIn("rolling code behavior", text)

    def test_fixed_check_raises_posture(self):
        a, b = self.sg.make_pair("fixed", 4)
        recs = [{"type": "subghz", "source_file": n, "frequency": "433920000", "protocol": "RAW",
                 "raw_data": s.splitlines()[5:]} for n, s in (("a.sub", a), ("b.sub", b))]
        text = report.generate_report(analyze.analyze_all(recs))
        self.assertIn("**Overall Risk Posture:** 🟠 **HIGH**", text)


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
