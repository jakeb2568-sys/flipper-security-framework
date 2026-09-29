"""Tests for tools/capture.py using a fake Flipper (no hardware needed).

Run:  python -m unittest discover tests
"""

import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tools"))
sys.path.insert(0, str(Path(__file__).parent))

import capture  # noqa: E402
from fake_flipper import FakeFlipperSerial  # noqa: E402


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.fake = FakeFlipperSerial()
        self.cli = capture.FlipperCLI("fake", conn=self.fake)
        self.session = capture.Session(Path(self.tmp.name), "t")

    def tearDown(self):
        self.tmp.cleanup()

    def files(self):
        return sorted(p.name for p in self.session.dir.iterdir() if p.is_file())

    def test_device_info(self):
        info = self.cli.device_info()
        self.assertEqual(info["firmware_version"], "1.4.3")

    def test_pull_copies_sd_card_files(self):
        capture.pull(self.cli, self.session)
        self.assertEqual(self.files(), ["badge.rfid", "garage_remote.sub", "tv.ir"])
        text = (self.session.dir / "garage_remote.sub").read_text()
        self.assertTrue(text.startswith("Filetype: Flipper SubGhz Key File"))
        self.assertNotIn("Size:", text)

    def test_subghz_scan_decodes_and_dedupes(self):
        capture.scan_subghz(self.cli, self.session, [433.92, 315], seconds=1)
        self.assertEqual(self.files(), ["live_subghz_433920000_1.sub"])
        sub = (self.session.dir / "live_subghz_433920000_1.sub").read_text()
        self.assertIn("Protocol: Princeton", sub)
        self.assertIn("Key: 00 00 00 00 00 A1 2F 44", sub)
        self.assertIn("Frequency: 433920000", sub)
        # both frequencies leave a transcript, decoded or not
        self.assertEqual(len(list(self.session.transcripts.iterdir())), 2)

    def test_all_scans(self):
        capture.run_scans(self.cli, self.session, list(capture.SCAN_TYPES), [433.92], 1)
        exts = sorted(Path(f).suffix for f in self.files())
        self.assertEqual(exts, [".ibtn", ".ir", ".nfc", ".rfid", ".sub"])
        rfid = next(self.session.dir.glob("*.rfid")).read_text()
        self.assertIn("Key type: EM4100", rfid)
        self.assertIn("Data: 1C 00 3F 7A 21", rfid)
        ir = next(self.session.dir.glob("*.ir")).read_text()
        self.assertEqual(ir.count("name:"), 1)  # repeat frame deduped
        self.assertIn("address: 87 EE 00 00", ir)

    def test_nothing_decoded_saves_nothing(self):
        self.fake.fail_live = True
        capture.run_scans(self.cli, self.session, ["rfid", "ibutton"], [433.92], 1)
        self.assertEqual(self.files(), [])

    def test_prompt_left_clean_after_stream(self):
        # after a Ctrl+C'd scan the next command must get its own clean output
        self.cli.stream("subghz rx 433920000 0", 0.3)
        self.assertEqual(self.cli.device_info()["hardware_name"], "Fake-Flip")


class PipelineTest(unittest.TestCase):
    def test_capture_to_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            cli = capture.FlipperCLI("fake", conn=FakeFlipperSerial())
            s = capture.Session(Path(tmp), "pipeline-test")
            capture.pull(cli, s)
            capture.run_scans(cli, s, ["subghz"], [433.92], 1)
            report = capture.run_pipeline(s, "Unit Test")
            try:
                text = report.read_text()
                self.assertIn("Unit Test", text)
                self.assertIn("HIGH", text)
            finally:
                import shutil
                shutil.rmtree(report.parent, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
