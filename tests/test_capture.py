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
        self.assertEqual(info["firmware_origin"], "Official")
        self.assertEqual(info["region"], "US")
        # serial number / MAC are not kept in the manifest
        self.assertNotIn("0000000000000000", str(info))

    def test_pull_copies_sd_card_files(self):
        capture.pull(self.cli, self.session)
        self.assertEqual(self.files(), ["badge.rfid", "garage_remote.sub", "tv.ir"])
        text = (self.session.dir / "garage_remote.sub").read_text()
        self.assertTrue(text.startswith("Filetype: Flipper SubGhz Key File"))
        self.assertNotIn("Size:", text)

    def test_pull_since_uses_filename_date_and_timestamp(self):
        from datetime import date, datetime
        raw = "Filetype: Flipper SubGhz RAW File\nVersion: 1\nFrequency: 433920000\nProtocol: RAW\n"
        self.fake.files.update({
            "/ext/subghz/RAW-20260519-114544.sub": raw,     # old, dated by name
            "/ext/subghz/RAW-20260929-123231.sub": raw,     # new, dated by name
            "/ext/subghz/Raw_signal_.sub": raw,             # no date in name -> timestamp
        })
        self.fake.timestamps["/ext/subghz/Raw_signal_.sub"] = int(datetime(2026, 9, 29, 12).timestamp())
        capture.pull(self.cli, self.session, since=date(2026, 9, 29))
        self.assertEqual(self.files(), ["RAW-20260929-123231.sub", "Raw_signal_.sub"])

    def test_pull_since_skips_undated_files(self):
        from datetime import date
        # SD_CARD files have no date in the name and no timestamp -> skipped, not guessed
        capture.pull(self.cli, self.session, since=date(2026, 1, 1))
        self.assertEqual(self.files(), [])

    def test_pull_only_pattern(self):
        capture.pull(self.cli, self.session, only=["*.RFID", "tv*"])
        self.assertEqual(self.files(), ["badge.rfid", "tv.ir"])

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

    def test_app_open_raises_clear_error(self):
        self.fake.app_open = True
        with self.assertRaises(capture.FlipperBusyError) as ctx:
            capture.run_scans(self.cli, self.session, ["subghz"], [433.92], 1)
        self.assertIn("home screen", str(ctx.exception))

    def test_prompt_left_clean_after_stream(self):
        # after a Ctrl+C'd scan the next command must get its own clean output
        self.cli.stream("subghz rx 433920000 0", 0.3)
        self.assertEqual(self.cli.device_info()["hardware_name"], "Fake-Flip")


class ArgumentTests(unittest.TestCase):
    def parse(self, *argv):
        return capture.build_parser().parse_args(argv)

    def test_options_after_subcommand(self):
        a = self.parse("scan", "subghz", "--freq", "433.92", "--report", "--redact", "--name", "Car")
        self.assertTrue(a.report and a.redact)
        self.assertEqual((a.name, a.freq, a.mode), ("Car", [433.92], "scan"))

    def test_options_before_subcommand(self):
        a = self.parse("--port", "COM4", "--report", "pull")
        self.assertEqual((a.port, a.report, a.redact, a.mode), ("COM4", True, False, "pull"))

    def test_pull_filters_parse(self):
        from datetime import date
        a = self.parse("pull", "--since", "today", "--only", "RAW-*", "--report")
        self.assertEqual((a.since, a.only, a.report), (date.today(), ["RAW-*"], True))
        with self.assertRaises(SystemExit):
            self.parse("pull", "--since", "last tuesday")

    def test_defaults(self):
        a = self.parse("pull")
        self.assertEqual((a.port, a.report, a.name, a.yes), (None, False, "Live Assessment", False))


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
