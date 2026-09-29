#!/usr/bin/env python3
"""
capture.py — Flipper Zero Capture Collection
Flipper Security Framework

Collects captures from a Flipper Zero over its USB serial CLI and writes them as
standard Flipper files (.sub, .nfc, .rfid, .ir, .ibtn) that ingest.py reads.

Two ways to collect:
  pull   Copy captures already saved on the Flipper's SD card (every type,
         including IR you saved from the Infrared app).
  scan   Run live read-only scans (subghz, rfid, ibutton, nfc, ir) and save
         whatever the device decodes.

Examples:
  python tools/capture.py pull
  python tools/capture.py pull --since today --report --redact
  python tools/capture.py pull --only "RAW-20260929-*"
  python tools/capture.py scan subghz --freq 433.92 --freq 315 --seconds 15
  python tools/capture.py scan all --report
  python tools/capture.py --port COM4 pull --report

Design notes:
  * Talks to the CLI directly with pyserial: one open port, one thread,
    deadline-based reads. No timer threads, so no stray Ctrl+C landing on the
    next command and no dropped COM port between scans (the old pyFlipper issue).
  * Read-only. Nothing here transmits, emulates, or writes to tags.
  * Every scan's raw CLI output is saved under transcripts/ as evidence, even
    when nothing is decoded.

Only capture devices you own or are explicitly authorized to assess.
See docs/legal-ethics.md.
"""

import argparse
import fnmatch
import json
import re
import subprocess
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path

try:
    import serial
    import serial.tools.list_ports
except ImportError:  # pragma: no cover
    sys.exit("pyserial is required:  pip install -r requirements.txt")

REPO_ROOT = Path(__file__).resolve().parents[1]
PROMPT = b">: "
ANSI = re.compile(r"\x1b\[[0-9;?=]*[A-Za-z]")
HEX_BYTES = re.compile(r"\b(?:[0-9A-Fa-f]{2} ){1,}[0-9A-Fa-f]{2}\b")

# Flipper Zero USB CDC identifiers (STMicro VID/PID used by the stock firmware)
FLIPPER_VID, FLIPPER_PID = 0x0483, 0x5740

# SD card folders to pull, and the extension kept from each
SD_FOLDERS = {
    "/ext/subghz": ".sub",
    "/ext/nfc": ".nfc",
    "/ext/lfrfid": ".rfid",
    "/ext/infrared": ".ir",
    "/ext/ibutton": ".ibtn",
}

SCAN_TYPES = ("subghz", "rfid", "ibutton", "nfc", "ir")


# ── Serial CLI transport ─────────────────────────────────────────────────────

class FlipperBusyError(RuntimeError):
    """The Flipper refused a command because an app is open on the device."""

    HINT = ("An app is open on the Flipper, so it refused the scan. "
            "Press Back on the Flipper until you reach the home screen, then rerun.")


def _check_busy(text: str):
    if "application is open" in text.lower():
        raise FlipperBusyError(FlipperBusyError.HINT)


class FlipperCLI:
    """Minimal, single-threaded client for the Flipper Zero serial CLI."""

    def __init__(self, port: str, open_timeout: float = 5.0, conn=None):
        self.port = port
        self._ser = conn or serial.serial_for_url(port, baudrate=230400, timeout=0.1)
        self._ser.write(b"\r")
        self._read_until(PROMPT, open_timeout)  # swallow banner

    # context manager so the port is always released
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        try:
            self._ser.close()
        except Exception:
            pass

    def _read_until(self, marker: bytes, timeout: float) -> bytes:
        deadline = time.monotonic() + timeout
        buf = bytearray()
        while time.monotonic() < deadline:
            chunk = self._ser.read(self._ser.in_waiting or 1)
            if chunk:
                buf += chunk
                if marker in buf:
                    break
        return bytes(buf)

    @staticmethod
    def _clean(raw: bytes, cmd: str) -> str:
        text = ANSI.sub("", raw.decode(errors="ignore")).replace("\r\n", "\n")
        if cmd and cmd in text:  # drop the echoed command
            text = text.split(cmd, 1)[1]
        text = text.rstrip()
        for p in ("[nfc]>:", ">:"):
            if text.endswith(p):
                text = text[: -len(p)]
        return text.strip("\n ")

    def run(self, cmd: str, timeout: float = 10.0) -> str:
        """Run a command that returns to the prompt on its own."""
        self._ser.reset_input_buffer()
        self._ser.write(f"{cmd}\r".encode())
        out = self._clean(self._read_until(PROMPT, timeout), cmd)
        _check_busy(out)
        return out

    def stream(self, cmd: str, seconds: float, until=None) -> str:
        """Run a continuous command (rx/read) for up to `seconds`, then Ctrl+C.

        Returns early if the command finishes on its own (prompt seen) or if
        `until(text)` returns True.
        """
        self._ser.reset_input_buffer()
        self._ser.write(f"{cmd}\r".encode())
        deadline = time.monotonic() + seconds
        buf = bytearray()
        finished = False
        while time.monotonic() < deadline:
            chunk = self._ser.read(self._ser.in_waiting or 1)
            if not chunk:
                continue
            buf += chunk
            body = bytes(buf).split(cmd.encode(), 1)[-1]
            if PROMPT in body:
                finished = True
                break
            if until and until(self._clean(bytes(buf), cmd)):
                break
        if not finished:
            self._ser.write(b"\x03")
            buf += self._read_until(PROMPT, 3.0)
        out = self._clean(bytes(buf), cmd)
        _check_busy(out)
        return out

    # convenience wrappers
    def device_info(self) -> dict:
        """Model/firmware summary. Handles both key styles:
        firmware 1.x prints `firmware.version : 1.4.3`, older builds `firmware_version : ...`.
        Serial numbers and MAC addresses are deliberately not kept."""
        out = self.run("info device")
        if "firmware" not in out:
            out = self.run("device_info")
        info = {}
        for key, val in re.findall(r"^\s*([\w.]+)\s*:\s*(.+)$", out, re.M):
            info[key.strip().replace(".", "_")] = val.strip()
        return {
            "hardware_model": info.get("hardware_model") or "Flipper Zero",
            "hardware_name": info.get("hardware_name"),
            "region": info.get("hardware_region_provisioned"),
            "firmware_version": info.get("firmware_version"),
            "firmware_origin": info.get("firmware_origin_fork"),
            "firmware_commit": info.get("firmware_commit_hash") or info.get("firmware_commit"),
        }

    def list_files(self, folder: str) -> list:
        out = self.run(f"storage list {folder}")
        return [m.strip() for m in re.findall(r"^\s*\[F\]\s+(.+?)\s+\d+\w*\s*$", out, re.M)]

    def read_file(self, path: str) -> str:
        out = self.run(f"storage read {path}", timeout=20)
        lines = out.split("\n")
        if lines and lines[0].startswith("Size:"):
            lines = lines[1:]
        return "\n".join(lines).strip() + "\n"


def find_flipper_port() -> str | None:
    """Return the serial port of the first attached Flipper Zero, if any."""
    for p in serial.tools.list_ports.comports():
        if (p.vid, p.pid) == (FLIPPER_VID, FLIPPER_PID) or "flipper" in (p.description or "").lower():
            return p.device
    return None


# ── Output parsers: CLI text → Flipper file formats ─────────────────────────

def _spaced_hex(value: str, width_bytes: int | None = None) -> str:
    h = value.replace(" ", "").upper()
    if width_bytes:
        h = h.zfill(width_bytes * 2)
    if len(h) % 2:
        h = "0" + h
    return " ".join(h[i:i + 2] for i in range(0, len(h), 2))


def _le_bytes(value: int, n: int = 4) -> str:
    return " ".join(f"{b:02X}" for b in value.to_bytes(n, "little"))


def parse_subghz(text: str, freq_hz: int) -> list[str]:
    """Decoded `subghz rx` packets → list of .sub key-file contents (deduped)."""
    files, seen = [], set()
    # Each decoded packet starts with "<Protocol> <N>bit"
    blocks = re.split(r"\n(?=[A-Za-z][\w .\-/]*? \d+bit\s*$)", "\n" + text, flags=re.M)
    for block in blocks:
        head = re.match(r"\s*([A-Za-z][\w .\-/]*?) (\d+)bit", block)
        key = re.search(r"Key:\s*0x([0-9A-Fa-f]+)", block)
        if not (head and key):
            continue
        proto, bits = head.group(1).strip(), int(head.group(2))
        sig = (proto, key.group(1).upper())
        if sig in seen:
            continue
        seen.add(sig)
        te = re.search(r"Te:\s*(\d+)", block)
        lines = [
            "Filetype: Flipper SubGhz Key File",
            "Version: 1",
            f"Frequency: {freq_hz}",
            "Preset: FuriHalSubGhzPresetOok650Async",
            f"Protocol: {proto}",
            f"Bit: {bits}",
            f"Key: {_spaced_hex(key.group(1), 8)}",
        ]
        if te:
            lines.append(f"TE: {te.group(1)}")
        files.append("\n".join(lines) + "\n")
    return files


RFID_PROTOCOLS = [
    "EM4100/32", "EM4100/16", "EM4100", "H10301", "Indala26", "IoProxXSF", "AWID",
    "FDX-A", "FDX-B", "HIDProx", "HIDExt", "Pyramid", "Viking", "Jablotron",
    "Paradox", "PAC/Stanley", "Keri", "Gallagher", "Nexwatch", "SecuraKey",
    "GProxII", "Noralsy", "Idteck", "Electra", "InstaFob",
]


def parse_rfid(text: str) -> str | None:
    """`rfid read` output → .rfid file content."""
    proto = next((p for p in RFID_PROTOCOLS if re.search(rf"\b{re.escape(p)}\b", text)), None)
    data = HEX_BYTES.search(text)
    if not (proto and data):
        return None
    return ("Filetype: Flipper RFID key\nVersion: 1\n"
            f"Key type: {proto}\nData: {data.group(0).upper()}\n")


IBUTTON_PROTOCOLS = ["DS1990", "DS1992", "DS1996", "DS1971", "DSGeneric", "Cyfral", "Metakom", "Dallas"]


def parse_ibutton(text: str) -> str | None:
    """`ikey read` output → .ibtn file content."""
    proto = next((p for p in IBUTTON_PROTOCOLS if p in text), None)
    data = HEX_BYTES.search(text)
    if not (proto and data):
        return None
    return ("Filetype: Flipper iButton key\nVersion: 2\n"
            f"Protocol: {proto}\nData: {data.group(0).upper()}\n")


def parse_ir(text: str) -> str | None:
    """`ir rx` output → .ir signals file (parsed signals only)."""
    sigs = re.findall(r"^(\w+), A:0x([0-9A-Fa-f]+), C:0x([0-9A-Fa-f]+)", text, re.M)
    uniq = list(dict.fromkeys((p, int(a, 16), int(c, 16)) for p, a, c in sigs))
    if not uniq:
        return None
    out = ["Filetype: IR signals file", "Version: 1"]
    for i, (proto, addr, cmd) in enumerate(uniq, 1):
        out += ["#", f"name: signal_{i}", "type: parsed", f"protocol: {proto}",
                f"address: {_le_bytes(addr)}", f"command: {_le_bytes(cmd)}"]
    return "\n".join(out) + "\n"


# ── Session handling ─────────────────────────────────────────────────────────

class Session:
    """A timestamped folder under data/raw/ holding one collection run."""

    def __init__(self, root: Path, name: str | None = None):
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.id = name or stamp
        self.dir = root / self.id
        self.transcripts = self.dir / "transcripts"   # .cli files are ignored by ingest
        self.transcripts.mkdir(parents=True, exist_ok=True)
        self.saved: list[str] = []
        self.events: list[dict] = []

    def save(self, filename: str, content: str) -> Path:
        path = self.dir / re.sub(r"[^\w.\-]", "_", filename)
        path.write_text(content, encoding="utf-8")
        self.saved.append(path.name)
        print(f"    [+] saved {path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path}")
        return path

    def transcript(self, label: str, text: str):
        (self.transcripts / f"{label}.cli").write_text(text + "\n", encoding="utf-8")

    def log(self, **event):
        event["at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self.events.append(event)

    def write_manifest(self, extra: dict):
        manifest = {"session": self.id, "files": self.saved, "events": self.events, **extra}
        (self.dir / "manifest.json").write_text(json.dumps(manifest, indent=2))


# ── Collection actions ───────────────────────────────────────────────────────

def parse_since(value: str | None) -> date | None:
    """'today', 'yesterday' or 'YYYY-MM-DD' -> date."""
    if not value:
        return None
    v = value.strip().lower()
    if v == "today":
        return date.today()
    if v == "yesterday":
        return date.fromordinal(date.today().toordinal() - 1)
    try:
        return date.fromisoformat(v)
    except ValueError:
        raise argparse.ArgumentTypeError(f"--since must be today, yesterday or YYYY-MM-DD (got {value!r})")


def capture_date(cli: FlipperCLI, path: str) -> date | None:
    """When a file on the Flipper was saved.

    Uses the date the Flipper puts in auto-generated names (RAW-20260929-123231.sub),
    otherwise asks the Flipper for the file's timestamp.
    """
    m = re.search(r"(20\d{2})(\d{2})(\d{2})[-_]\d{4,6}", path.rsplit("/", 1)[-1])
    if m:
        try:
            return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            pass
    try:
        out = cli.run(f"storage timestamp {path}")
    except FlipperBusyError:
        raise
    except Exception:
        return None
    ts = re.search(r"\b(\d{9,11})\b", out)
    return datetime.fromtimestamp(int(ts.group(1))).date() if ts else None


def pull(cli: FlipperCLI, s: Session, folders=SD_FOLDERS, since: date | None = None,
         only: list[str] | None = None):
    """Copy saved captures off the SD card, optionally filtered by date and/or name."""
    what = []
    if since:
        what.append(f"saved on/after {since.isoformat()}")
    if only:
        what.append("matching " + ", ".join(only))
    print("\n  Pulling saved captures from SD card" + (f" ({'; '.join(what)})" if what else ""))
    for folder, ext in folders.items():
        names = [n for n in cli.list_files(folder) if n.lower().endswith(ext)]
        if only:
            names = [n for n in names if any(fnmatch.fnmatch(n.lower(), pat.lower()) for pat in only)]
        kept, skipped, undated = [], 0, []
        for name in names:
            if since:
                d = capture_date(cli, f"{folder}/{name}")
                if d is None:
                    undated.append(name)
                    continue
                if d < since:
                    skipped += 1
                    continue
            kept.append(name)
        note = f" (skipped {skipped} older)" if skipped else ""
        print(f"  {folder}: {len(kept)} file(s){note}")
        for name in undated:
            print(f"    [?] {name}: no date available, skipped — use --only \"{name}\" to include it")
        for name in kept:
            content = cli.read_file(f"{folder}/{name}")
            s.save(name, content)
            s.log(action="pull", source=f"{folder}/{name}")


def scan_subghz(cli, s, freqs_mhz, seconds):
    for mhz in freqs_mhz:
        hz = int(round(mhz * 1_000_000))
        print(f"\n  Sub-GHz: listening on {mhz} MHz for {seconds}s — press the remote now")
        text = cli.stream(f"subghz rx {hz} 0", seconds)
        s.transcript(f"subghz_{hz}", text)
        files = parse_subghz(text, hz)
        for i, content in enumerate(files, 1):
            s.save(f"live_subghz_{hz}_{i}.sub", content)
        s.log(action="scan", type="subghz", frequency=hz, decoded=len(files))
        if not files:
            print("    [-] nothing decoded")


def scan_simple(cli, s, kind, cmd, parser, ext, seconds, hint):
    print(f"\n  {kind}: {hint} ({seconds}s)")
    text = cli.stream(cmd, seconds)
    s.transcript(kind.lower(), text)
    content = parser(text)
    if content:
        s.save(f"live_{kind.lower()}_{datetime.now():%H%M%S}{ext}", content)
    else:
        print("    [-] nothing decoded")
    s.log(action="scan", type=kind.lower(), decoded=bool(content))


# Firmware scanner lines: "Protocols detected: Mifare Classic" (flat) and
# "Protocol [1]: Iso14443-3a -> Mifare Classic" (tree). Take the name after "->"
# when present, else after the colon.
_UID_RE = re.compile(r"\bUID:\s*([0-9A-Fa-f ]{4,})", re.M)


def _detected_nfc_type(text: str) -> str | None:
    """Card family from firmware scanner output.

    Handles both "Protocols detected: Mifare Classic" and
    "Protocol [1]: Iso14443-3a -> Mifare Classic", and the case where the CLI
    collapses them onto one line. Prefers the name after the last "->".
    """
    arrows = re.findall(r"->\s*([^\r\n]+)", text)
    if arrows:
        return arrows[-1].strip()
    m = re.search(r"Protocols? detected:\s*([^\r\n]+)", text)
    if m:
        name = m.group(1).strip()
        if name and not name.lower().startswith("iso14443"):
            return name
    return None


def _partial_nfc_file(card_type: str, uid: str | None) -> str:
    lines = ["Filetype: Flipper NFC device", "Version: 4", f"Device type: {card_type}"]
    if uid:
        lines.append(f"UID: {uid.strip().upper()}")
    if card_type.startswith("Mifare Classic"):
        lines.append("Mifare Classic type: 1K")
    lines.append("# Type detected by scanner; full dump not performed (keys required).")
    return "\n".join(lines) + "\n"


def scan_nfc(cli, s, seconds):
    """Detect and, if possible, dump an NFC tag.

    A full dump of a keyed card (e.g. Mifare Classic) needs its sector keys, which
    the CLI does not have, so it may fail. When it does, the card type from the
    scanner is still recorded — the type itself is the finding.
    """
    print(f"\n  NFC: hold the card to the back of the Flipper ({seconds}s)")
    remote = f"/ext/nfc/fsf_{datetime.now():%Y%m%d_%H%M%S}.nfc"
    cli.run("nfc", timeout=3)
    try:
        scan_out = cli.stream("scanner -t", min(seconds, 6))
        card_type = _detected_nfc_type(scan_out)
        dump_out = ""
        if card_type:
            print(f"    [+] detected: {card_type}")
            dump_out = cli.run(f"dump -f {remote} -t {seconds * 1000}", timeout=seconds + 5)
    finally:
        cli.run("exit", timeout=3)
    s.transcript("nfc", scan_out + "\n----- dump -----\n" + dump_out)

    if not card_type:
        print("    [-] no tag detected (see transcripts/nfc.cli)")
        s.log(action="scan", type="nfc", decoded=False)
        return

    content = cli.read_file(remote)
    if content.startswith("Filetype: Flipper NFC"):
        s.save(Path(remote).name, content)          # full dump succeeded
        s.log(action="scan", type="nfc", decoded=True, card_type=card_type, remote=remote)
    else:                                            # dump failed → keep the detection
        uid = _UID_RE.search(dump_out)
        s.save(f"nfc_{datetime.now():%H%M%S}.nfc",
               _partial_nfc_file(card_type, uid.group(1) if uid else None))
        print(f"    [i] full dump needs the card's keys; recorded the detected type ({card_type})")
        s.log(action="scan", type="nfc", decoded="type_only", card_type=card_type)


def run_scans(cli, s, types, freqs, seconds):
    for t in types:
        try:
            if t == "subghz":
                scan_subghz(cli, s, freqs, seconds)
            elif t == "rfid":
                scan_simple(cli, s, "RFID", "rfid read", parse_rfid, ".rfid", seconds,
                            "hold the 125 kHz card to the back of the Flipper")
            elif t == "ibutton":
                scan_simple(cli, s, "iButton", "ikey read", parse_ibutton, ".ibtn", seconds,
                            "touch the key to the iButton contacts")
            elif t == "ir":
                scan_simple(cli, s, "IR", "ir rx", parse_ir, ".ir", seconds,
                            "point the remote at the Flipper and press buttons")
            elif t == "nfc":
                scan_nfc(cli, s, seconds)
        except serial.SerialException as e:
            print(f"    [!] {t} scan failed: {e}")
            s.log(action="scan", type=t, error=str(e))


def run_pipeline(s: Session, name: str, redact: bool = False) -> Path:
    out = REPO_ROOT / "data" / "processed" / s.id
    out.mkdir(parents=True, exist_ok=True)
    steps = [
        ["tools/ingest.py", str(s.dir), "-o", str(out / "ingested.json")],
        ["tools/analyze.py", "-i", str(out / "ingested.json"), "-o", str(out / "analyzed.json")],
        ["tools/report.py", "-i", str(out / "analyzed.json"), "-o", str(out / "findings_report.md"), "-n", name,
         *(["--redact"] if redact else [])],
    ]
    for step in steps:
        if subprocess.run([sys.executable, *step], cwd=REPO_ROOT).returncode != 0:
            sys.exit(f"  [!] pipeline step failed: {step[0]}")
    return out / "findings_report.md"


# ── CLI ───────────────────────────────────────────────────────────────────────

def _add_common(parser, suppress: bool = False):
    """Options accepted before OR after the pull/scan subcommand.

    The subcommand copies use SUPPRESS defaults so they never overwrite a value
    that was given before the subcommand.
    """
    d = (lambda v: argparse.SUPPRESS) if suppress else (lambda v: v)
    parser.add_argument("--port", default=d(None), help="Serial port (e.g. COM4, /dev/ttyACM0). Auto-detected if omitted.")
    parser.add_argument("--out", default=d(str(REPO_ROOT / "data" / "raw")), help="Root folder for sessions (default: data/raw)")
    parser.add_argument("--session", default=d(None), help="Session folder name (default: timestamp)")
    parser.add_argument("--report", action="store_true", default=d(False), help="Run ingest → analyze → report after collecting")
    parser.add_argument("--name", default=d("Live Assessment"), help="Assessment name used in the report")
    parser.add_argument("--redact", action="store_true", default=d(False), help="Mask UIDs/keys in the report (safe to share)")
    parser.add_argument("-y", "--yes", action="store_true", default=d(False), help="Skip the authorization confirmation")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Flipper Security Framework — collect captures from a Flipper Zero")
    _add_common(ap)
    sub = ap.add_subparsers(dest="mode", required=True)

    pl = sub.add_parser("pull", help="Copy captures saved on the Flipper's SD card")
    pl.add_argument("--since", type=parse_since, help="Only files saved on/after this day: today, yesterday or YYYY-MM-DD")
    pl.add_argument("--only", action="append", metavar="PATTERN",
                    help='Only files whose name matches (repeatable, wildcards ok): --only "RAW-20260929-*"')
    _add_common(pl, suppress=True)

    sc = sub.add_parser("scan", help="Run live read-only scans")
    sc.add_argument("types", nargs="+", choices=[*SCAN_TYPES, "all"], help="What to scan")
    sc.add_argument("--freq", type=float, action="append", help="Sub-GHz frequency in MHz (repeatable; default 433.92 and 315)")
    sc.add_argument("--seconds", type=int, default=10, help="Listen time per scan (default 10)")
    sc.add_argument("--pull", action="store_true", help="Also pull captures saved on the SD card today")
    _add_common(sc, suppress=True)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)

    if not args.yes:
        ok = input("  Only capture devices you own or are authorized to assess. Continue? [y/N] ")
        if ok.strip().lower() != "y":
            sys.exit("  Aborted.")

    port = args.port or find_flipper_port()
    if not port:
        sys.exit("  [!] No Flipper found. Plug it in, close qFlipper, or pass --port COM4.")

    session = Session(Path(args.out), args.session)
    print(f"\n[Flipper Security Framework] Capture session {session.id} on {port}")

    with FlipperCLI(port) as cli:
        info = cli.device_info()
        print(f"  Device: {info['hardware_name'] or info['hardware_model']}  "
              f"firmware {info.get('firmware_version') or '?'} ({info.get('firmware_origin') or 'unknown'})")
        try:
            if args.mode == "pull":
                pull(cli, session, since=args.since, only=args.only)
            else:
                types = list(SCAN_TYPES) if "all" in args.types else args.types
                run_scans(cli, session, types, args.freq or [433.92, 315.0], args.seconds)
                if args.pull:
                    pull(cli, session, since=date.today())  # just today's saves
        except FlipperBusyError as e:
            session.log(action="abort", error=str(e))
            session.write_manifest({"port": port, "device": info})
            sys.exit(f"\n  [!] {e}")

    session.write_manifest({"port": port, "device": info})
    print(f"\n  [✓] {len(session.saved)} capture file(s) in {session.dir}")

    if args.report:
        if not session.saved:
            print("  [!] Nothing captured — skipping report.")
            return
        report = run_pipeline(session, args.name, args.redact)
        print(f"\n  [✓] Report: {report}")


if __name__ == "__main__":
    main()
