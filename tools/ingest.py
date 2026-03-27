"""
ingest.py — Flipper Zero Capture Ingestion & Normalization
Flipper Security Framework

Parses raw Flipper Zero output files (.sub, .nfc, .ir, .txt logs)
and normalizes them into a standard JSON format for analysis.
"""

import os
import json
import re
import argparse
from datetime import datetime
from pathlib import Path


# ── Supported file type parsers ──────────────────────────────────────────────

def parse_subghz(filepath: str) -> dict:
    """Parse a Flipper Zero Sub-GHz capture file (.sub)."""
    result = {
        "type": "subghz",
        "source_file": os.path.basename(filepath),
        "protocol": None,
        "frequency": None,
        "raw_data": [],
        "parsed_fields": {}
    }

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Frequency:"):
                result["frequency"] = line.split(":", 1)[1].strip()
            elif line.startswith("Preset:") or line.startswith("Protocol:"):
                result["protocol"] = line.split(":", 1)[1].strip()
            elif line.startswith("RAW_Data:") or line.startswith("Data:"):
                result["raw_data"].append(line.split(":", 1)[1].strip())
            elif ":" in line:
                k, v = line.split(":", 1)
                result["parsed_fields"][k.strip()] = v.strip()

    return result


def parse_nfc(filepath: str) -> dict:
    """Parse a Flipper Zero NFC dump file (.nfc)."""
    result = {
        "type": "nfc",
        "source_file": os.path.basename(filepath),
        "card_type": None,
        "uid": None,
        "atqa": None,
        "sak": None,
        "blocks": [],
        "parsed_fields": {}
    }

    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line.startswith("Card Type:"):
                result["card_type"] = line.split(":", 1)[1].strip()
            elif line.startswith("UID:"):
                result["uid"] = line.split(":", 1)[1].strip()
            elif line.startswith("ATQA:"):
                result["atqa"] = line.split(":", 1)[1].strip()
            elif line.startswith("SAK:"):
                result["sak"] = line.split(":", 1)[1].strip()
            elif re.match(r"Block \d+:", line):
                result["blocks"].append(line)
            elif ":" in line:
                k, v = line.split(":", 1)
                result["parsed_fields"][k.strip()] = v.strip()

    return result


def parse_ir(filepath: str) -> dict:
    """Parse a Flipper Zero IR capture file (.ir)."""
    result = {
        "type": "ir",
        "source_file": os.path.basename(filepath),
        "signals": [],
        "parsed_fields": {}
    }

    current_signal = {}
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line.startswith("name:"):
                if current_signal:
                    result["signals"].append(current_signal)
                current_signal = {"name": line.split(":", 1)[1].strip()}
            elif line.startswith("type:"):
                current_signal["type"] = line.split(":", 1)[1].strip()
            elif line.startswith("protocol:"):
                current_signal["protocol"] = line.split(":", 1)[1].strip()
            elif line.startswith("address:"):
                current_signal["address"] = line.split(":", 1)[1].strip()
            elif line.startswith("command:"):
                current_signal["command"] = line.split(":", 1)[1].strip()
            elif ":" in line:
                k, v = line.split(":", 1)
                result["parsed_fields"][k.strip()] = v.strip()

    if current_signal:
        result["signals"].append(current_signal)

    return result


def parse_generic_log(filepath: str) -> dict:
    """Fallback parser for generic Flipper text logs."""
    result = {
        "type": "log",
        "source_file": os.path.basename(filepath),
        "lines": [],
        "parsed_fields": {}
    }
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                result["lines"].append(line)
                if ":" in line:
                    k, v = line.split(":", 1)
                    result["parsed_fields"][k.strip()] = v.strip()
    return result


# ── File routing ─────────────────────────────────────────────────────────────

PARSERS = {
    ".sub": parse_subghz,
    ".nfc": parse_nfc,
    ".ir":  parse_ir,
    ".txt": parse_generic_log,
    ".log": parse_generic_log,
}


def ingest_file(filepath: str) -> dict:
    """Route a file to the correct parser and wrap with metadata."""
    ext = Path(filepath).suffix.lower()
    parser = PARSERS.get(ext, parse_generic_log)
    data = parser(filepath)
    data["ingested_at"] = datetime.utcnow().isoformat() + "Z"
    data["filepath"] = filepath
    return data


def ingest_directory(directory: str) -> list:
    """Ingest all supported files from a directory."""
    records = []
    supported = set(PARSERS.keys())
    for root, _, files in os.walk(directory):
        for fname in files:
            if Path(fname).suffix.lower() in supported:
                fpath = os.path.join(root, fname)
                print(f"  [+] Ingesting: {fpath}")
                records.append(ingest_file(fpath))
    return records


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Flipper Security Framework — Ingest & Normalize captures"
    )
    parser.add_argument(
        "input", help="Path to a capture file or directory of captures"
    )
    parser.add_argument(
        "-o", "--output", default="data/processed/ingested.json",
        help="Output JSON file (default: data/processed/ingested.json)"
    )
    args = parser.parse_args()

    input_path = args.input
    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    print(f"\n[Flipper Security Framework] Ingestion starting...")
    print(f"  Input:  {input_path}")
    print(f"  Output: {args.output}\n")

    if os.path.isdir(input_path):
        records = ingest_directory(input_path)
    elif os.path.isfile(input_path):
        print(f"  [+] Ingesting: {input_path}")
        records = [ingest_file(input_path)]
    else:
        print(f"  [!] Error: '{input_path}' not found.")
        return

    with open(args.output, "w") as f:
        json.dump(records, f, indent=2)

    print(f"\n  [✓] Ingested {len(records)} capture(s) → {args.output}")


if __name__ == "__main__":
    main()
