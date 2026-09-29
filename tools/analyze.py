"""
analyze.py — Signal Analysis & Risk Classification
Flipper Security Framework

Reads normalized ingestion JSON and classifies each capture by:
  - Signal/protocol type
  - Risk level (LOW / MEDIUM / HIGH / CRITICAL)
  - Finding category
  - Recommended mitigations
"""

import json
import os
import sys
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import replay_check  # noqa: E402


# ── Risk classification rules ────────────────────────────────────────────────

# Protocol names as the Flipper firmware writes them
FIXED_CODE_PROTOCOLS = {
    "Princeton", "Nice FLO", "CAME", "CAME TWEE", "Gate TX", "Holtek", "Holtek_HT12X",
    "Linear", "LinearDelta3", "Chamberlain Code", "Ansonic", "SMC5326", "Megacode",
    "Mastercode", "Clemsa", "BETT", "Doitrand", "Marantec", "Hormann HSM", "Power Smart",
}
ROLLING_CODE_PROTOCOLS = {
    "KeeLoq", "Star Line", "Security+ 1.0", "Security+ 2.0", "Faac SLH", "Somfy Telis",
    "Somfy Keytis", "Nice FloR-S", "Came Atomo", "Alutech AT-4N", "KingGates Stylo4k",
    "Phoenix_V2", "Scher-Khan",
}


def _mhz(record: dict) -> float:
    """Frequency in MHz (files store Hz), or 0 if missing/unparseable."""
    try:
        return int(str(record.get("frequency")).strip()) / 1_000_000
    except (TypeError, ValueError):
        return 0.0


def _unknown_protocol(record: dict) -> bool:
    return record.get("protocol") in (None, "", "RAW", "BinRAW")


def _not_rolling(record: dict) -> bool:
    return record.get("protocol") not in ROLLING_CODE_PROTOCOLS


SUBGHZ_RISK_RULES = [
    {
        "match": lambda r: r.get("protocol") in FIXED_CODE_PROTOCOLS,
        "risk": "HIGH",
        "finding": "Fixed-code remote detected — replayable",
        "detail": "Fixed-code protocols send the same code on every press. Anyone within radio "
                  "range can record one press and replay it to operate the device.",
        "mitigations": [
            "Replace with rolling-code (KeeLoq, Security+ 2.0) or challenge-response systems",
            "Implement RF jamming detection on entry systems",
            "Audit which devices in scope use this protocol"
        ]
    },
    {
        "match": lambda r: r.get("protocol") in ROLLING_CODE_PROTOCOLS,
        "risk": "LOW",
        "finding": "Rolling-code remote detected — resists simple replay",
        "detail": "The code changes on every press, so a recorded signal will not work twice. "
                  "Residual risks are relay/jam-and-replay attacks (e.g. RollJam) and weak "
                  "manufacturer key management for older KeeLoq implementations.",
        "mitigations": [
            "Keep the key fob in a signal-blocking pouch when not in use if relay attacks are a concern",
            "Prefer systems with challenge-response or UWB distance bounding for keyless entry",
            "Document manufacturer and model for the asset inventory"
        ]
    },
    {
        "match": lambda r: 433.0 <= _mhz(r) <= 435.0 and _not_rolling(r),
        "risk": "MEDIUM",
        "finding": "433 MHz transmission captured",
        "detail": "433 MHz is a common unencrypted ISM band used by many consumer IoT devices, "
                  "sensors, and remote controls. Traffic may be unencrypted.",
        "mitigations": [
            "Identify device owner and model",
            "Assess whether traffic contains sensitive operational data",
            "Consider RF shielding for sensitive areas"
        ]
    },
    {
        "match": lambda r: 300.0 <= _mhz(r) <= 320.0 and _not_rolling(r),
        "risk": "MEDIUM",
        "finding": "315 MHz transmission captured",
        "detail": "315 MHz band commonly used for US automotive key fobs and garage door openers.",
        "mitigations": [
            "Verify rolling-code implementation on vehicle/access systems",
            "Document devices operating in this band within scope"
        ]
    },
    {
        "match": lambda r: (860.0 <= _mhz(r) <= 870.0 or 902.0 <= _mhz(r) <= 928.0) and _not_rolling(r),
        "risk": "MEDIUM",
        "finding": "868/915 MHz transmission captured",
        "detail": "868 MHz (EU) and 902–928 MHz (US) ISM bands carry smart-home, alarm, meter "
                  "and LoRa traffic. Many devices here use weak or no encryption.",
        "mitigations": [
            "Identify the device and whether it is part of a security or alarm system",
            "Check vendor documentation for link-layer encryption",
            "Document devices operating in this band within scope"
        ]
    },
    {
        "match": lambda r: _unknown_protocol(r) and len(r.get("raw_data", [])) > 0,
        "risk": "LOW",
        "finding": "Unidentified Sub-GHz transmission captured (raw)",
        "detail": "Signal was captured but protocol could not be identified. "
                  "May be proprietary or encrypted.",
        "mitigations": [
            "Perform deeper signal analysis with a SDR (e.g. GQRX, URH)",
            "Document frequency, timing, and signal characteristics",
            "Cross-reference with known protocol databases"
        ]
    },
]

NFC_RISK_RULES = [
    {
        "match": lambda r: str(r.get("card_type") or "").startswith("Mifare Classic"),
        "risk": "HIGH",
        "finding": "Mifare Classic card detected — known cryptographic weakness",
        "detail": "Mifare Classic uses the broken CRYPTO1 cipher. Cards can be cloned "
                  "with commodity hardware. Widely used in access control and transit systems.",
        "mitigations": [
            "Replace with Mifare DESFire EV2/EV3 or ICODE SLIX2",
            "Implement mutual authentication at the reader level",
            "Audit all access control readers using this card type"
        ]
    },
    {
        "match": lambda r: r.get("uid") is not None and not str(r.get("card_type") or "").startswith("Mifare Classic"),
        "risk": "LOW",
        "finding": "NFC/RFID card inventoried",
        "detail": "Card was read and UID recorded. Card type does not match known-vulnerable protocols.",
        "mitigations": [
            "Verify card is an authorized device within scope",
            "Document UID and card type in asset inventory"
        ]
    },
]

RFID_RISK_RULES = [
    {
        "match": lambda r: r.get("card_type") and not str(r["card_type"]).startswith("FDX"),
        "risk": "CRITICAL",
        "finding": "125 kHz proximity credential detected — no encryption",
        "detail": "125 kHz LF credentials (EM4100, HID Prox/H10301, Indala, AWID, ...) have no "
                  "encryption or authentication. The ID can be read and cloned in seconds, "
                  "sometimes from several feet away with a long-range reader.",
        "mitigations": [
            "Migrate to 13.56 MHz credentials with mutual authentication (DESFire EV2/EV3, iCLASS SE, SEOS)",
            "Pair the badge with a second factor (PIN or biometric) at sensitive doors",
            "Deploy anti-cloning card sleeves as an interim measure"
        ]
    },
    {
        "match": lambda r: str(r.get("card_type") or "").startswith("FDX"),
        "risk": "LOW",
        "finding": "Animal ID tag (ISO 11784/5) read",
        "detail": "FDX tags are animal microchips. They are read-only identifiers with no access-control role.",
        "mitigations": ["Document in inventory; no action needed for access control"]
    },
]

IBUTTON_RISK_RULES = [
    {
        "match": lambda r: bool(r.get("protocol")),
        "risk": "HIGH",
        "finding": "iButton contact key detected — clonable",
        "detail": "Dallas/Cyfral/Metakom keys expose a fixed ID with no authentication. "
                  "A single touch is enough to read and duplicate the key onto a blank.",
        "mitigations": [
            "Replace with keys that use challenge-response (e.g. DS1961S/DS28E-series secure authenticators)",
            "Restrict physical access to readers and key holders",
            "Log and review key usage at controlled doors"
        ]
    },
]

IR_RISK_RULES = [
    {
        "match": lambda r: any(
            s.get("name", "").lower() in ["power", "vol+", "vol-", "mute", "input"]
            for s in r.get("signals", [])
        ),
        "risk": "LOW",
        "finding": "IR remote signals captured — consumer A/V device",
        "detail": "Standard IR remote codes captured for common A/V equipment. "
                  "IR has no authentication; signals can be replayed freely.",
        "mitigations": [
            "If device controls sensitive systems (displays in secure areas, conference rooms), "
            "consider IR blockers or physical controls",
            "Document devices controllable via captured codes"
        ]
    },
    {
        "match": lambda r: len(r.get("signals", [])) > 0,
        "risk": "LOW",
        "finding": "IR signals captured",
        "detail": "Infrared signals recorded. IR has no encryption or authentication.",
        "mitigations": [
            "Identify controlled device and assess sensitivity of function",
            "Document in IR signal inventory"
        ]
    },
]

LOG_RISK_RULES = [
    {
        "match": lambda r: any(
            kw in " ".join(r.get("lines", [])).lower()
            for kw in ["error", "fail", "denied", "unauthorized", "warning"]
        ),
        "risk": "MEDIUM",
        "finding": "Log entries contain error or denial indicators",
        "detail": "Possible anomalous activity or misconfiguration indicated in log output.",
        "mitigations": [
            "Review full log for context",
            "Correlate with other captures from the same timeframe"
        ]
    },
]

TYPE_RULES = {
    "subghz": SUBGHZ_RISK_RULES,
    "nfc":    NFC_RISK_RULES,
    "rfid":   RFID_RISK_RULES,
    "ibutton": IBUTTON_RISK_RULES,
    "ir":     IR_RISK_RULES,
    "log":    LOG_RISK_RULES,
}

RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def classify(record: dict) -> dict:
    """Apply risk rules to a normalized record and return an analysis result."""
    rtype = record.get("type", "log")
    rules = TYPE_RULES.get(rtype, LOG_RISK_RULES)

    findings = []
    for rule in rules:
        try:
            if rule["match"](record):
                findings.append({
                    "risk": rule["risk"],
                    "finding": rule["finding"],
                    "detail": rule["detail"],
                    "mitigations": rule["mitigations"]
                })
        except Exception:
            continue

    # Determine overall risk level for this capture
    if findings:
        overall_risk = max(findings, key=lambda f: RISK_ORDER.get(f["risk"], 0))["risk"]
    else:
        overall_risk = "INFO"
        findings.append({
            "risk": "INFO",
            "finding": "No specific risk patterns matched",
            "detail": "Capture was ingested but did not match any known risk signatures.",
            "mitigations": ["Review raw data manually for context"]
        })

    return {
        "source_file": record.get("source_file"),
        "capture_type": rtype,
        "overall_risk": overall_risk,
        "findings": findings,
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "raw_summary": {
            k: v for k, v in record.items()
            if k not in ("raw_data", "blocks", "lines", "parsed_fields", "filepath")
        }
    }


REPLAY_FINDINGS = {
    "fixed": {
        "risk": "HIGH",
        "finding": "Replay-resistance check: same code on every press — fixed code",
        "detail": "Separate button presses produced the same packet. Anyone who records one "
                  "press can replay it to operate the device.",
        "mitigations": [
            "Replace with a rolling-code or challenge-response system",
            "Until replaced, treat the remote like a physical key: limit where it is used and who holds it"
        ]
    },
    "rolling": {
        "risk": "LOW",
        "finding": "Replay-resistance check: code changes on every press — rolling code behavior",
        "detail": "Separate button presses produced packets with the same structure but different "
                  "content, so a recorded press cannot simply be replayed. Residual risk: "
                  "jam-and-replay (RollJam) and relay attacks, which this check does not test.",
        "mitigations": [
            "No action needed against simple replay",
            "Consider a signal-blocking pouch if relay attacks on keyless entry are a concern"
        ]
    },
}


def replay_checks(records: list) -> list:
    """Compare RAW Sub-GHz recordings made on the same frequency.

    Each frequency with two or more comparable packets gets one finding.
    Assumes recordings on the same frequency in one session are the same remote.
    """
    groups = {}
    for r in records:
        if r.get("type") == "subghz" and r.get("raw_data"):
            groups.setdefault(r.get("frequency"), {})[r["source_file"]] = \
                replay_check.durations_from_raw_lines(r["raw_data"])

    checks = []
    for freq, caps in groups.items():
        result = replay_check.check(caps)
        if result["verdict"] not in REPLAY_FINDINGS:
            continue
        evidence = [p for p in result["pairs"] if p["verdict"] != "not_comparable"]
        checks.append({
            **REPLAY_FINDINGS[result["verdict"]],
            "verdict": result["verdict"],
            "frequency": freq,
            "files": sorted(caps),
            "evidence": [
                {"a": p["a"], "b": p["b"], "similarity": p["similarity"], "verdict": p["verdict"]}
                for p in evidence
            ],
        })
    return checks


def analyze_all(records: list) -> dict:
    """Analyze a list of ingested records and produce a summary report structure."""
    results = [classify(r) for r in records]

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for r in results:
        counts[r["overall_risk"]] = counts.get(r["overall_risk"], 0) + 1

    return {
        "analysis_summary": {
            "total_captures": len(results),
            "risk_counts": counts,
            "analyzed_at": datetime.utcnow().isoformat() + "Z"
        },
        "results": results,
        "replay_checks": replay_checks(records),
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Flipper Security Framework — Analyze & Classify Captures"
    )
    parser.add_argument(
        "-i", "--input", default="data/processed/ingested.json",
        help="Input ingested JSON (default: data/processed/ingested.json)"
    )
    parser.add_argument(
        "-o", "--output", default="data/processed/analyzed.json",
        help="Output analysis JSON (default: data/processed/analyzed.json)"
    )
    args = parser.parse_args()

    print(f"\n[Flipper Security Framework] Analysis starting...")
    print(f"  Input:  {args.input}")
    print(f"  Output: {args.output}\n")

    with open(args.input, encoding="utf-8") as f:
        records = json.load(f)

    analysis = analyze_all(records)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(analysis, f, indent=2)

    summary = analysis["analysis_summary"]
    print(f"  [✓] Analyzed {summary['total_captures']} capture(s)")
    print(f"  Risk breakdown: {summary['risk_counts']}")
    for c in analysis["replay_checks"]:
        print(f"  Replay check @ {c['frequency']}: {c['verdict'].upper()} ({', '.join(c['files'])})")
    print(f"  → Output: {args.output}")


if __name__ == "__main__":
    main()
