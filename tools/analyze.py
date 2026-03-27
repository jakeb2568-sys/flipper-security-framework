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
import argparse
from datetime import datetime


# ── Risk classification rules ────────────────────────────────────────────────

SUBGHZ_RISK_RULES = [
    {
        "match": lambda r: r.get("protocol") in ["Princeton", "Nice FLORs", "CAME"],
        "risk": "HIGH",
        "finding": "Fixed-code rolling-door or gate remote detected",
        "detail": "Fixed-code protocols are vulnerable to replay attacks. "
                  "An attacker can capture and retransmit signals to gain physical access.",
        "mitigations": [
            "Replace with rolling-code (KeeLoq, AUT64) or challenge-response systems",
            "Implement RF jamming detection on entry systems",
            "Audit which devices in scope use this protocol"
        ]
    },
    {
        "match": lambda r: r.get("frequency") and "433" in str(r.get("frequency", "")),
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
        "match": lambda r: r.get("frequency") and "315" in str(r.get("frequency", "")),
        "risk": "MEDIUM",
        "finding": "315 MHz transmission captured",
        "detail": "315 MHz band commonly used for US automotive key fobs and garage door openers.",
        "mitigations": [
            "Verify rolling-code implementation on vehicle/access systems",
            "Document devices operating in this band within scope"
        ]
    },
    {
        "match": lambda r: r.get("raw_data") and len(r.get("raw_data", [])) > 0 and not r.get("protocol"),
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
        "match": lambda r: r.get("card_type") in ["Mifare Classic 1K", "Mifare Classic 4K"],
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
        "match": lambda r: r.get("card_type") in ["EM4100", "HID Prox", "Indala"],
        "risk": "CRITICAL",
        "finding": "125 kHz proximity card detected — no encryption",
        "detail": "125 kHz LF cards (EM4100, HID Prox, Indala) have no encryption or authentication. "
                  "UID can be read and cloned trivially from several feet away.",
        "mitigations": [
            "Immediately replace with 13.56 MHz smart card technology",
            "Deploy anti-cloning overlays as interim measure",
            "Assess perimeter for unauthorized long-range readers"
        ]
    },
    {
        "match": lambda r: r.get("uid") is not None and r.get("card_type") not in [
            "Mifare Classic 1K", "Mifare Classic 4K", "EM4100", "HID Prox", "Indala"
        ],
        "risk": "LOW",
        "finding": "NFC/RFID card inventoried",
        "detail": "Card was read and UID recorded. Card type does not match known-vulnerable protocols.",
        "mitigations": [
            "Verify card is an authorized device within scope",
            "Document UID and card type in asset inventory"
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
        "results": results
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

    with open(args.input) as f:
        records = json.load(f)

    analysis = analyze_all(records)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(analysis, f, indent=2)

    summary = analysis["analysis_summary"]
    print(f"  [✓] Analyzed {summary['total_captures']} capture(s)")
    print(f"  Risk breakdown: {summary['risk_counts']}")
    print(f"  → Output: {args.output}")


if __name__ == "__main__":
    main()
