"""
report.py — Findings Report Generator
Flipper Security Framework

Reads analysis JSON and produces a clean, structured Markdown report
with findings, risk levels, and mitigation recommendations.
"""

import json
import os
import argparse
from datetime import datetime


RISK_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}

RISK_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


# Fields that identify a specific real card, key or remote
SENSITIVE_FIELDS = {"uid", "key", "key_data", "atqa", "sak"}


def redact(value) -> str:
    """Mask all but the last byte of a hex identifier: '4A 3B 2C 1D' -> '** ** ** 1D'."""
    parts = str(value).split()
    if len(parts) <= 1:
        text = str(value)
        return "*" * max(len(text) - 2, 0) + text[-2:]
    return " ".join(["**"] * (len(parts) - 1) + [parts[-1]])


def risk_sort_key(result):
    return RISK_ORDER.get(result.get("overall_risk", "INFO"), 0)


def generate_report(analysis: dict, assessment_name: str = "Security Assessment",
                    redacted: bool = False) -> str:
    summary = analysis.get("analysis_summary", {})
    results = sorted(analysis.get("results", []), key=risk_sort_key, reverse=True)
    counts = summary.get("risk_counts", {})
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%MZ")

    lines = []

    # ── Header ────────────────────────────────────────────────────────────────
    lines += [
        f"# {assessment_name}",
        f"**Generated:** {now}  ",
        f"**Framework:** Flipper Security Framework  ",
        f"**Tool:** Flipper Zero + Python Analysis Pipeline  ",
        f"**Identifiers:** {'redacted' if redacted else 'shown in full'}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Total Captures | CRITICAL | HIGH | MEDIUM | LOW | INFO |",
        f"|---|---|---|---|---|---|",
        f"| {summary.get('total_captures', 0)} "
        f"| {counts.get('CRITICAL', 0)} "
        f"| {counts.get('HIGH', 0)} "
        f"| {counts.get('MEDIUM', 0)} "
        f"| {counts.get('LOW', 0)} "
        f"| {counts.get('INFO', 0)} |",
        "",
    ]

    # ── Overall risk posture (captures + replay checks) ───────────────────────
    checks = analysis.get("replay_checks", [])
    present = {lvl for lvl, n in counts.items() if n} | {c["risk"] for c in checks}
    highest = next((lvl for lvl in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if lvl in present), "INFO")

    emoji = RISK_EMOJI.get(highest, "⚪")
    lines += [
        f"**Overall Risk Posture:** {emoji} **{highest}**",
        "",
        "---",
        "",
    ]

    # ── Replay-resistance checks ──────────────────────────────────────────────
    if checks:
        lines += ["## Replay-Resistance Checks", ""]
        for c in checks:
            e = RISK_EMOJI.get(c["risk"], "⚪")
            try:
                freq = f"{int(c['frequency']) / 1e6:.2f} MHz"
            except (TypeError, ValueError):
                freq = str(c["frequency"])
            lines += [
                f"**{e} {c['finding']}** ({freq})",
                "",
                f"> {c['detail']}",
                "",
                "| Recording A | Recording B | Packet similarity | Result |",
                "|---|---|---|---|",
            ]
            for ev in c["evidence"]:
                same = " (two presses in one recording)" if ev["a"] == ev["b"] else ""
                lines.append(f"| `{ev['a']}` | `{ev['b']}`{same} | {ev['similarity']:.0%} | {ev['verdict']} |")
            lines += ["", "**Recommended Mitigations:**"] + [f"- {m}" for m in c["mitigations"]]
            lines += ["", "*Method: repeated packets are extracted from each RAW recording and compared "
                      "after normalizing pulse widths. Assumes the recordings are the same transmitter.*",
                      "", "---", ""]

    lines += ["## Findings", ""]

    # ── Per-capture findings ──────────────────────────────────────────────────
    for i, result in enumerate(results, 1):
        src = result.get("source_file", "unknown")
        ctype = result.get("capture_type", "unknown").upper()
        overall = result.get("overall_risk", "INFO")
        emoji = RISK_EMOJI.get(overall, "⚪")

        lines += [
            f"### Finding {i} — {emoji} {overall} | `{src}` ({ctype})",
            "",
        ]

        raw = result.get("raw_summary", {})
        if raw:
            lines.append("**Capture Details:**")
            for k, v in raw.items():
                if v and k not in ("ingested_at", "source_file", "type"):
                    if redacted and k in SENSITIVE_FIELDS:
                        v = redact(v)
                    lines.append(f"- **{k.replace('_', ' ').title()}:** `{v}`")
            lines.append("")

        for finding in result.get("findings", []):
            frisk = finding.get("risk", "INFO")
            femoji = RISK_EMOJI.get(frisk, "⚪")
            lines += [
                f"**{femoji} {finding['finding']}**",
                "",
                f"> {finding['detail']}",
                "",
                "**Recommended Mitigations:**",
            ]
            for m in finding.get("mitigations", []):
                lines.append(f"- {m}")
            lines.append("")

        lines += ["---", ""]

    # ── Methodology note ──────────────────────────────────────────────────────
    lines += [
        "## Methodology & Scope",
        "",
        "This assessment was conducted using the Flipper Security Framework, "
        "an ethical RF, NFC, and IoT security assessment workflow built on "
        "Flipper Zero hardware and Python analysis scripts.",
        "",
        "**In scope:** Sub-GHz signal capture and classification, NFC/RFID tag "
        "inventory, IR signal documentation, IoT device recon.",
        "",
        "**Out of scope:** Exploitation of discovered vulnerabilities, "
        "unauthorized access to any system, or active attacks of any kind.",
        "",
        "All testing was conducted with proper authorization. "
        "Findings are provided for defensive purposes only.",
        "",
        "---",
        "",
        "*Report generated by Flipper Security Framework — "
        "https://github.com/jakeb2568-sys/flipper-security-framework*",
    ]

    return "\n".join(lines)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Flipper Security Framework — Generate Findings Report"
    )
    parser.add_argument(
        "-i", "--input", default="data/processed/analyzed.json",
        help="Input analysis JSON"
    )
    parser.add_argument(
        "-o", "--output", default="reports/findings_report.md",
        help="Output Markdown report"
    )
    parser.add_argument(
        "-n", "--name", default="Flipper Zero Security Assessment",
        help="Assessment name for report header"
    )
    parser.add_argument(
        "--redact", action="store_true",
        help="Mask UIDs/keys (keep last byte) so the report is safe to share"
    )
    args = parser.parse_args()

    print(f"\n[Flipper Security Framework] Report generation starting...")
    print(f"  Input:  {args.input}")
    print(f"  Output: {args.output}\n")

    with open(args.input, encoding="utf-8") as f:
        analysis = json.load(f)

    report = generate_report(analysis, assessment_name=args.name, redacted=args.redact)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"  [✓] Report written → {args.output}")


if __name__ == "__main__":
    main()
