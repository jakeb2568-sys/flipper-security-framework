#!/usr/bin/env python3
"""
demo.py — Full Pipeline Demo
Flipper Security Framework

Runs ingest → analyze → report against the sample captures
to demonstrate the full assessment workflow.
"""

import subprocess
import sys
import os

os.chdir(os.path.dirname(os.path.abspath(__file__)) + "/..")

STEPS = [
    {
        "label": "Step 1: Ingest sample captures",
        "cmd": [sys.executable, "tools/ingest.py", "data/samples", "-o", "data/processed/ingested.json"]
    },
    {
        "label": "Step 2: Analyze & classify findings",
        "cmd": [sys.executable, "tools/analyze.py", "-i", "data/processed/ingested.json", "-o", "data/processed/analyzed.json"]
    },
    {
        "label": "Step 3: Generate findings report",
        "cmd": [sys.executable, "tools/report.py", "-i", "data/processed/analyzed.json", "-o", "reports/findings_report.md", "-n", "Demo Assessment — Sample Captures"]
    },
]

print("=" * 60)
print("  Flipper Security Framework — Full Pipeline Demo")
print("=" * 60)

for step in STEPS:
    print(f"\n{'─'*60}")
    print(f"  {step['label']}")
    print(f"{'─'*60}")
    result = subprocess.run(step["cmd"], capture_output=False)
    if result.returncode != 0:
        print(f"\n  [!] Step failed. Stopping.")
        sys.exit(1)

print(f"\n{'='*60}")
print("  Demo complete!")
print("  → Report: reports/findings_report.md")
print(f"{'='*60}\n")
