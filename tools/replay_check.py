#!/usr/bin/env python3
"""
replay_check.py — Replay-Resistance Check for Sub-GHz RAW captures
Flipper Security Framework

Answers one question from recordings alone: does the remote send the SAME code
every press (fixed code, replayable) or a DIFFERENT code each press (rolling code)?

How it works:
  1. Read the RAW_Data pulse timings from a Flipper RAW .sub file.
  2. Split the recording into frames at long silences. A remote repeats its
     packet several times per press, so the frame that repeats is the packet.
  3. Normalize each frame to multiples of the shortest pulse (TE) so small
     timing jitter doesn't matter.
  4. Compare packets from separate presses:
       ~identical       -> fixed code (replayable)
       same shape, different content -> rolling code (changes every press)
       different shape  -> probably different devices, not comparable

Record at least two separate presses (two Read RAW saves, or two presses in one
recording). This is a heuristic: it assumes the captures come from the same
transmitter, and it reports the similarity so the result can be judged.

Usage:
  python tools/replay_check.py press1.sub press2.sub
"""

import argparse
import re
import sys
from collections import Counter
from difflib import SequenceMatcher
from itertools import combinations
from pathlib import Path

GAP_US = 6000          # silence longer than this separates frames
MIN_PULSES = 16        # shorter frames are noise
NOISE_US = 60          # pulses shorter than this are glitches
IDENTICAL = 0.97       # similarity at/above this = same code
SAME_SHAPE = 0.80      # packet length ratio below this = not comparable


def read_raw_durations(path) -> list[int]:
    """Signed pulse durations (µs) from a Flipper RAW .sub file."""
    values = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if line.startswith("RAW_Data:"):
                values += [int(v) for v in re.findall(r"-?\d+", line.split(":", 1)[1])]
    return values


def durations_from_raw_lines(lines: list[str]) -> list[int]:
    """Same as read_raw_durations, from ingest.py's raw_data list."""
    return [int(v) for line in lines for v in re.findall(r"-?\d+", str(line))]


def _clean(durations: list[int]) -> list[int]:
    """Drop glitches and merge consecutive same-level pulses."""
    out: list[int] = []
    for d in durations:
        if d == 0 or abs(d) < NOISE_US:
            continue
        if out and (out[-1] > 0) == (d > 0):
            out[-1] += d
        else:
            out.append(d)
    return out


def split_frames(durations: list[int]) -> list[list[int]]:
    frames, cur = [], []
    for d in _clean(durations):
        if d < 0 and -d >= GAP_US:
            if len(cur) >= MIN_PULSES:
                frames.append(cur)
            cur = []
        else:
            cur.append(d)
    if len(cur) >= MIN_PULSES:
        frames.append(cur)
    return frames


def _te(frames: list[list[int]]) -> float:
    vals = sorted(abs(d) for fr in frames for d in fr)
    return float(vals[len(vals) // 10]) if vals else 1.0


def packets(durations: list[int]) -> list[tuple]:
    """Distinct packets in one recording, most-repeated first.

    A packet is a frame signature that repeats (the remote's retransmissions).
    If nothing repeats, the longest frame is returned as a best effort.
    """
    frames = split_frames(durations)
    if not frames:
        return []
    te = _te(frames)
    sigs = [tuple((1 if d > 0 else -1) * max(1, round(abs(d) / te)) for d in fr) for fr in frames]
    counts = Counter(sigs)
    repeated = [sig for sig, n in counts.most_common() if n >= 2]
    return repeated or [max(sigs, key=len)]


def compare(a: tuple, b: tuple) -> dict:
    shape = min(len(a), len(b)) / max(len(a), len(b))
    sim = SequenceMatcher(None, a, b, autojunk=False).ratio()
    if shape < SAME_SHAPE:
        verdict = "not_comparable"
    elif sim >= IDENTICAL:
        verdict = "identical"
    else:
        verdict = "changed"
    return {"verdict": verdict, "similarity": round(sim, 3), "length_ratio": round(shape, 3)}


def check(captures: dict[str, list[int]]) -> dict:
    """Compare packets across captures (and distinct packets within one capture).

    captures: {name: durations}. Returns a summary with the overall verdict:
    'fixed', 'rolling' or 'inconclusive'.
    """
    items = [(name, pkt) for name, durs in captures.items() for pkt in packets(durs)]
    pairs = []
    for (na, pa), (nb, pb) in combinations(items, 2):
        result = compare(pa, pb)
        result["a"], result["b"] = na, nb
        pairs.append(result)

    comparable = [p for p in pairs if p["verdict"] != "not_comparable"]
    if any(p["verdict"] == "identical" and p["a"] != p["b"] for p in comparable):
        overall = "fixed"
    elif any(p["verdict"] == "changed" for p in comparable):
        overall = "rolling"
    else:
        overall = "inconclusive"
    return {"verdict": overall, "packets": len(items), "pairs": pairs}


def main():
    ap = argparse.ArgumentParser(description="Replay-resistance check for Flipper RAW .sub recordings")
    ap.add_argument("files", nargs="+", help="Two or more RAW .sub files from the same remote")
    args = ap.parse_args()

    caps = {Path(f).name: read_raw_durations(f) for f in args.files}
    for name, durs in caps.items():
        pk = packets(durs)
        print(f"  {name}: {len(durs)} pulses, {len(pk)} packet(s)" + (f", {len(pk[0])} symbols" if pk else ""))
    result = check(caps)
    for p in result["pairs"]:
        print(f"    {p['a']} vs {p['b']}: {p['verdict']} (similarity {p['similarity']:.0%})")
    label = {"fixed": "FIXED CODE — same code every press (replayable)",
             "rolling": "ROLLING CODE — code changes every press",
             "inconclusive": "INCONCLUSIVE — need two clean presses from the same remote"}[result["verdict"]]
    print(f"\n  Verdict: {label}")
    return 0 if result["verdict"] != "inconclusive" else 1


if __name__ == "__main__":
    sys.exit(main())
