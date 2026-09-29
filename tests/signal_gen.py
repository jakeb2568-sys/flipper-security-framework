"""
signal_gen.py — synthetic Flipper RAW .sub recordings for tests and samples.

Builds a KeeLoq-style PWM remote: preamble, header gap, 66-bit packet
(32-bit hop + 28-bit serial + button/status), repeated a few times per press,
with timing jitter and noise at the start — roughly what Read RAW records.
"""

import random

TE = 400


def _frame(bits: str) -> list[int]:
    out = []
    for _ in range(11):                 # preamble
        out += [TE, -TE]
    out += [TE, -10 * TE]               # header
    for b in bits:                      # PWM: 1 = short high, 0 = long high
        out += [TE, -2 * TE] if b == "1" else [2 * TE, -TE]
    return out


def press(bits: str, rng: random.Random, repeats: int = 4) -> list[int]:
    """One button press: noise, then the packet repeated with gaps."""
    out = [rng.choice([1, -1]) * rng.randint(30, 300) for _ in range(12)]
    out.append(-20000)
    for _ in range(repeats):
        out += _frame(bits) + [-16000]
    # timing jitter like a real receiver
    return [d + (1 if d > 0 else -1) * rng.randint(-40, 40) if abs(d) < 5000 else d for d in out]


def rolling_bits(rng: random.Random, serial: str) -> str:
    hop = "".join(rng.choice("01") for _ in range(32))    # encrypted part, new every press
    return hop + serial + "0010" + "00"


def fixed_bits(serial: str) -> str:
    return "10110010" * 4 + serial + "0010" + "00"


def to_sub(durations: list[int], frequency: int = 433920000) -> str:
    lines = [
        "Filetype: Flipper SubGhz RAW File",
        "Version: 1",
        f"Frequency: {frequency}",
        "Preset: FuriHalSubGhzPresetOok650Async",
        "Protocol: RAW",
    ]
    for i in range(0, len(durations), 512):
        lines.append("RAW_Data: " + " ".join(str(d) for d in durations[i:i + 512]))
    return "\n".join(lines) + "\n"


def make_pair(kind: str, seed: int = 7, frequency: int = 433920000) -> tuple[str, str]:
    """Two presses of the same remote as .sub file contents. kind: 'fixed' or 'rolling'."""
    rng = random.Random(seed)
    serial = "".join(rng.choice("01") for _ in range(28))
    presses = []
    for _ in range(2):
        bits = fixed_bits(serial) if kind == "fixed" else rolling_bits(rng, serial)
        presses.append(to_sub(press(bits, rng), frequency))
    return presses[0], presses[1]
