# tools/

| Script | What it does |
|---|---|
| `capture.py` | Collects captures from a Flipper Zero over USB serial — `pull` saved SD-card files or `scan` live (subghz, rfid, ibutton, nfc, ir). Read-only. Add `--report` to run the whole pipeline. |
| `replay_check.py` | Compares RAW Sub-GHz recordings of separate button presses: same packet = fixed code (replayable), changed packet = rolling code. Runs automatically inside `analyze.py`; can also be run on files directly. |
| `ingest.py` | Parses Flipper files (`.sub`, `.nfc`, `.rfid`, `.ibtn`, `.ir`, logs) into normalized JSON. |
| `analyze.py` | Classifies each capture by risk (LOW → CRITICAL) with mitigations. |
| `report.py` | Renders a Markdown findings report with an executive summary. |

```bash
pip install -r requirements.txt
python tools/capture.py pull --report --redact                     # SD card → report
python tools/capture.py pull --since today --report --redact       # only today's saves
python tools/capture.py pull --only "RAW-20260929-*"               # only matching names
python tools/capture.py scan subghz --freq 315 --seconds 15        # live Sub-GHz
python tools/capture.py --port COM4 scan all --pull --report       # everything
```

**Replay-resistance check:** on the Flipper, use Sub-GHz → Read RAW to record one
button press, save, then record and save a second press (or press twice in one
recording). Pull them together and the report gets a *Replay-Resistance Checks* section:

```bash
python tools/capture.py pull --since today --report --redact
python tools/replay_check.py data/raw/<session>/RAW-*.sub         # or run it directly
```

Sessions are written to `data/raw/<timestamp>/` (git-ignored) with a `manifest.json`
and raw CLI transcripts; reports go to `data/processed/<timestamp>/`.
Tests run without hardware: `python -m unittest discover tests`.
