# tools/

| Script | What it does |
|---|---|
| `capture.py` | Collects captures from a Flipper Zero over USB serial — `pull` saved SD-card files or `scan` live (subghz, rfid, ibutton, nfc, ir). Read-only. Add `--report` to run the whole pipeline. |
| `ingest.py` | Parses Flipper files (`.sub`, `.nfc`, `.ir`, logs) into normalized JSON. |
| `analyze.py` | Classifies each capture by risk (LOW → CRITICAL) with mitigations. |
| `report.py` | Renders a Markdown findings report with an executive summary. |

```bash
pip install -r requirements.txt
python tools/capture.py pull --report                              # SD card → report
python tools/capture.py scan subghz --freq 315 --seconds 15        # live Sub-GHz
python tools/capture.py --port COM4 scan all --pull --report       # everything
```

Sessions are written to `data/raw/<timestamp>/` (git-ignored) with a `manifest.json`
and raw CLI transcripts; reports go to `data/processed/<timestamp>/`.
Tests run without hardware: `python -m unittest discover tests`.
