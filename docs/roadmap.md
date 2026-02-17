# Project Roadmap

This roadmap outlines the staged development of the Flipper Security Framework.

The goal is to evolve from structured documentation and methodology into a lightweight, modular toolkit that supports authorized physical and IoT security assessments.

---

## Phase 1 – Foundation (In Progress)

Objective: Establish structure, ethics boundaries, and assessment methodology.

- [x] Repository structure (docs / tools / data / templates)
- [x] Legal & ethical guidelines
- [x] High-level assessment methodology
- [x] Threat modeling framework
- [ ] Reporting templates
- [ ] Example assessment (lab-based)

Deliverable:
A documentation-first security framework ready for implementation.

---

## Phase 2 – Artifact Management & Ingest Tools

Objective: Standardize how captured data is organized and labeled.

Planned Features:
- [ ] Metadata schema for captures (JSON/YAML)
- [ ] Folder normalization script for Flipper exports
- [ ] Automatic renaming and timestamp tagging
- [ ] Data validation checks

Deliverable:
`tools/ingest/` module capable of organizing assessment artifacts consistently.

---

## Phase 3 – Analysis Helpers

Objective: Provide non-exploit analytical tooling for common RF/NFC patterns.

Planned Features:
- [ ] Sub-GHz capture parser (read-only)
- [ ] NFC tag inventory summarizer
- [ ] IR capture organization helper
- [ ] Replay-risk classification logic (documentation-based)

Deliverable:
`tools/analyze/` module for artifact review and structured risk documentation.

---

## Phase 4 – Reporting Automation

Objective: Reduce friction between findings and final reports.

Planned Features:
- [ ] Markdown-based finding generator
- [ ] Severity scoring helper
- [ ] Structured output template builder
- [ ] Export to PDF (optional)

Deliverable:
`tools/report/` module to assist in producing consistent assessment reports.

---

## Phase 5 – Extended Capabilities

Objective: Expand framework maturity.

Planned Concepts:
- [ ] IoT asset inventory automation
- [ ] Lightweight risk scoring model
- [ ] Threat surface visualization
- [ ] CI checks for documentation quality
- [ ] Example lab-based case studies

---

## Long-Term Vision

This framework is intended to evolve into a repeatable assessment workflow suitable for:

- Educational environments
- Lab-based security research
- Authorized consulting-style engagements
- Portfolio demonstration of structured security thinking

The emphasis will remain on:
- Ethical boundaries
- Non-exploit analysis
- Clear documentation
- Practical mitigation guidance

