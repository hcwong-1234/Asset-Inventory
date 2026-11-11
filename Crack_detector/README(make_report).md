# Compliance Markdown Report Generator (Cracked Software / Licensing Indicators)

This script reads two JSON files:

- `crack_inventory_report_*.json` (software + system inventory + metadata)
- `crack_inventory_alerts_*.json` (alert rules triggered)

It then produces a **single Markdown report** summarizing:
- device and collection metadata
- inventory counts
- alerts & indicators
- suspected “crack/activator” software based on keyword matching
- a list of recent installs (top 25 by install date)
- a list of detected commercial software brands (selected list)

> Note: Findings are **indicators**, not proof. Validate with licensing records and deeper checks.

---

## Requirements

- Python **3.9+** (3.8 may work, but 3.9+ is recommended)
- No external packages required (standard library only)

---

## Files

- `make_report.py` (this script)
- Input JSONs:
  - `crack_inventory_report_*.json`
  - `crack_inventory_alerts_*.json`

---

## How to Run

From the same folder as the script:

```bash
python make_report.py --inventory crack_inventory_report_HOST.json --alerts crack_inventory_alerts_HOST.json
