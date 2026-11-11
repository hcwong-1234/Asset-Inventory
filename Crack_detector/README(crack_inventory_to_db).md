# Crack Inventory Uploader (Python -> MySQL `soft_inv`)

This document explains the Python uploader script in detail:

- Script: `crack_inventory_to_db.py`
- Purpose: run the crack detector, collect machine metadata, and insert one row into `dsg_it.soft_inv`
- Target OS for production use: **Windows** (because it calls PowerShell and Win32 CIM commands)

---

## 1. What this script does

The script performs this flow:

1. Loads SSH + MySQL configuration (hardcoded values and/or environment variables).
2. Runs `crack_inventory_detector.ps1` to generate report/alerts JSON.
3. Reads the generated JSON files.
4. Computes overall severity (`high`, `medium`, `low`, `none`).
5. Collects:
   - PC name
   - MAC addresses
   - collection timestamp
6. Builds a JSON payload for the `result` column.
7. Opens an SSH tunnel (password-based) to your server.
8. Inserts a row into `dsg_it.soft_inv`.

---

## 2. Database mapping (`dsg_it.soft_inv`)

Your table:

```sql
DESC soft_inv;
```

Relevant column mapping:

- `id` -> auto-increment, not manually set by script
- `timestamp` -> current local collection datetime
- `computer_name` -> hostname detected from report / environment
- `severity` -> highest severity found in detector results
- `mac_address` -> comma-separated MAC address string
- `result` -> JSON text containing summary + full detector report (or reduced payload if too large)

---

## 3. Files

- `crack_inventory_to_db.py`  
  Main uploader script.

- `crack_inventory_detector.ps1`  
  Existing detector script that generates inventory and alert JSON files.

- `requirements-crack-inventory-to-db.txt`  
  Python package requirements.

---

## 4. Requirements

### 4.1 Runtime requirements (Windows endpoint)

1. Windows with PowerShell available.
2. Python 3.9+ (recommended 3.10 or 3.11).
3. Network reachability to SSH host (`152.42.228.57:22`).
4. MySQL service reachable from the SSH server at `127.0.0.1:3306`.
5. The detector script present:
   - `crack_inventory_detector.ps1`

### 4.2 Python dependencies

- `sshtunnel` (creates SSH tunnel, uses Paramiko underneath)
- `PyMySQL` (MySQL client library)

Install:

```powershell
cd C:\path\to\Crack_detector
python -m pip install -r requirements-crack-inventory-to-db.txt
```

Or manually:

```powershell
python -m pip install sshtunnel PyMySQL
```

---

## 5. Configuration

Configuration is inside `crack_inventory_to_db.py`.

Default section:

- `HARDCODED_SSH_HOST = "152.42.228.57"`
- `HARDCODED_SSH_PORT = 22`
- `HARDCODED_SSH_USER = "root"`
- `HARDCODED_SSH_PASSWORD = ""`
- `HARDCODED_DB_NAME = "dsg_it"`
- `HARDCODED_DB_TABLE = "soft_inv"`
- `HARDCODED_DB_USER = "romel"`
- `HARDCODED_DB_PASSWORD = "passWD123"`

### 5.1 Password-based SSH handling

For fully automatic authentication in compiled `.exe`, choose one:

1. Put SSH password in code (`HARDCODED_SSH_PASSWORD`)  
2. Set env var `CRACK_SSH_PASSWORD` before execution

Environment variables override hardcoded values:

- `CRACK_SSH_HOST`
- `CRACK_SSH_PORT`
- `CRACK_SSH_USER`
- `CRACK_SSH_PASSWORD`
- `CRACK_DB_NAME`
- `CRACK_DB_TABLE`
- `CRACK_DB_USER`
- `CRACK_DB_PASSWORD`

Example (PowerShell):

```powershell
$env:CRACK_SSH_PASSWORD = "your_ssh_password"
$env:CRACK_DB_PASSWORD = "your_mysql_password"
python .\crack_inventory_to_db.py
```

---

## 6. How to run (Python mode)

Basic run:

```powershell
python .\crack_inventory_to_db.py
```

Optional flags:

```powershell
python .\crack_inventory_to_db.py `
  --include-appx-packages `
  --pretty-json `
  --event-lookback-hours 48 `
  --max-events-per-log 400 `
  --max-process-hashes 200
```

What you should see on success:

- inserted row id
- timestamp
- computer_name
- severity
- mac_address

---

## 7. Compile to `.exe` (PyInstaller)

Install build tool:

```powershell
python -m pip install pyinstaller
```

Build (important: include detector script in the executable bundle):

```powershell
cd C:\path\to\Crack_detector
pyinstaller --onefile --name crack_inventory_uploader --add-data "crack_inventory_detector.ps1;." crack_inventory_to_db.py
```

Output:

- `dist\crack_inventory_uploader.exe`

Run:

```powershell
.\dist\crack_inventory_uploader.exe
```

Notes:

- The script already handles PyInstaller bundle paths (`sys._MEIPASS`) to find `crack_inventory_detector.ps1`.
- If your AV blocks unknown executables, sign the `.exe` in your deployment pipeline.

---

## 8. Detailed code walkthrough

### 8.1 `load_config()`

- Reads all runtime config values.
- Priority: environment variable -> hardcoded fallback.
- Returns dictionary used by tunnel and DB functions.

### 8.2 `run_detector(...)`

- Executes `crack_inventory_detector.ps1` with selected CLI options.
- Tracks report files before/after run.
- Selects the newest generated:
  - `crack_inventory_report_*.json`
  - `crack_inventory_alerts_*.json`
- Parses JSON and validates format.

### 8.3 `get_mac_addresses()`

- Uses PowerShell CIM query:
  - `Win32_NetworkAdapterConfiguration` with `IPEnabled=TRUE`
- Returns unique non-empty MAC addresses list.

### 8.4 `compute_overall_severity(...)`

- First reads `alert_summary` from report.
- Severity precedence:
  1. `high`
  2. `medium`
  3. `low`
  4. `none`

### 8.5 `encode_result_payload(...)`

- Serializes payload to JSON for `soft_inv.result`.
- Protects against MySQL `MEDIUMTEXT` max size (`16,777,215` bytes):
  - Stores full payload when size fits
  - Falls back to reduced summary if too large
  - Trims alerts list further if still too large

### 8.6 `insert_soft_inv_row(...)`

- Creates SSH tunnel using:
  - `SSHTunnelForwarder`
  - username/password auth
- Connects to MySQL over local forwarded port via `PyMySQL`.
- Executes parameterized INSERT:

```sql
INSERT INTO soft_inv (`timestamp`, `computer_name`, `severity`, `mac_address`, `result`)
VALUES (%s, %s, %s, %s, %s)
```

- Commits transaction and returns inserted row id.

### 8.7 `parse_args()` + `main()`

- Defines CLI flags.
- Handles frozen executable mode (PyInstaller).
- Runs the full pipeline and prints result summary.

---

## 9. Security guidance

If this is deployed broadly, avoid hardcoding plaintext secrets in source/exe.

Recommended options:

1. Use environment variables set by deployment tooling.
2. Store encrypted secret in Windows Credential Manager + decrypt at runtime.
3. Create a dedicated least-privilege DB user for `INSERT` on `dsg_it.soft_inv` only.

---

## 10. Verification SQL

Check newest uploads:

```sql
SELECT id, `timestamp`, computer_name, severity, mac_address
FROM dsg_it.soft_inv
ORDER BY id DESC
LIMIT 20;
```

Inspect result payload (snippet):

```sql
SELECT id, LEFT(result, 500) AS result_preview
FROM dsg_it.soft_inv
ORDER BY id DESC
LIMIT 5;
```

---

## 11. Troubleshooting

1. `Missing required secret`  
   Set `CRACK_SSH_PASSWORD` / `CRACK_DB_PASSWORD` or hardcoded values.

2. `Detector script not found`  
   Ensure `crack_inventory_detector.ps1` is in the same folder as script/exe, or pass `--detector-script`.

3. SSH connection fails  
   Verify host/user/password and firewall access on port 22.

4. MySQL auth/table errors  
   Verify DB user credentials and table exists:
   - `dsg_it.soft_inv`

5. No JSON outputs from detector  
   Run detector script directly first:

```powershell
powershell -ExecutionPolicy Bypass -File .\crack_inventory_detector.ps1 -OutputDir .\logs -PrettyJson
```

---

## 12. Suggested deployment checklist

1. Confirm detector script runs on a test endpoint.
2. Confirm one Python run inserts a row in `soft_inv`.
3. Build `.exe` and retest end-to-end.
4. Move secrets out of source into secured runtime configuration.
5. Schedule execution (Task Scheduler) if continuous collection is required.
