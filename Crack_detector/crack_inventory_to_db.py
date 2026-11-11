#!/usr/bin/env python3
"""
Run crack inventory detection and upload findings into dsg_it.soft_inv.

Target table schema:
  id            -> auto_increment (not inserted explicitly)
  timestamp     -> collection timestamp
  computer_name -> PC name
  severity      -> highest severity found (high/medium/low/none)
  mac_address   -> detected MAC addresses (comma-separated)
  result        -> JSON payload with detector report + alerts

Dependencies:
  pip install sshtunnel pymysql
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

try:
    import pymysql
    from sshtunnel import SSHTunnelForwarder
except ImportError as exc:  # pragma: no cover
    print(
        "[ERROR] Missing dependency. Install with:\n"
        "  pip install sshtunnel pymysql\n"
        f"Details: {exc}"
    )
    raise


SCRIPT_VERSION = "1.0.0"
MAX_MEDIUMTEXT_BYTES = 16_777_215


# ---------------------------
# Configuration
# ---------------------------
# For fully automatic auth in compiled .exe:
# 1) Set these values directly below, OR
# 2) Set environment variables before launch.
#
# Environment variable names:
# - CRACK_SSH_HOST / CRACK_SSH_PORT / CRACK_SSH_USER / CRACK_SSH_PASSWORD
# - CRACK_DB_NAME / CRACK_DB_TABLE / CRACK_DB_USER / CRACK_DB_PASSWORD

HARDCODED_SSH_HOST = "152.42.228.57"
HARDCODED_SSH_PORT = 22
HARDCODED_SSH_USER = "root"
HARDCODED_SSH_PASSWORD = ""  # <- set password here if you want no prompt at all

HARDCODED_DB_NAME = "dsg_it"
HARDCODED_DB_TABLE = "soft_inv"
HARDCODED_DB_USER = "romel"
HARDCODED_DB_PASSWORD = "passWD123"

REMOTE_DB_HOST = "127.0.0.1"
REMOTE_DB_PORT = 3306


def load_config() -> Dict[str, Any]:
    cfg = {
        "ssh_host": os.getenv("CRACK_SSH_HOST", HARDCODED_SSH_HOST),
        "ssh_port": int(os.getenv("CRACK_SSH_PORT", str(HARDCODED_SSH_PORT))),
        "ssh_user": os.getenv("CRACK_SSH_USER", HARDCODED_SSH_USER),
        "ssh_password": os.getenv("CRACK_SSH_PASSWORD", HARDCODED_SSH_PASSWORD),
        "db_name": os.getenv("CRACK_DB_NAME", HARDCODED_DB_NAME),
        "db_table": os.getenv("CRACK_DB_TABLE", HARDCODED_DB_TABLE),
        "db_user": os.getenv("CRACK_DB_USER", HARDCODED_DB_USER),
        "db_password": os.getenv("CRACK_DB_PASSWORD", HARDCODED_DB_PASSWORD),
    }
    return cfg


def run_cmd(cmd: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=False)


def require_non_empty(value: str, field_name: str) -> None:
    if not value:
        raise RuntimeError(
            f"Missing required secret: {field_name}. "
            f"Set it in the script or via environment variable."
        )


def powershell_json(script: str) -> Any:
    completed = run_cmd(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "PowerShell command failed.\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )
    raw = completed.stdout.strip()
    if not raw:
        return []
    return json.loads(raw)


def get_mac_addresses() -> List[str]:
    script = (
        "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter \"IPEnabled=TRUE\" "
        "| Select-Object -ExpandProperty MACAddress "
        "| Where-Object { $_ -and $_.Trim() -ne '' } "
        "| Sort-Object -Unique "
        "| ConvertTo-Json -Compress"
    )
    try:
        data = powershell_json(script)
    except Exception:
        return []

    if isinstance(data, str):
        return [data]
    if isinstance(data, list):
        return [x for x in data if isinstance(x, str)]
    return []


def run_detector(
    detector_script: Path,
    output_dir: Path,
    include_appx: bool,
    pretty_json: bool,
    event_lookback_hours: int,
    max_events_per_log: int,
    max_process_hashes: int,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    if not detector_script.exists():
        raise FileNotFoundError(f"Detector script not found: {detector_script}")

    output_dir.mkdir(parents=True, exist_ok=True)
    before_reports = set(output_dir.glob("crack_inventory_report_*.json"))
    before_alerts = set(output_dir.glob("crack_inventory_alerts_*.json"))

    cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(detector_script),
        "-OutputDir",
        str(output_dir),
        "-EventLookbackHours",
        str(event_lookback_hours),
        "-MaxEventsPerLog",
        str(max_events_per_log),
        "-MaxProcessHashes",
        str(max_process_hashes),
    ]
    if include_appx:
        cmd.append("-IncludeAppxPackages")
    if pretty_json:
        cmd.append("-PrettyJson")

    completed = run_cmd(cmd)
    if completed.returncode != 0:
        raise RuntimeError(
            "Detector script failed.\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )

    after_reports = set(output_dir.glob("crack_inventory_report_*.json"))
    after_alerts = set(output_dir.glob("crack_inventory_alerts_*.json"))
    new_reports = sorted(after_reports - before_reports, key=lambda p: p.stat().st_mtime)
    new_alerts = sorted(after_alerts - before_alerts, key=lambda p: p.stat().st_mtime)

    if new_reports:
        report_path = new_reports[-1]
    else:
        report_candidates = sorted(after_reports, key=lambda p: p.stat().st_mtime)
        if not report_candidates:
            raise RuntimeError("No report JSON found after detector execution.")
        report_path = report_candidates[-1]

    if new_alerts:
        alerts_path = new_alerts[-1]
    else:
        alert_candidates = sorted(after_alerts, key=lambda p: p.stat().st_mtime)
        if not alert_candidates:
            raise RuntimeError("No alerts JSON found after detector execution.")
        alerts_path = alert_candidates[-1]

    report = json.loads(report_path.read_text(encoding="utf-8"))
    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
    if not isinstance(report, dict):
        raise RuntimeError("Detector report JSON format is invalid.")
    if not isinstance(alerts, list):
        raise RuntimeError("Detector alerts JSON format is invalid.")
    return report, alerts


def compute_overall_severity(report: Dict[str, Any], alerts: List[Dict[str, Any]]) -> str:
    summary = report.get("alert_summary", {})
    if isinstance(summary, dict):
        if int(summary.get("high", 0) or 0) > 0:
            return "high"
        if int(summary.get("medium", 0) or 0) > 0:
            return "medium"
        if int(summary.get("low", 0) or 0) > 0:
            return "low"

    severities = {str(a.get("severity", "")).strip().lower() for a in alerts if isinstance(a, dict)}
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    if "low" in severities:
        return "low"
    return "none"


def encode_result_payload(payload: Dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    size = len(encoded.encode("utf-8"))
    if size <= MAX_MEDIUMTEXT_BYTES:
        return encoded

    reduced_payload = {
        "collector": payload.get("collector"),
        "script_version": payload.get("script_version"),
        "generated_at": payload.get("generated_at"),
        "computer_name": payload.get("computer_name"),
        "mac_addresses": payload.get("mac_addresses"),
        "severity": payload.get("severity"),
        "alert_summary": payload.get("alert_summary"),
        "alerts": payload.get("alerts"),
        "inventory_counts": payload.get("inventory_counts"),
        "note": (
            "Full report omitted because result exceeded MySQL MEDIUMTEXT size. "
            "Only summary and alerts are stored."
        ),
    }
    reduced_encoded = json.dumps(reduced_payload, ensure_ascii=False, separators=(",", ":"))
    reduced_size = len(reduced_encoded.encode("utf-8"))
    if reduced_size > MAX_MEDIUMTEXT_BYTES:
        trimmed = dict(reduced_payload)
        trimmed["alerts"] = (trimmed.get("alerts") or [])[:200]
        trimmed["note"] = (
            "Stored reduced summary with first 200 alerts because result exceeded MEDIUMTEXT."
        )
        return json.dumps(trimmed, ensure_ascii=False, separators=(",", ":"))
    return reduced_encoded


def insert_soft_inv_row(
    cfg: Dict[str, Any],
    collection_ts: dt.datetime,
    computer_name: str,
    severity: str,
    mac_address: str,
    result_text: str,
) -> int:
    query = (
        f"INSERT INTO `{cfg['db_table']}` "
        "(`timestamp`, `computer_name`, `severity`, `mac_address`, `result`) "
        "VALUES (%s, %s, %s, %s, %s)"
    )

    with SSHTunnelForwarder(
        (cfg["ssh_host"], cfg["ssh_port"]),
        ssh_username=cfg["ssh_user"],
        ssh_password=cfg["ssh_password"],
        remote_bind_address=(REMOTE_DB_HOST, REMOTE_DB_PORT),
        local_bind_address=("127.0.0.1", 0),
    ) as tunnel:
        conn = pymysql.connect(
            host="127.0.0.1",
            port=tunnel.local_bind_port,
            user=cfg["db_user"],
            password=cfg["db_password"],
            database=cfg["db_name"],
            charset="utf8mb4",
            autocommit=False,
        )
        try:
            with conn.cursor() as cur:
                cur.execute(
                    query,
                    (
                        collection_ts.strftime("%Y-%m-%d %H:%M:%S"),
                        computer_name,
                        severity,
                        mac_address,
                        result_text,
                    ),
                )
                row_id = cur.lastrowid
            conn.commit()
            return int(row_id)
        finally:
            conn.close()


def parse_args() -> argparse.Namespace:
    if getattr(sys, "frozen", False):
        default_base = Path(sys.executable).resolve().parent
        bundled_base = Path(getattr(sys, "_MEIPASS", default_base))
    else:
        default_base = Path(__file__).resolve().parent
        bundled_base = default_base

    detector_candidates = [
        bundled_base / "crack_inventory_detector.ps1",
        default_base / "crack_inventory_detector.ps1",
    ]
    detector_default = next((p for p in detector_candidates if p.exists()), detector_candidates[0])

    parser = argparse.ArgumentParser(
        description="Run crack detector and upload result to dsg_it.soft_inv"
    )
    parser.add_argument(
        "--detector-script",
        type=Path,
        default=detector_default,
        help="Path to crack_inventory_detector.ps1",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=default_base / "logs",
        help="Where detector JSON files are written",
    )
    parser.add_argument("--include-appx-packages", action="store_true")
    parser.add_argument("--pretty-json", action="store_true")
    parser.add_argument("--event-lookback-hours", type=int, default=24)
    parser.add_argument("--max-events-per-log", type=int, default=200)
    parser.add_argument("--max-process-hashes", type=int, default=150)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cfg = load_config()

    require_non_empty(cfg["ssh_host"], "CRACK_SSH_HOST")
    require_non_empty(cfg["ssh_user"], "CRACK_SSH_USER")
    require_non_empty(cfg["ssh_password"], "CRACK_SSH_PASSWORD/HARDCODED_SSH_PASSWORD")
    require_non_empty(cfg["db_user"], "CRACK_DB_USER")
    require_non_empty(cfg["db_password"], "CRACK_DB_PASSWORD/HARDCODED_DB_PASSWORD")
    require_non_empty(cfg["db_name"], "CRACK_DB_NAME")
    require_non_empty(cfg["db_table"], "CRACK_DB_TABLE")

    report, alerts = run_detector(
        detector_script=args.detector_script,
        output_dir=args.output_dir,
        include_appx=args.include_appx_packages,
        pretty_json=args.pretty_json,
        event_lookback_hours=args.event_lookback_hours,
        max_events_per_log=args.max_events_per_log,
        max_process_hashes=args.max_process_hashes,
    )

    collection_ts = dt.datetime.now()
    computer_name = (
        str(report.get("report_metadata", {}).get("hostname", "")).strip()
        or os.environ.get("COMPUTERNAME", "").strip()
        or platform.node().strip()
        or "unknown"
    )
    mac_addresses = get_mac_addresses()
    mac_value = ", ".join(mac_addresses) if mac_addresses else "unknown"
    severity = compute_overall_severity(report, alerts)

    result_payload = {
        "collector": "crack_inventory_to_db.py",
        "script_version": SCRIPT_VERSION,
        "generated_at": collection_ts.strftime("%Y-%m-%d %H:%M:%S"),
        "computer_name": computer_name,
        "mac_addresses": mac_addresses,
        "severity": severity,
        "alert_summary": report.get("alert_summary", {}),
        "inventory_counts": report.get("inventory_counts", {}),
        "alerts": alerts,
        "report": report,
    }
    result_text = encode_result_payload(result_payload)

    row_id = insert_soft_inv_row(
        cfg=cfg,
        collection_ts=collection_ts,
        computer_name=computer_name,
        severity=severity,
        mac_address=mac_value,
        result_text=result_text,
    )

    print(f"[OK] Inserted into {cfg['db_name']}.{cfg['db_table']} with id={row_id}")
    print(f"timestamp={collection_ts.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"computer_name={computer_name}")
    print(f"severity={severity}")
    print(f"mac_address={mac_value}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"[ERROR] {exc}")
        raise SystemExit(1)
