import json, re, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)

def parse_install_date(d: Any) -> Optional[datetime.date]:
    if not d:
        return None
    s = str(d).strip()
    if re.fullmatch(r"\d{8}", s):
        try:
            return datetime.datetime.strptime(s, "%Y%m%d").date()
        except ValueError:
            return None
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%d/%m/%y"):
        try:
            return datetime.datetime.strptime(s, fmt).date()
        except ValueError:
            pass
    return None

def md_table(headers: List[str], rows: List[List[str]]) -> str:
    def esc(x: str) -> str:
        return (x or "").replace("\n", " ").replace("|", r"\|").strip()
    out = []
    out.append("| " + " | ".join(esc(h) for h in headers) + " |")
    out.append("| " + " | ".join("---" for _ in headers) + " |")
    for r in rows:
        out.append("| " + " | ".join(esc(str(c)) for c in r) + " |")
    return "\n".join(out)

def as_str(x: Any) -> str:
    return "" if x is None else str(x)

def compute_findings(inv: Dict[str, Any], alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    meta = inv.get("report_metadata", {}) or {}
    counts = inv.get("inventory_counts", {}) or {}
    installed = (inv.get("inventory", {}) or {}).get("installed_software", []) or []

    piracy_patterns = [
        r"\bcrack\b", r"\bkeygen\b", r"\bactivator\b",
        r"\bkms\b", r"kmspico", r"\bwarez\b",
        r"license\s*reset", r"trial\s*reset", r"genuine\s*bypass",
    ]
    piracy_re = re.compile("|".join(piracy_patterns), re.IGNORECASE)

    suspicious_software = []
    for s in installed:
        blob = " | ".join([
            as_str(s.get("software_name")),
            as_str(s.get("publisher")),
            as_str(s.get("install_location")),
            as_str(s.get("uninstall_string")),
            as_str(s.get("display_icon")),
        ])
        if piracy_re.search(blob):
            suspicious_software.append({
                "software_name": as_str(s.get("software_name")),
                "version": as_str(s.get("version")),
                "publisher": as_str(s.get("publisher")),
                "install_date": as_str(s.get("install_date")),
                "install_location": as_str(s.get("install_location")),
            })

    commercial_brands = ["Adobe", "Autodesk", "Microsoft Office", "SolidWorks", "MATLAB", "VMware", "JetBrains"]
    commercial_found = []
    for s in installed:
        name = as_str(s.get("software_name"))
        if any(b.lower() in name.lower() for b in commercial_brands):
            commercial_found.append({
                "software_name": name,
                "version": as_str(s.get("version")),
                "publisher": as_str(s.get("publisher")),
                "install_date": as_str(s.get("install_date")),
            })

    recent = []
    for s in installed:
        dt = parse_install_date(s.get("install_date"))
        if dt:
            recent.append((dt, s))
    recent.sort(key=lambda x: x[0], reverse=True)
    recent_top = []
    for dt, s in recent[:25]:
        recent_top.append({
            "install_date": str(dt),
            "software_name": as_str(s.get("software_name")),
            "version": as_str(s.get("version")),
            "publisher": as_str(s.get("publisher")),
        })

    risk = "Low"
    risk_notes: List[str] = []

    if any((a.get("severity") or "").lower() == "high" for a in alerts):
        risk = "Moderate"
        risk_notes.append("At least one HIGH-severity alert is present (scheduled task).")

    if any("sppsvc" in (a.get("entity") or "") for a in alerts):
        risk = "Moderate"
        risk_notes.append("Windows Software Protection service (sppsvc) is stopped (can indicate activation tampering).")

    if suspicious_software:
        risk = "High"
        risk_notes.append("Keyword scan found likely cracking/activation tools in installed software list.")

    return {
        "meta": meta,
        "counts": counts,
        "alerts": alerts,
        "risk": risk,
        "risk_notes": risk_notes,
        "suspicious_software": suspicious_software,
        "commercial_found": commercial_found,
        "recent_top": recent_top,
    }

def build_markdown_report(data: Dict[str, Any]) -> str:
    meta = data["meta"]
    counts = data["counts"]
    alerts = data["alerts"]
    risk = data["risk"]
    risk_notes = data["risk_notes"]
    suspicious_software = data["suspicious_software"]
    commercial_found = data["commercial_found"]
    recent_top = data["recent_top"]

    hostname = as_str(meta.get("hostname"))
    username = as_str(meta.get("username"))
    os_caption = as_str(meta.get("os_caption"))
    os_version = as_str(meta.get("os_version"))
    generated_utc = as_str(meta.get("generated_utc"))
    script_version = as_str(meta.get("script_version"))
    userdomain = as_str(meta.get("userdomain"))

    lines: List[str] = []
    lines.append("# Cracked Software / Compliance Assessment Report\n")
    lines.append(f"**Target device:** {hostname}")
    lines.append(f"**Collected user:** {username}")
    lines.append(f"**Domain:** {userdomain}")
    lines.append(f"**OS:** {os_caption} ({os_version})")
    lines.append(f"**Generated (UTC):** {generated_utc}")
    if script_version:
        lines.append(f"**Script version:** {script_version}")
    lines.append("")

    lines.append("## Executive Summary\n")
    lines.append(f"**Overall risk rating:** **{risk}**\n")
    lines.append("This report reviews software inventory, system state indicators, and alert rules to highlight evidence that may indicate unlicensed or cracked software usage.")
    lines.append("Findings are **indicators** and should be validated with licensing documentation and deeper checks before taking action.\n")
    if risk_notes:
        lines.append("**Key drivers:**")
        for n in risk_notes:
            lines.append(f"- {n}")
        lines.append("")

    lines.append("## 1. Inventory Summary\n")
    inv_rows = [
        ["Installed software entries", as_str(counts.get("installed_software"))],
        ["AppX packages", as_str(counts.get("appx_packages"))],
        ["Running processes", as_str(counts.get("running_processes"))],
        ["Startup items", as_str(counts.get("startup_items"))],
        ["Scheduled tasks", as_str(counts.get("scheduled_tasks"))],
        ["Relevant event logs", as_str(counts.get("event_logs_relevant"))],
        ["Alert rules triggered", as_str(counts.get("alerts"))],
    ]
    lines.append(md_table(["Metric", "Count"], inv_rows) + "\n")

    lines.append("## 2. Alerts & Indicators\n")
    if alerts:
        alert_rows = []
        for a in alerts:
            alert_rows.append([
                as_str(a.get("severity")),
                as_str(a.get("rule_id")),
                as_str(a.get("title")),
                as_str(a.get("entity")),
                as_str(a.get("recommendation")),
            ])
        lines.append(md_table(["Severity", "Rule", "Title", "Entity", "Recommendation"], alert_rows))
    else:
        lines.append("_No alert rules were triggered by this run._")
    lines.append("")

    lines.append("## 3. Potential Indicators of Cracked / Unlicensed Software\n")
    lines.append("- **Windows licensing service stopped (sppsvc):** may indicate activation tampering or misconfiguration (validate).")
    lines.append("- **Suspicious scheduled tasks:** tasks can be used to run loaders/activators or persist malware; confirm actions and file signatures.")
    lines.append("- **Defender configuration change events (e.g., Event ID 5007):** confirm changes align with authorized baselines/policies.\n")

    if suspicious_software:
        lines.append(f"### Keyword-flagged installed software ({len(suspicious_software)})")
        rows = [[s["software_name"], s["version"], s["publisher"], s["install_date"]] for s in suspicious_software]
        lines.append(md_table(["Software", "Version", "Publisher", "Install date"], rows))
        lines.append("")
    else:
        lines.append("### Keyword-flagged installed software")
        lines.append("_None detected in installed-software name/publisher/path fields captured by this run._\n")

    lines.append("## 4. Recommended Follow-Up Checks\n")
    lines.append("- Inspect the scheduled task **Calibration Loader**: identify the Action path/arguments, hash the referenced file, and verify digital signature.")
    lines.append("- Re-enable and verify the **Software Protection service (sppsvc)**, then run Windows activation diagnostics (e.g., `slmgr /dlv`) and confirm licensing compliance.")
    lines.append("- Review Defender change events to confirm they were authorized (baseline/policy).")
    lines.append("- Validate licenses for commercial software (e.g., Adobe products) against purchase records / assigned seats.")
    lines.append("- Run a full malware scan (Defender Offline Scan or EDR) and review for known activator artifacts (Task Scheduler/Startup/Temp/ProgramData).\n")

    lines.append("## Appendix A. Recent Installed Software (Top 25 by install date)\n")
    if recent_top:
        rows = [[r["install_date"], r["software_name"], r["version"], r["publisher"]] for r in recent_top]
        lines.append(md_table(["Install date", "Software", "Version", "Publisher"], rows))
    else:
        lines.append("_No parseable install dates were found in the inventory._")
    lines.append("")

    lines.append("## Appendix B. Commercial Software Present (selected brands)\n")
    if commercial_found:
        rows = [[c["software_name"], c["version"], c["publisher"], c["install_date"]] for c in commercial_found[:60]]
        lines.append(md_table(["Software", "Version", "Publisher", "Install date"], rows))
        if len(commercial_found) > 60:
            lines.append(f"\n_Showing first 60 of {len(commercial_found)} matches._")
    else:
        lines.append("_No matches found for the selected brand list._")
    lines.append("")
    return "\n".join(lines)

def main(inventory_json: str, alerts_json: str, out_md: str) -> None:
    inv = load_json(Path(inventory_json))
    alerts = load_json(Path(alerts_json))
    data = compute_findings(inv, alerts)
    md = build_markdown_report(data)
    Path(out_md).write_text(md, encoding="utf-8")
    print("Wrote:", out_md)

if __name__ == "__main__":
    import argparse
    from pathlib import Path
    import datetime

    p = argparse.ArgumentParser()
    p.add_argument("--inventory", required=True, help="Path to crack_inventory_report_*.json")
    p.add_argument("--alerts", required=True, help="Path to crack_inventory_alerts_*.json")
    p.add_argument("--out", default="", help="Output .md path (optional)")
    args = p.parse_args()

    inv = load_json(Path(args.inventory))
    alerts = load_json(Path(args.alerts))

    data = compute_findings(inv, alerts)
    md = build_markdown_report(data)

    hostname = as_str((inv.get("report_metadata", {}) or {}).get("hostname")) or "UNKNOWN_HOST"
    date_str = datetime.date.today().isoformat()
    out_path = Path(args.out) if args.out else Path(f"Cracked_Software_Compliance_Assessment_{hostname}_{date_str}.md")

    out_path.write_text(md, encoding="utf-8")
    print(f"Wrote: {out_path.resolve()}")

