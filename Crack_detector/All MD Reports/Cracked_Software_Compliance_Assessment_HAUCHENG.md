# Cracked Software / Compliance Assessment Report

**Target device:** HAUCHENG
**Collected user:** HauCheng_PC
**Domain:** HAUCHENG
**OS:** Microsoft Windows 11 Home (10.0.26100)
**Generated (UTC):** 02/12/2026 02:08:31
**Script version:** 0.1.0

## Executive Summary

**Overall risk rating:** **Moderate**

This report reviews software inventory, system state indicators, and alert rules to highlight evidence that may indicate unlicensed or cracked software usage.
Findings are **indicators** and should be validated with licensing documentation and deeper checks before taking action.

**Key drivers:**
- At least one HIGH-severity alert is present (scheduled task).
- Windows Software Protection service (sppsvc) is stopped (can indicate activation tampering).

## 1. Inventory Summary

| Metric | Count |
| --- | --- |
| Installed software entries | 413 |
| AppX packages | 151 |
| Running processes | 287 |
| Startup items | 12 |
| Scheduled tasks | 265 |
| Relevant event logs | 31 |
| Alert rules triggered | 5 |

## 2. Alerts & Indicators

| Severity | Rule | Title | Entity | Recommendation |
| --- | --- | --- | --- | --- |
| high | TK-001 | Suspicious scheduled task | Calibration Loader | Disable task and inspect referenced executable/script. |
| medium | LS-001 | Windows licensing service stopped | sppsvc | Confirm this is expected; unexpected stoppage may indicate tampering. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |

## 3. Potential Indicators of Cracked / Unlicensed Software

- **Windows licensing service stopped (sppsvc):** may indicate activation tampering or misconfiguration (validate).
- **Suspicious scheduled tasks:** tasks can be used to run loaders/activators or persist malware; confirm actions and file signatures.
- **Defender configuration change events (e.g., Event ID 5007):** confirm changes align with authorized baselines/policies.

### Keyword-flagged installed software
_None detected in installed-software name/publisher/path fields captured by this run._

## 4. Recommended Follow-Up Checks

- Inspect the scheduled task **Calibration Loader**: identify the Action path/arguments, hash the referenced file, and verify digital signature.
- Re-enable and verify the **Software Protection service (sppsvc)**, then run Windows activation diagnostics (e.g., `slmgr /dlv`) and confirm licensing compliance.
- Review Defender change events to confirm they were authorized (baseline/policy).
- Validate licenses for commercial software (e.g., Adobe products) against purchase records / assigned seats.
- Run a full malware scan (Defender Offline Scan or EDR) and review for known activator artifacts (Task Scheduler/Startup/Temp/ProgramData).

## Appendix A. Recent Installed Software (Top 25 by install date)

| Install date | Software | Version | Publisher |
| --- | --- | --- | --- |
| 2026-02-11 | Google Chrome | 145.0.7632.45 | Google LLC |
| 2026-02-11 | Microsoft Visual Studio Code (User) | 1.109.2 | Microsoft Corporation |
| 2026-02-09 | Adobe Acrobat (64-bit) | 25.001.21184 | Adobe |
| 2026-02-09 | Microsoft Edge | 144.0.3719.115 | Microsoft Corporation |
| 2026-02-09 | Microsoft Edge WebView2 Runtime | 144.0.3719.115 | Microsoft Corporation |
| 2026-02-06 | Malwarebytes version 5.4.7.229 | 5.4.7.229 | Malwarebytes |
| 2026-02-04 | GrafanaEnterprise | 12.3.2.0 | Grafana Labs |
| 2026-01-21 | Office 16 Click-to-Run Extensibility Component | 16.0.19426.20170 | Microsoft Corporation |
| 2025-12-08 | Antigravity (User) | 1.11.14 | Google |
| 2025-12-05 | MySQL Server 8.4 | 8.4.6 | Oracle Corporation |
| 2025-11-13 | Advanced IP Scanner 2.5.1 | 2.5.4594.1 | Famatech |
| 2025-10-27 | Git | 2.51.1 | The Git Development Community |
| 2025-09-22 | Application Verifier x64 External Package | 10.1.19041.5609 | Microsoft |
| 2025-09-22 | Kits Configuration Installer | 10.1.19041.5609 | Microsoft |
| 2025-09-22 | Microsoft .NET Framework 4 Multi-Targeting Pack | 4.0.30319 | Microsoft Corporation |
| 2025-09-22 | MSI Development Tools | 10.1.19041.5609 | Microsoft Corporation |
| 2025-09-22 | Node.js | 22.19.0 | Node.js Foundation |
| 2025-09-22 | Python 3.13.7 Add to Path (64-bit) | 3.13.7150.0 | Python Software Foundation |
| 2025-09-22 | Python 3.13.7 Core Interpreter (64-bit) | 3.13.7150.0 | Python Software Foundation |
| 2025-09-22 | Python 3.13.7 Development Libraries (64-bit) | 3.13.7150.0 | Python Software Foundation |
| 2025-09-22 | Python 3.13.7 Documentation (64-bit) | 3.13.7150.0 | Python Software Foundation |
| 2025-09-22 | Python 3.13.7 Executables (64-bit) | 3.13.7150.0 | Python Software Foundation |
| 2025-09-22 | Python 3.13.7 pip Bootstrap (64-bit) | 3.13.7150.0 | Python Software Foundation |
| 2025-09-22 | Python 3.13.7 Standard Library (64-bit) | 3.13.7150.0 | Python Software Foundation |
| 2025-09-22 | Python 3.13.7 Tcl/Tk Support (64-bit) | 3.13.7150.0 | Python Software Foundation |

## Appendix B. Commercial Software Present (selected brands)

| Software | Version | Publisher | Install date |
| --- | --- | --- | --- |
| Adobe Acrobat (64-bit) | 25.001.21184 | Adobe | 20260209 |
| Adobe Genuine Service | 9.1.0.52 | Adobe Inc. |  |
| Adobe Refresh Manager | 1.8.0 | Adobe Systems Incorporated | 20250908 |
| Open XML SDK 2.5 for Microsoft Office | 2.5.5631 | Microsoft Corporation | 20250825 |
