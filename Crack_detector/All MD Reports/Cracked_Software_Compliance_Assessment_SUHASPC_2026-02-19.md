# Cracked Software / Compliance Assessment Report

**Target device:** SUHASPC
**Collected user:** Daikai
**Domain:** SUHASPC
**OS:** Microsoft Windows 11 Home (10.0.26200)
**Generated (UTC):** 02/19/2026 08:23:18
**Script version:** 0.1.0

## Executive Summary

**Overall risk rating:** **Moderate**

This report reviews software inventory, system state indicators, and alert rules to highlight evidence that may indicate unlicensed or cracked software usage.
Findings are **indicators** and should be validated with licensing documentation and deeper checks before taking action.

**Key drivers:**
- At least one HIGH-severity alert is present (scheduled task).

## 1. Inventory Summary

| Metric | Count |
| --- | --- |
| Installed software entries | 88 |
| AppX packages | 0 |
| Running processes | 302 |
| Startup items | 25 |
| Scheduled tasks | 291 |
| Relevant event logs | 26 |
| Alert rules triggered | 27 |

## 2. Alerts & Indicators

| Severity | Rule | Title | Entity | Recommendation |
| --- | --- | --- | --- | --- |
| high | PR-001 | Suspicious process indicator | Notepad.exe | Terminate the process only after collecting forensic evidence. |
| high | PR-001 | Suspicious process indicator | Notepad.exe | Terminate the process only after collecting forensic evidence. |
| high | TK-001 | Suspicious scheduled task | Calibration Loader | Disable task and inspect referenced executable/script. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
| medium | EV-003 | Defender settings changed | Defender:5007 | Validate if policy change was authorized. |
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
| 2026-02-19 | Adobe Acrobat (64-bit) | 25.001.21223 | Adobe |
| 2026-02-16 | Microsoft Edge | 145.0.3800.58 | Microsoft Corporation |
| 2026-02-13 | Adobe Refresh Manager | 1.8.0 | Adobe Systems Incorporated |
| 2026-02-13 | Google Chrome | 144.0.7559.134 | Google LLC |
| 2026-02-13 | Malwarebytes version 5.4.7.229 | 5.4.7.229 | Malwarebytes |
| 2026-02-13 | Microsoft Edge WebView2 Runtime | 144.0.3719.115 | Microsoft Corporation |
| 2026-01-30 | Lenovo Vantage Service | 4.2601.20.0 | Lenovo Group Ltd. |
| 2025-11-20 | Cisco AnyConnect Secure Mobility Client | 4.10.05085 | Cisco Systems, Inc. |
| 2025-09-26 | Microsoft Visual C++ 2022 X64 Additional Runtime - 14.44.35211 | 14.44.35211 | Microsoft Corporation |
| 2025-09-26 | Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211 | 14.44.35211 | Microsoft Corporation |
| 2025-09-03 | Brother iPrint&Scan | 14.0.2.1 | Brother Industries, Ltd. |
| 2025-07-24 | HttpToUsbBridge | 2.6.121.1 | Brother Industries Ltd. |
| 2025-04-27 | AppLogLibSetup | 1.0.3.0 | Brother Industries Ltd. |
| 2025-04-27 | BrLauncher | 2.0.36.0 | Brother Industries Ltd. |
| 2025-04-27 | BrLogRx | 1.0.5.0 | Brother Industries Ltd. |
| 2025-04-27 | Brother Printer Driver | 1.2.0.0 | Brother Industries Ltd. |
| 2025-04-27 | Brother Scanner Driver | 1.0.16.1 | Brother Industries Ltd. |
| 2025-04-27 | Brother Scanner Driver | 1.1.12.1 | Brother Industries Ltd. |
| 2025-04-27 | BrSupportTools | 1.0.44.0 | Brother Industries Ltd. |
| 2025-04-27 | HowToGuide | 1.0.3.0 | Brother Industries Ltd. |
| 2025-04-27 | Kofax PaperPort 14 | 14.7.1000 | Kofax Inc. |
| 2025-04-27 | Kofax PDF Viewer SE | 7.21.3266 | Kofax Inc. |
| 2025-04-27 | Microsoft .NET Host - 8.0.12 (x64) | 64.48.26165 | Microsoft Corporation |
| 2025-04-27 | Microsoft .NET Host - 8.0.12 (x86) | 64.48.26165 | Microsoft Corporation |
| 2025-04-27 | Microsoft .NET Host FX Resolver - 8.0.12 (x64) | 64.48.26165 | Microsoft Corporation |

## Appendix B. Commercial Software Present (selected brands)

| Software | Version | Publisher | Install date |
| --- | --- | --- | --- |
| Adobe Acrobat (64-bit) | 25.001.21223 | Adobe | 20260219 |
| Adobe Refresh Manager | 1.8.0 | Adobe Systems Incorporated | 20260213 |
| Asian Language And Spelling Dictionaries Support For Adobe Acrobat Reader | 22.001.20085 | Adobe Systems Incorporated | 20230922 |
| Microsoft Teams Meeting Add-in for Microsoft Office | 1.24.19202 | Microsoft | 20240916 |
