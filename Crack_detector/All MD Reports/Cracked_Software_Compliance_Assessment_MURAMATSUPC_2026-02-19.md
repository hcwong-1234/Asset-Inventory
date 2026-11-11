# Cracked Software / Compliance Assessment Report

**Target device:** MURAMATSUPC
**Collected user:** Daikai
**Domain:** MURAMATSUPC
**OS:** Microsoft Windows 11 Home (10.0.26100)
**Generated (UTC):** 02/16/2026 08:39:28
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
| Installed software entries | 49 |
| AppX packages | 0 |
| Running processes | 264 |
| Startup items | 16 |
| Scheduled tasks | 286 |
| Relevant event logs | 41 |
| Alert rules triggered | 17 |

## 2. Alerts & Indicators

| Severity | Rule | Title | Entity | Recommendation |
| --- | --- | --- | --- | --- |
| high | TK-001 | Suspicious scheduled task | Calibration Loader | Disable task and inspect referenced executable/script. |
| medium | LS-001 | Windows licensing service stopped | sppsvc | Confirm this is expected; unexpected stoppage may indicate tampering. |
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
| 2026-02-16 | Microsoft Edge | 145.0.3800.58 | Microsoft Corporation |
| 2026-02-16 | MySQL Server 8.4 | 8.4.8 | Oracle Corporation |
| 2026-02-16 | Office 16 Click-to-Run Extensibility Component | 16.0.19628.20204 | Microsoft Corporation |
| 2026-02-13 | Adobe Refresh Manager | 1.8.0 | Adobe Systems Incorporated |
| 2026-02-12 | Google Chrome | 144.0.7559.133 | Google LLC |
| 2026-02-11 | Malwarebytes version 5.4.7.229 | 5.4.7.229 | Malwarebytes |
| 2026-02-10 | Adobe Acrobat (64-bit) | 25.001.21184 | Adobe |
| 2026-02-10 | Microsoft Edge WebView2 Runtime | 144.0.3719.115 | Microsoft Corporation |
| 2026-01-31 | Lenovo Vantage Service | 4.2601.20.0 | Lenovo Group Ltd. |
| 2026-01-31 | Microsoft Visual C++ 2022 X64 Additional Runtime - 14.44.35211 | 14.44.35211 | Microsoft Corporation |
| 2026-01-31 | Microsoft Visual C++ 2022 X64 Minimum Runtime - 14.44.35211 | 14.44.35211 | Microsoft Corporation |
| 2026-01-31 | Microsoft Visual C++ 2022 X86 Additional Runtime - 14.44.35211 | 14.44.35211 | Microsoft Corporation |
| 2026-01-31 | Microsoft Visual C++ 2022 X86 Minimum Runtime - 14.44.35211 | 14.44.35211 | Microsoft Corporation |
| 2026-01-31 | Office 16 Click-to-Run Localization Component | 16.0.19628.20150 | Microsoft Corporation |
| 2026-01-13 | Lenovo Now | 4.5.0.24 | Lenovo |
| 2025-08-28 | VIAApp | 2.2.0617.894 | KRAMER |
| 2025-08-25 | Office 16 Click-to-Run Licensing Component | 16.0.19029.20208 | Microsoft Corporation |
| 2024-08-14 | Microsoft Teams Meeting Add-in for Microsoft Office | 1.24.19202 | Microsoft |
| 2024-03-08 | Cisco AnyConnect Secure Mobility Client | 4.10.05085 | Cisco Systems, Inc. |
| 2024-02-27 | Asian Language And Spelling Dictionaries Support For Adobe Acrobat Reader | 23.008.20421 | Adobe Systems Incorporated |
| 2024-02-27 | Google Update Helper | 1.3.35.451 | Google LLC |
| 2024-02-27 | Image Resizer Powertoy Clone for Windows (64 bit) | 2.1 | Brice Lambson |
| 2024-02-27 | LibreOffice 7.6.2.1 | 7.6.2.1 | The Document Foundation |
| 2024-02-27 | Microsoft Update Health Tools | 5.72.0.0 | Microsoft Corporation |
| 2024-02-27 | paint.net | 5.0.12 | dotPDN LLC |

## Appendix B. Commercial Software Present (selected brands)

| Software | Version | Publisher | Install date |
| --- | --- | --- | --- |
| Adobe Acrobat (64-bit) | 25.001.21184 | Adobe | 20260210 |
| Adobe Refresh Manager | 1.8.0 | Adobe Systems Incorporated | 20260213 |
| Asian Language And Spelling Dictionaries Support For Adobe Acrobat Reader | 23.008.20421 | Adobe Systems Incorporated | 20240227 |
| Microsoft Office Home and Business 2019 - en-us | 16.0.19628.20204 | Microsoft Corporation |  |
| Microsoft Office Home and Business 2019 - ja-jp | 16.0.19628.20204 | Microsoft Corporation |  |
| Microsoft Teams Meeting Add-in for Microsoft Office | 1.24.19202 | Microsoft | 20240814 |
