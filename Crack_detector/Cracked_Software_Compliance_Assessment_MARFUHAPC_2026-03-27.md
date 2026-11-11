# Cracked Software / Compliance Assessment Report

**Target device:** MARFUHAPC
**Collected user:** MARFUHA
**Domain:** MARFUHAPC
**OS:** Microsoft Windows 11 Home (10.0.26200)
**Generated (UTC):** 03/27/2026 01:50:47
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
| Installed software entries | 38 |
| AppX packages | 0 |
| Running processes | 239 |
| Startup items | 15 |
| Scheduled tasks | 297 |
| Relevant event logs | 28 |
| Alert rules triggered | 21 |

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
| 2026-03-26 | Google Chrome | 146.0.7680.165 | Google LLC |
| 2026-03-26 | Lenovo Now | 4.6.0.44 | Lenovo |
| 2026-03-25 | Microsoft Edge WebView2 Runtime | 146.0.3856.78 | Microsoft Corporation |
| 2026-03-24 | Microsoft Edge | 146.0.3856.72 | Microsoft Corporation |
| 2026-03-19 | Lenovo Vantage Service | 4.2601.21.0 | Lenovo Group Ltd. |
| 2026-03-12 | Adobe Acrobat (64-bit) | 25.001.21288 | Adobe |
| 2026-03-10 | Malwarebytes version 5.5.1.240 | 5.5.1.240 | Malwarebytes |
| 2026-02-13 | Adobe Refresh Manager | 1.8.0 | Adobe Systems Incorporated |
| 2024-09-03 | Microsoft Teams Meeting Add-in for Microsoft Office | 1.24.14501 | Microsoft |
| 2023-11-03 | Microsoft Update Health Tools | 5.72.0.0 | Microsoft Corporation |
| 2023-03-15 | Cisco AnyConnect Secure Mobility Client | 4.10.05085 | Cisco Systems, Inc. |
| 2023-03-11 | Lenovo Voice Service | 3.0.26.0 | Lenovo Group Ltd. |
| 2022-11-15 | Asian Language And Spelling Dictionaries Support For Adobe Acrobat Reader | 22.001.20085 | Adobe Systems Incorporated |
| 2022-11-15 | Gmail | 1.0 | Google\Chrome |
| 2022-11-15 | Kintone | 1.0 | Google\Chrome |
| 2022-11-13 | Cisco Webex Meetings | 40.12.3.11 | Cisco Webex LLC |
| 2022-11-13 | Google Update Helper | 1.3.35.451 | Google LLC |
| 2022-11-13 | Image Resizer Powertoy Clone for Windows (64 bit) | 2.1 | Brice Lambson |
| 2022-11-13 | Microsoft PowerPoint Viewer | 14.0.4763.1000 | Microsoft Corporation |
| 2022-11-13 | paint.net | 4.3.12 | dotPDN LLC |
| 2022-11-13 | Skype version 8.58 | 8.58 | Skype Technologies S.A. |
| 2022-11-12 | LibreOffice 7.4.2.3 | 7.4.2.3 | The Document Foundation |

## Appendix B. Commercial Software Present (selected brands)

| Software | Version | Publisher | Install date |
| --- | --- | --- | --- |
| Adobe Acrobat (64-bit) | 25.001.21288 | Adobe | 20260312 |
| Adobe Refresh Manager | 1.8.0 | Adobe Systems Incorporated | 20260213 |
| Asian Language And Spelling Dictionaries Support For Adobe Acrobat Reader | 22.001.20085 | Adobe Systems Incorporated | 20221115 |
| Microsoft Teams Meeting Add-in for Microsoft Office | 1.24.14501 | Microsoft | 20240903 |
