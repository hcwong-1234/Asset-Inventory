# Windows 11 Crack Software Inventory Detector (MVP)

This project provides a PowerShell-based endpoint inventory and suspicious software detector for Windows 11.

## What it collects

- Installed software from registry uninstall keys
- Optional AppX/UWP packages
- Running processes, command lines, parent process, file hash (SHA256), signature status
- Startup persistence (Run/RunOnce keys + Startup folders)
- Scheduled tasks and task actions
- Relevant Windows Event Logs (lookback window + max per log):
  - `System`: service/install lifecycle signals
  - `Security`: process creation, service install, log clear events
  - `Application`: MSI/software install and uninstall events
  - `Microsoft-Windows-Windows Defender/Operational`: malware and config-change events
- Security signals:
  - suspicious `hosts` file entries
  - key service states (`sppsvc`, `osppsvc`, `WinDefend`)
  - Microsoft Defender status (if available)

## Detection rules (MVP)

- Name/path/command indicators for common crack tooling terms:
  - `kms`, `kmspico`, `autokms`, `keygen`, `crack`, `activator`, `patcher`, `loader`, `microsoft toolkit`, `vlmcsd`
- Suspicious startup items and scheduled tasks
- Suspicious hosts-file mappings tied to activation/licensing domains
- Windows licensing service stopped unexpectedly
- Defender service not running
- Executables with problematic signature states

## Run

Open PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\crack_inventory_detector.ps1 -OutputDir .\logs -IncludeAppxPackages -PrettyJson
```

Minimal run:

```powershell
.\crack_inventory_detector.ps1
```

Custom log window (last 72 hours, max 400 events/log):

```powershell
.\crack_inventory_detector.ps1 -EventLookbackHours 72 -MaxEventsPerLog 400 -OutputDir .\logs
```

## Output

The script writes two JSON files per run into `OutputDir`:

- `crack_inventory_report_<PCNAME>_YYYYMMDD_HHMMSS.json` (full inventory + alerts)
- `crack_inventory_alerts_<PCNAME>_YYYYMMDD_HHMMSS.json` (alerts only)

Main fields include:

- `report_metadata`: host/user/time/OS info
- `inventory_counts`: counts by category
- `inventory.installed_software[*]`: software name, version, publisher, install location
- `inventory.running_processes[*]`: process, command line, executable path, hash, signature, signer
- `inventory.event_logs_relevant[*]`: time, event ID, provider, level, user SID, event message
- `alerts[*]`: `rule_id`, `severity`, `title`, `source`, `entity`, `evidence`, `recommendation`

## Schedule every hour (example)

```powershell
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\Path\To\crack_inventory_detector.ps1 -OutputDir C:\Path\To\logs -IncludeAppxPackages"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).Date -RepetitionInterval (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName "CrackInventoryDetector" -Action $action -Trigger $trigger -RunLevel Highest -Description "Windows software inventory and crack indicator detection"
```

## Notes

- This is for defensive compliance/inventory use.
- Current detection is indicator-based and can produce false positives.
- Tune regex patterns and add allowlists before production rollout.
