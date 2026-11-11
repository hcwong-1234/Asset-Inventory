<#
    crack_inventory_detector_and_upload_api.ps1

    - Collects software / security inventory from Windows laptop
    - Detects suspicious cracked-software indicators
    - Saves local JSON report + alerts files
    - Uploads one row to dsg_it.soft_inv through the HTTPS API
    - No SSH tunnel and no direct MySQL client required
#>

param(
    [string]$ApiUrl = "",
    [string]$Username = "",
    [string]$Password = "",
    [string]$OutputDir = ".\logs",
    [switch]$IncludeAppxPackages,
    [int]$MaxProcessHashes = 150,
    [int]$EventLookbackHours = 24,
    [int]$MaxEventsPerLog = 200,
    [switch]$PrettyJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#############################
# BUILT-IN API SETTINGS
#############################
# Edit these three values if the server URL or login changes.
$DefaultApiUrl = "https://itinv.3utilities.com/api.php"
$DefaultUsername = "haucheng44444"
$DefaultPassword = "ia5lnbvo8j"

#############################
# CONFIGURATION
#############################

$ScriptVersion = "0.3.0"
$NowUtc = (Get-Date).ToUniversalTime()
$CurrentProcessId = $PID
$ComputerNameValue = [string]$env:COMPUTERNAME
if ([string]::IsNullOrWhiteSpace($ComputerNameValue)) {
    $ComputerNameValue = [string][System.Environment]::MachineName
}
if ([string]::IsNullOrWhiteSpace($ComputerNameValue)) {
    $ComputerNameValue = "unknown-host"
}

# Paths based on where this script lives
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Local output folder
if ([System.IO.Path]::IsPathRooted($OutputDir)) {
    $ResolvedOutputDir = $OutputDir
} else {
    $ResolvedOutputDir = Join-Path $ScriptDir $OutputDir
}

if (-not (Test-Path -LiteralPath $ResolvedOutputDir)) {
    New-Item -ItemType Directory -Path $ResolvedOutputDir -Force | Out-Null
}

#############################
# HELPER FUNCTIONS
#############################

function Resolve-ApiEndpoint {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $resolved = $Value.Trim()
    if ([string]::IsNullOrWhiteSpace($resolved)) {
        throw "API URL is empty."
    }

    if ($resolved -match '^http://(?!localhost\b|127\.0\.0\.1\b)') {
        $resolved = 'https://' + $resolved.Substring(7)
    }

    $resolved = $resolved.TrimEnd('/')
    if ($resolved -notmatch '/api\.php$') {
        $resolved += '/api.php'
    }

    return $resolved
}

function ConvertTo-ApiQueryString {
    param(
        [hashtable]$Query = @{}
    )

    if ($Query.Count -eq 0) {
        return ""
    }

    return ($Query.GetEnumerator() | ForEach-Object {
        $key = [System.Uri]::EscapeDataString([string] $_.Key)
        $value = [System.Uri]::EscapeDataString([string] $_.Value)
        "$key=$value"
    }) -join "&"
}

function Read-SecretPlainText {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt
    )

    $secure = Read-Host -Prompt $Prompt -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Invoke-ApiRequest {
    param(
        [string]$Method = "GET",
        [Parameter(Mandatory = $true)]
        [string]$Action,
        [hashtable]$Query = @{},
        [object]$Body = $null,
        [string]$Token = $null
    )

    $encodedAction = [System.Uri]::EscapeDataString($Action)
    $url = $ApiBaseUrl + "?action=$encodedAction"
    $queryString = ConvertTo-ApiQueryString -Query $Query
    if ($queryString -ne "") {
        $url += "&" + $queryString
    }

    $headers = @{
        "Accept" = "application/json"
        "Content-Type" = "application/json"
    }
    if ($Token) {
        $headers["Authorization"] = "Bearer $Token"
    }

    $params = @{
        Uri = $url
        Method = $Method
        Headers = $headers
        TimeoutSec = 60
    }

    if ($null -ne $Body) {
        $params.Body = ($Body | ConvertTo-Json -Depth 10)
    }

    try {
        $response = Invoke-RestMethod @params
        if ($null -ne $response.ok -and $response.ok -eq $false) {
            throw "API Error: $($response.error.message)"
        }
        return $response
    } catch {
        $serverMessage = $null
        $responseStream = $null

        try {
            if ($null -ne $_.Exception.Response) {
                $responseStream = $_.Exception.Response.GetResponseStream()
                if ($null -ne $responseStream) {
                    $reader = New-Object System.IO.StreamReader($responseStream)
                    try {
                        $rawErrorBody = $reader.ReadToEnd()
                        if (-not [string]::IsNullOrWhiteSpace($rawErrorBody)) {
                            try {
                                $decodedError = $rawErrorBody | ConvertFrom-Json -ErrorAction Stop
                                if ($null -ne $decodedError.error.message) {
                                    $serverMessage = [string]$decodedError.error.message
                                } else {
                                    $serverMessage = $rawErrorBody
                                }
                            } catch {
                                $serverMessage = $rawErrorBody
                            }
                        }
                    } finally {
                        $reader.Dispose()
                    }
                }
            }
        } catch {
            $serverMessage = $null
        } finally {
            if ($null -ne $responseStream) {
                $responseStream.Dispose()
            }
        }

        Write-Host "[ERROR] API request failed: $($_.Exception.Message)" -ForegroundColor Red
        if (-not [string]::IsNullOrWhiteSpace($serverMessage)) {
            Write-Host "[ERROR] API response body: $serverMessage" -ForegroundColor Yellow
        }
        Write-Host "[ERROR] Endpoint: $url" -ForegroundColor DarkRed
        exit 1
    }
}

function Get-HashSafe {
    param([string]$Path)
    try {
        if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return $null }
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch {
        return $null
    }
}

function Get-SignatureSafe {
    param([string]$Path)
    try {
        if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
            return [pscustomobject]@{
                status = "NotFound"
                signer = $null
            }
        }

        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $signer = $null
        if ($sig.SignerCertificate) {
            $signer = $sig.SignerCertificate.Subject
        }

        return [pscustomobject]@{
            status = [string]$sig.Status
            signer = $signer
        }
    } catch {
        return [pscustomobject]@{
            status = "Error"
            signer = $null
        }
    }
}

function Get-InstalledSoftware {
    $paths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $rows = New-Object System.Collections.Generic.List[object]

    foreach ($path in $paths) {
        try {
            $items = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                if ([string]::IsNullOrWhiteSpace($item.DisplayName)) { continue }
                $rows.Add([pscustomobject]@{
                    software_name = [string]$item.DisplayName
                    version = [string]$item.DisplayVersion
                    publisher = [string]$item.Publisher
                    install_date = [string]$item.InstallDate
                    install_location = [string]$item.InstallLocation
                    uninstall_string = [string]$item.UninstallString
                    display_icon = [string]$item.DisplayIcon
                    registry_key = [string]$item.PSPath
                })
            }
        } catch {
            continue
        }
    }

    return $rows | Sort-Object software_name, version, publisher -Unique
}

function Get-AppxPackagesInventory {
    try {
        $pkgs = Get-AppxPackage -ErrorAction Stop
        return $pkgs | ForEach-Object {
            [pscustomobject]@{
                software_name = $_.Name
                version = [string]$_.Version
                publisher = [string]$_.Publisher
                install_location = [string]$_.InstallLocation
                package_full_name = [string]$_.PackageFullName
                is_framework = [bool]$_.IsFramework
            }
        }
    } catch {
        return @()
    }
}

function Get-ProcessInventory {
    param([int]$HashBudget)

    $procs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
    if (-not $procs) { return @() }

    $procByPid = @{}
    foreach ($p in $procs) {
        $procByPid[[int]$p.ProcessId] = [string]$p.Name
    }

    $hashCache = @{}
    $sigCache = @{}
    $hashedPathsCount = 0
    $inventory = New-Object System.Collections.Generic.List[object]

    foreach ($p in $procs) {
        $exe = [string]$p.ExecutablePath
        $hash = $null
        $sigStatus = $null
        $sigSigner = $null

        if (-not [string]::IsNullOrWhiteSpace($exe)) {
            if ($hashCache.ContainsKey($exe)) {
                $hash = $hashCache[$exe]
            } elseif ($hashedPathsCount -lt $HashBudget) {
                $hash = Get-HashSafe -Path $exe
                $hashCache[$exe] = $hash
                $hashedPathsCount++
            }

            if ($sigCache.ContainsKey($exe)) {
                $sigStatus = $sigCache[$exe].status
                $sigSigner = $sigCache[$exe].signer
            } else {
                $sig = Get-SignatureSafe -Path $exe
                $sigCache[$exe] = $sig
                $sigStatus = $sig.status
                $sigSigner = $sig.signer
            }
        }

        $parentPid = [int]$p.ParentProcessId
        $parentName = $null
        if ($procByPid.ContainsKey($parentPid)) {
            $parentName = $procByPid[$parentPid]
        }

        $inventory.Add([pscustomobject]@{
            process_id = [int]$p.ProcessId
            process_name = [string]$p.Name
            parent_process_id = $parentPid
            parent_process_name = $parentName
            executable_path = $exe
            command_line = [string]$p.CommandLine
            file_hash_sha256 = $hash
            digital_signature_status = $sigStatus
            signer = $sigSigner
            creation_date = $(if ($p.CreationDate) {
                try { [string]([System.Management.ManagementDateTimeConverter]::ToDateTime($p.CreationDate)) } catch { $null }
            } else { $null })
        })
    }

    return $inventory
}

function Get-StartupItems {
    $results = New-Object System.Collections.Generic.List[object]

    $runKeyPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )

    foreach ($keyPath in $runKeyPaths) {
        try {
            $props = Get-ItemProperty -Path $keyPath -ErrorAction Stop
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -match "^PS") { continue }
                $results.Add([pscustomobject]@{
                    source = "registry_run_key"
                    location = $keyPath
                    name = [string]$prop.Name
                    command = [string]$prop.Value
                })
            }
        } catch {
            continue
        }
    }

    $startupFolders = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    )

    foreach ($folder in $startupFolders) {
        if (-not (Test-Path -LiteralPath $folder)) { continue }
        try {
            $items = Get-ChildItem -LiteralPath $folder -Force -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $results.Add([pscustomobject]@{
                    source = "startup_folder"
                    location = $folder
                    name = [string]$item.Name
                    command = [string]$item.FullName
                })
            }
        } catch {
            continue
        }
    }

    return $results
}

function Get-ScheduledTasksInventory {
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
    } catch {
        return @()
    }

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($task in $tasks) {
        $taskInfo = $null
        try {
            $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
        } catch {
            $taskInfo = $null
        }

        foreach ($action in $task.Actions) {
            $actionType = $null
            $execute = $null
            $arguments = $null
            $workingDirectory = $null

            if ($null -ne $action) {
                if ($action.PSObject.Properties.Match("CimClass").Count -gt 0 -and $null -ne $action.CimClass) {
                    $actionType = [string]$action.CimClass.CimClassName
                }
                if ($action.PSObject.Properties.Match("Execute").Count -gt 0) {
                    $execute = [string]$action.Execute
                }
                if ($action.PSObject.Properties.Match("Arguments").Count -gt 0) {
                    $arguments = [string]$action.Arguments
                }
                if ($action.PSObject.Properties.Match("WorkingDirectory").Count -gt 0) {
                    $workingDirectory = [string]$action.WorkingDirectory
                }
            }

            $results.Add([pscustomobject]@{
                task_name = [string]$task.TaskName
                task_path = [string]$task.TaskPath
                state = [string]$task.State
                author = [string]$task.Author
                run_as_user = [string]$task.Principal.UserId
                action_type = $actionType
                execute = $execute
                arguments = $arguments
                working_directory = $workingDirectory
                last_run_time = if ($taskInfo) { [string]$taskInfo.LastRunTime } else { $null }
                next_run_time = if ($taskInfo) { [string]$taskInfo.NextRunTime } else { $null }
                last_task_result = if ($taskInfo) { [long]$taskInfo.LastTaskResult } else { $null }
            })
        }
    }

    return $results
}

function Get-PrimaryMacAddress {
    try {
        $adapters = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ErrorAction Stop |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_.MACAddress) }

        if (-not $adapters) { return $null }

        $preferred = $adapters |
            Sort-Object @{ Expression = { if ($_.DefaultIPGateway) { 0 } else { 1 } } }, Description |
            Select-Object -First 1

        return [string]$preferred.MACAddress
    } catch {
        return $null
    }
}

function Get-SecuritySignals {
    $signals = [ordered]@{}

    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsSuspicious = @()
    if (Test-Path -LiteralPath $hostsPath) {
        try {
            $lines = Get-Content -LiteralPath $hostsPath -ErrorAction Stop
            foreach ($line in $lines) {
                $trim = $line.Trim()
                if ([string]::IsNullOrWhiteSpace($trim)) { continue }
                if ($trim.StartsWith("#")) { continue }
                if ($trim -match "(?i)microsoft|office|activation|kms|adobe|autodesk") {
                    $hostsSuspicious += $trim
                }
            }
        } catch {
            $hostsSuspicious = @()
        }
    }
    $signals["hosts_suspicious_entries"] = $hostsSuspicious

    $services = @("sppsvc", "osppsvc", "WinDefend")
    $svcStates = New-Object System.Collections.Generic.List[object]
    foreach ($svc in $services) {
        try {
            $obj = Get-Service -Name $svc -ErrorAction Stop
            $svcStates.Add([pscustomobject]@{
                service_name = $svc
                status = [string]$obj.Status
                start_type = $(try { [string](Get-CimInstance Win32_Service -Filter "Name='$svc'" -ErrorAction Stop).StartMode } catch { $null })
            })
        } catch {
            $svcStates.Add([pscustomobject]@{
                service_name = $svc
                status = "NotFound"
                start_type = $null
            })
        }
    }
    $signals["service_states"] = $svcStates

    if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
        try {
            $mp = Get-MpComputerStatus -ErrorAction Stop
            $signals["defender"] = [pscustomobject]@{
                real_time_protection_enabled = [bool]$mp.RealTimeProtectionEnabled
                antivirus_enabled = [bool]$mp.AntivirusEnabled
                antispyware_enabled = [bool]$mp.AntispywareEnabled
                ioav_protection_enabled = [bool]$mp.IoavProtectionEnabled
                tamper_protection_source = [string]$mp.IsTamperProtected
            }
        } catch {
            $signals["defender"] = $null
        }
    } else {
        $signals["defender"] = $null
    }

    return [pscustomobject]$signals
}

function Get-RelevantEventLogs {
    param(
        [int]$LookbackHours,
        [int]$MaxPerLog
    )

    $results = New-Object System.Collections.Generic.List[object]
    $startTime = (Get-Date).AddHours(-1 * $LookbackHours)

    $logIds = @{
        "System" = @(7036, 7040, 7045)
        "Security" = @(4688, 4697, 1102)
        "Application" = @(1033, 11707, 11724)
        "Microsoft-Windows-Windows Defender/Operational" = @(1116, 1117, 5007, 5010)
    }

    foreach ($logName in $logIds.Keys) {
        $logExists = $false
        try {
            $logExists = [bool](Get-WinEvent -ListLog $logName -ErrorAction Stop)
        } catch {
            $logExists = $false
        }
        if (-not $logExists) { continue }

        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName = $logName
                StartTime = $startTime
            } -ErrorAction Stop -MaxEvents $MaxPerLog
        } catch {
            continue
        }

        foreach ($evt in $events) {
            if ($evt.Id -notin $logIds[$logName]) { continue }

            $msg = $null
            try {
                $msg = [string]$evt.Message
            } catch {
                $msg = $null
            }

            if ($msg -and $msg.Length -gt 1200) {
                $msg = $msg.Substring(0, 1200)
            }

            $results.Add([pscustomobject]@{
                timestamp_utc = [string]($evt.TimeCreated.ToUniversalTime())
                log_name = [string]$evt.LogName
                event_id = [int]$evt.Id
                provider = [string]$evt.ProviderName
                level = [string]$evt.LevelDisplayName
                machine_name = [string]$evt.MachineName
                user_id = [string]$evt.UserId
                message = $msg
            })
        }
    }

    return $results | Sort-Object timestamp_utc -Descending
}

function New-Alert {
    param(
        [string]$RuleId,
        [string]$Severity,
        [string]$Title,
        [string]$Source,
        [string]$Entity,
        [string]$Evidence,
        [string]$Recommendation
    )

    return [pscustomobject]@{
        rule_id = $RuleId
        severity = $Severity
        title = $Title
        source = $Source
        entity = $Entity
        evidence = $Evidence
        recommendation = $Recommendation
    }
}

function Test-IsWhitelistedScheduledTask {
    param(
        [Parameter(Mandatory = $true)]
        $Task
    )

    $fullTaskName = "$($Task.task_path)$($Task.task_name)".ToLowerInvariant()

    $knownSafeTasks = @(
        "\microsoft\windows\windowscolorsystem\calibration loader",
        "\daikai crack detector monthly scan",
        "\crackdetector"
    )

    return $knownSafeTasks -contains $fullTaskName
}

function Test-IsScannerScheduledTask {
    param(
        [Parameter(Mandatory = $true)]
        $Task
    )

    if ($null -eq $Task) {
        return $false
    }

    $execute = [string]$Task.execute
    $arguments = [string]$Task.arguments
    $blob = "$execute $arguments".ToLowerInvariant()

    return (
        $blob -like "*\daikai\scanner.exe*" -or
        $blob -like "*crack_inventory_detector_and_upload_api.ps1*" -or
        $blob -like "*\crackdetector\*"
    )
}

function Test-IsScannerProcess {
    param(
        [Parameter(Mandatory = $true)]
        $Process,
        [Parameter(Mandatory = $true)]
        [int]$SelfProcessId
    )

    if ($null -eq $Process) {
        return $false
    }

    return ([int]$Process.process_id -eq $SelfProcessId)
}

function Find-SuspiciousItems {
    param(
        [array]$InstalledSoftware,
        [array]$Processes,
        [array]$StartupItems,
        [array]$ScheduledTasks,
        [pscustomobject]$SecuritySignals,
        [array]$EventLogs,
        [int]$SelfProcessId
    )

    $alerts = New-Object System.Collections.Generic.List[object]
    $pattern = "(?i)(kms|kmspico|autokms|keygen|crack|activator|patcher|loader|re-?loader|chew-wga|microsoft toolkit|vlmcsd)"

    foreach ($app in $InstalledSoftware) {
        $blob = "$($app.software_name) $($app.publisher) $($app.install_location) $($app.uninstall_string)"
        if ($blob -match $pattern) {
            $alerts.Add((New-Alert -RuleId "SW-001" -Severity "high" -Title "Suspicious software name/publisher" -Source "installed_software" -Entity $app.software_name -Evidence $blob -Recommendation "Remove the software and investigate installer source."))
        }
    }

    foreach ($proc in $Processes) {
        if (Test-IsScannerProcess -Process $proc -SelfProcessId $SelfProcessId) {
            continue
        }

        $blob = "$($proc.process_name) $($proc.command_line) $($proc.executable_path)"
        if ($blob -match $pattern) {
            $alerts.Add((New-Alert -RuleId "PR-001" -Severity "high" -Title "Suspicious process indicator" -Source "process" -Entity $proc.process_name -Evidence $blob -Recommendation "Terminate the process only after collecting forensic evidence."))
        }

        if ($proc.executable_path -and $proc.digital_signature_status -and $proc.digital_signature_status -notin @("Valid", "NotSigned")) {
            $alerts.Add((New-Alert -RuleId "PR-002" -Severity "medium" -Title "Process with problematic signature" -Source "process" -Entity $proc.process_name -Evidence "Signature status: $($proc.digital_signature_status); Path: $($proc.executable_path)" -Recommendation "Validate the binary hash against known-good sources."))
        }
    }

    foreach ($item in $StartupItems) {
        $blob = "$($item.name) $($item.command) $($item.location)"
        if ($blob -match $pattern) {
            $alerts.Add((New-Alert -RuleId "ST-001" -Severity "high" -Title "Suspicious startup persistence item" -Source "startup_item" -Entity $item.name -Evidence $blob -Recommendation "Disable this startup item and inspect file origin."))
        }
    }

    foreach ($task in $ScheduledTasks) {
        if (Test-IsWhitelistedScheduledTask -Task $task) {
            continue
        }
        if (Test-IsScannerScheduledTask -Task $task) {
            continue
        }

        $fullTaskName = "$($task.task_path)$($task.task_name)"
        $blob = "$fullTaskName $($task.execute) $($task.arguments)"

        if ($blob -match $pattern) {
            $alerts.Add((New-Alert -RuleId "TK-001" -Severity "high" -Title "Suspicious scheduled task" -Source "scheduled_task" -Entity $fullTaskName -Evidence $blob -Recommendation "Disable task and inspect referenced executable/script."))
        }
    }

    if ($SecuritySignals.hosts_suspicious_entries -and $SecuritySignals.hosts_suspicious_entries.Count -gt 0) {
        foreach ($entry in $SecuritySignals.hosts_suspicious_entries) {
            $alerts.Add((New-Alert -RuleId "HS-001" -Severity "high" -Title "Suspicious hosts file entry" -Source "hosts_file" -Entity "hosts" -Evidence $entry -Recommendation "Review and revert unauthorized host mappings."))
        }
    }

    foreach ($svc in $SecuritySignals.service_states) {
        if ($svc.service_name -eq "sppsvc" -and $svc.status -eq "Stopped") {
            $alerts.Add((New-Alert -RuleId "LS-001" -Severity "medium" -Title "Windows licensing service stopped" -Source "service_state" -Entity "sppsvc" -Evidence "Status: Stopped" -Recommendation "Confirm this is expected; unexpected stoppage may indicate tampering."))
        }
        if ($svc.service_name -eq "WinDefend" -and $svc.status -ne "Running" -and $svc.status -ne "NotFound") {
            $alerts.Add((New-Alert -RuleId "AV-001" -Severity "high" -Title "Defender service not running" -Source "service_state" -Entity "WinDefend" -Evidence "Status: $($svc.status)" -Recommendation "Restore AV protections and verify policy configuration."))
        }
    }

    foreach ($evt in $EventLogs) {
        $blob = "$($evt.provider) $($evt.message)"
        if ($blob -match $pattern) {
            $alerts.Add((New-Alert -RuleId "EV-001" -Severity "medium" -Title "Suspicious event-log indicator text" -Source "event_log" -Entity "$($evt.log_name):$($evt.event_id)" -Evidence $blob -Recommendation "Review related process/user activity and associated binaries."))
        }
        if ($evt.log_name -eq "Security" -and $evt.event_id -eq 1102) {
            $alerts.Add((New-Alert -RuleId "EV-002" -Severity "high" -Title "Security log was cleared" -Source "event_log" -Entity "Security:1102" -Evidence $evt.message -Recommendation "Treat as potential defense-evasion and investigate immediately."))
        }
        if ($evt.log_name -eq "Microsoft-Windows-Windows Defender/Operational" -and $evt.event_id -eq 5007) {
            $alerts.Add((New-Alert -RuleId "EV-003" -Severity "medium" -Title "Defender settings changed" -Source "event_log" -Entity "Defender:5007" -Evidence $evt.message -Recommendation "Validate if policy change was authorized."))
        }
    }

    return $alerts
}

function Get-OverallSeverity {
    param([array]$Alerts)

    if (@($Alerts | Where-Object { $_.severity -eq "high" }).Count -gt 0)   { return "high" }
    if (@($Alerts | Where-Object { $_.severity -eq "medium" }).Count -gt 0) { return "medium" }
    if (@($Alerts | Where-Object { $_.severity -eq "low" }).Count -gt 0)    { return "low" }
    return "clean"
}

function Write-JsonFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Object,
        [switch]$Pretty
    )

    $json = if ($Pretty) {
        $Object | ConvertTo-Json -Depth 8
    } else {
        $Object | ConvertTo-Json -Depth 8 -Compress
    }

    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

#############################
# API CONFIGURATION
#############################

if ([string]::IsNullOrWhiteSpace($ApiUrl)) {
    $ApiUrl = $DefaultApiUrl
}
if ([string]::IsNullOrWhiteSpace($Username)) {
    $Username = $DefaultUsername
}
if ([string]::IsNullOrWhiteSpace($Password)) {
    $Password = $DefaultPassword
}
if ([string]::IsNullOrWhiteSpace($Username)) {
    $Username = Read-Host -Prompt "API username"
}
if ([string]::IsNullOrWhiteSpace($Password)) {
    $Password = Read-SecretPlainText -Prompt "API password"
}

$ApiBaseUrl = Resolve-ApiEndpoint -Value $ApiUrl

#############################
# DEPENDENCY CHECKS
#############################

Write-Host "Checking dependencies..." -ForegroundColor Cyan
Write-Host "Using API endpoint: $ApiBaseUrl" -ForegroundColor DarkGray
Write-Host "Using API username: $Username" -ForegroundColor DarkGray
Write-Host "Dependencies OK." -ForegroundColor Green
Write-Host ""

#############################
# COLLECT INVENTORY DATA
#############################

Write-Host "Collecting software/security inventory..." -ForegroundColor Cyan

$installed = Get-InstalledSoftware

$appx = @()
if ($IncludeAppxPackages) {
    $appx = Get-AppxPackagesInventory
}

$processes = Get-ProcessInventory -HashBudget $MaxProcessHashes
$startup = Get-StartupItems
$tasks = Get-ScheduledTasksInventory
$signals = Get-SecuritySignals
$eventLogs = Get-RelevantEventLogs -LookbackHours $EventLookbackHours -MaxPerLog $MaxEventsPerLog
$primaryMacAddress = Get-PrimaryMacAddress

$alerts = Find-SuspiciousItems `
    -InstalledSoftware $installed `
    -Processes $processes `
    -StartupItems $startup `
    -ScheduledTasks $tasks `
    -SecuritySignals $signals `
    -EventLogs $eventLogs `
    -SelfProcessId $CurrentProcessId

$severityStats = @{
    low    = @($alerts | Where-Object { $_.severity -eq "low" }).Count
    medium = @($alerts | Where-Object { $_.severity -eq "medium" }).Count
    high   = @($alerts | Where-Object { $_.severity -eq "high" }).Count
}

$overallSeverity = Get-OverallSeverity -Alerts $alerts
$osInfo = $null
try {
    $osInfo = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
} catch {
    $osInfo = $null
}

Write-Host "Inventory collected." -ForegroundColor Green
Write-Host ""

#############################
# BUILD REPORT OBJECT
#############################

$report = [ordered]@{
    report_metadata = [ordered]@{
        script_version = $ScriptVersion
        generated_utc = [string]$NowUtc
        hostname = $ComputerNameValue
        username = $env:USERNAME
        userdomain = $env:USERDOMAIN
        primary_mac_address = $primaryMacAddress
        overall_severity = $overallSeverity
        os_caption = $(if ($null -ne $osInfo) { [string]$osInfo.Caption } else { $null })
        os_version = $(if ($null -ne $osInfo) { [string]$osInfo.Version } else { $null })
    }
    inventory_counts = [ordered]@{
        installed_software = @($installed).Count
        appx_packages = @($appx).Count
        running_processes = @($processes).Count
        startup_items = @($startup).Count
        scheduled_tasks = @($tasks).Count
        event_logs_relevant = @($eventLogs).Count
        alerts = @($alerts).Count
    }
    inventory = [ordered]@{
        installed_software = $installed
        appx_packages = $appx
        running_processes = $processes
        startup_items = $startup
        scheduled_tasks = $tasks
        event_logs_relevant = $eventLogs
        security_signals = $signals
    }
    alerts = $alerts
    alert_summary = $severityStats
}

$uploadReport = [ordered]@{
    report_metadata = $report.report_metadata
    inventory_counts = $report.inventory_counts
    alert_summary = $report.alert_summary
    alerts = $report.alerts
    security_signals = $signals
}

#############################
# WRITE LOCAL JSON FILES
#############################

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$safeHostName = $ComputerNameValue -replace '[^A-Za-z0-9._-]', '_'

$reportPath = Join-Path -Path $ResolvedOutputDir -ChildPath "crack_inventory_report_${safeHostName}_$stamp.json"
$alertsPath = Join-Path -Path $ResolvedOutputDir -ChildPath "crack_inventory_alerts_${safeHostName}_$stamp.json"

Write-JsonFile -Path $reportPath -Object $report -Pretty:$PrettyJson
Write-JsonFile -Path $alertsPath -Object $alerts -Pretty:$PrettyJson

Write-Host "Local JSON files written." -ForegroundColor Green
Write-Host "Report: $reportPath" -ForegroundColor DarkGray
Write-Host "Alerts: $alertsPath" -ForegroundColor DarkGray
Write-Host ""

#############################
# AUTHENTICATE WITH API
#############################

Write-Host "Authenticating with API..." -ForegroundColor Cyan

$loginResponse = Invoke-ApiRequest -Method "POST" -Action "login" -Body @{
    username = $Username
    password = $Password
}

$token = $loginResponse.token
Write-Host "Authenticated successfully." -ForegroundColor Green

#############################
# SUBMIT DETECTION DATA VIA API
#############################

Write-Host "Submitting suspicious-software report to API..." -ForegroundColor Cyan

$submitResponse = Invoke-ApiRequest -Method "POST" -Action "suspicious.submit" -Body @{
    computer_name = $ComputerNameValue
    severity = $overallSeverity
    mac_address = $primaryMacAddress
    result = $uploadReport
} -Token $token

Write-Host ""
Write-Host "[OK] Suspicious-software report submitted successfully. ID: $($submitResponse.id)" -ForegroundColor Green
Write-Host "Primary MAC      : $primaryMacAddress"
Write-Host "Overall Severity : $overallSeverity"
Write-Host "Alert counts     : high=$($severityStats.high), medium=$($severityStats.medium), low=$($severityStats.low)"
Write-Host ""
Write-Host "Done." -ForegroundColor Green
