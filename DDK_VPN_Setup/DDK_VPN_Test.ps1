# ============================================================
# DDK VPN Setup - Version 4
# ============================================================
#
# This version will:
#
# 1. Check Administrator privileges
# 2. Check whether Cisco AnyConnect is installed
# 3. Install AnyConnect silently ONLY if missing
# 4. Add SoftBank PKI to Windows Trusted Sites
# 5. Configure required Trusted Sites security settings
# 6. Enable Microsoft Edge IE Mode
# 7. Create/configure DDK Enterprise Mode Site List
# 8. Verify all configuration
#
# NOT included yet:
# - Certificate enrollment
# - VPN server/profile preconfiguration
#
# ============================================================

$ErrorActionPreference = "Stop"

Clear-Host

Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "          DDK VPN SETUP - VERSION 4"
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""


# ============================================================
# 1. CHECK ADMINISTRATOR PRIVILEGES
# ============================================================

Write-Host "[1/8] Checking Administrator privileges..." -ForegroundColor Yellow

$isAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

if (-not $isAdmin) {

    Write-Host ""
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host ""
    Write-Host "Please open PowerShell as Administrator and run the script again." -ForegroundColor Yellow
    Write-Host ""

    Read-Host "Press ENTER to close"

    exit 1
}

Write-Host "      OK - Running as Administrator" -ForegroundColor Green



# ============================================================
# 2. CHECK CISCO ANYCONNECT
# ============================================================

Write-Host ""
Write-Host "[2/8] Checking Cisco AnyConnect..." -ForegroundColor Yellow


$vpnPaths = @(

    "C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe",

    "C:\Program Files\Cisco\Cisco AnyConnect Secure Mobility Client\vpnui.exe",

    "C:\Program Files\Cisco\Cisco Secure Client\vpnui.exe"

)


$vpnFound = $false


foreach ($path in $vpnPaths) {

    if (Test-Path $path) {

        Write-Host "      Cisco AnyConnect already installed." -ForegroundColor Green
        Write-Host "      FOUND: $path" -ForegroundColor Green

        $vpnFound = $true

        break
    }
}


if (-not $vpnFound) {

    Write-Host "      Cisco AnyConnect NOT detected." -ForegroundColor Yellow

}



# ============================================================
# 3. INSTALL ANYCONNECT ONLY IF MISSING
# ============================================================

Write-Host ""
Write-Host "[3/8] AnyConnect installation check..." -ForegroundColor Yellow


$installerName = "anyconnect-win-4.10.05085-core-vpn-predeploy-k9.msi"

$installer = Join-Path $PSScriptRoot $installerName


if ($vpnFound) {

    Write-Host "      SKIPPED - AnyConnect is already installed." -ForegroundColor Green

}
else {

    Write-Host "      AnyConnect is NOT installed." -ForegroundColor Yellow


    if (-not (Test-Path $installer)) {

        Write-Host ""
        Write-Host "ERROR: AnyConnect installer was not found." -ForegroundColor Red
        Write-Host ""
        Write-Host "Expected location:" -ForegroundColor Yellow
        Write-Host "$installer"
        Write-Host ""

        Read-Host "Press ENTER to close"

        exit 1
    }


    Write-Host "      Installer found." -ForegroundColor Green
    Write-Host "      Installing Cisco AnyConnect..." -ForegroundColor Yellow
    Write-Host ""


    try {

        $process = Start-Process `
            -FilePath "msiexec.exe" `
            -ArgumentList "/i `"$installer`" /qn /norestart" `
            -Wait `
            -PassThru


        if ($process.ExitCode -eq 0) {

            Write-Host "      MSI installation completed successfully." -ForegroundColor Green

        }
        elseif ($process.ExitCode -eq 3010) {

            Write-Host "      Installation successful." -ForegroundColor Green
            Write-Host "      Windows restart may be required." -ForegroundColor Yellow

        }
        else {

            Write-Host ""
            Write-Host "ERROR: AnyConnect installation failed." -ForegroundColor Red
            Write-Host "MSI Exit Code: $($process.ExitCode)" -ForegroundColor Red
            Write-Host ""

            Read-Host "Press ENTER to close"

            exit 1
        }

    }
    catch {

        Write-Host ""
        Write-Host "ERROR while installing AnyConnect:" -ForegroundColor Red
        Write-Host $_.Exception.Message -ForegroundColor Red
        Write-Host ""

        Read-Host "Press ENTER to close"

        exit 1
    }


    # --------------------------------------------------------
    # Verify AnyConnect installation
    # --------------------------------------------------------

    Write-Host ""
    Write-Host "      Verifying installation..." -ForegroundColor Yellow

    Start-Sleep -Seconds 2

    $vpnFoundAfterInstall = $false


    foreach ($path in $vpnPaths) {

        if (Test-Path $path) {

            Write-Host "      VERIFIED: $path" -ForegroundColor Green

            $vpnFoundAfterInstall = $true

            break
        }
    }


    if (-not $vpnFoundAfterInstall) {

        Write-Host ""
        Write-Host "WARNING:" -ForegroundColor Yellow
        Write-Host "The MSI reported success, but vpnui.exe was not found."
        Write-Host "Check the Cisco installation manually."
        Write-Host ""
    }

}



# ============================================================
# 4. ADD SOFTBANK PKI TO TRUSTED SITES
# ============================================================

Write-Host ""
Write-Host "[4/8] Configuring SoftBank PKI Trusted Site..." -ForegroundColor Yellow


# DDK URL:
#
# https://pki-platform.softbanktelecom.co.jp
#
# Windows Security Zones:
#
# 1 = Local Intranet
# 2 = Trusted Sites
# 3 = Internet
# 4 = Restricted Sites


$domainKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\Domains\softbanktelecom.co.jp\pki-platform"


try {

    if (-not (Test-Path $domainKey)) {

        Write-Host "      Creating Trusted Site registry entry..."

        New-Item `
            -Path $domainKey `
            -Force |
            Out-Null

    }
    else {

        Write-Host "      Existing SoftBank registry entry found."

    }


    $currentTrustedValue = Get-ItemProperty `
        -Path $domainKey `
        -Name "https" `
        -ErrorAction SilentlyContinue


    if ($null -ne $currentTrustedValue -and $currentTrustedValue.https -eq 2) {

        Write-Host "      SKIPPED - SoftBank PKI already configured." -ForegroundColor Green

    }
    else {

        New-ItemProperty `
            -Path $domainKey `
            -Name "https" `
            -PropertyType DWord `
            -Value 2 `
            -Force |
            Out-Null

        Write-Host "      SoftBank PKI added to Trusted Sites." -ForegroundColor Green

    }

}
catch {

    Write-Host ""
    Write-Host "ERROR configuring SoftBank Trusted Site:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""

    exit 1
}



# ============================================================
# 5. CONFIGURE TRUSTED SITES SECURITY SETTINGS
# ============================================================

Write-Host ""
Write-Host "[5/8] Configuring Trusted Sites security settings..." -ForegroundColor Yellow


# ------------------------------------------------------------
# These settings correspond to the five changes shown
# in the DDK VPN guide.
#
# They apply ONLY to:
#
# Internet Options
#   -> Security
#      -> Trusted Sites (Zone 2)
#
#
# 1001 = Download signed ActiveX controls
# 1200 = Run ActiveX controls and plug-ins
# 1201 = Initialize/script ActiveX controls not marked safe
# 1400 = Active scripting
# 2201 = Automatic prompting for ActiveX controls
#
# Value 0 = Enable
# ------------------------------------------------------------


$trustedZonePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2"


$securitySettings = [ordered]@{

    "1001" = 0
    "1200" = 0
    "1201" = 0
    "1400" = 0
    "2201" = 0

}


$securityNames = @{

    "1001" = "Download signed ActiveX controls"

    "1200" = "Run ActiveX controls and plug-ins"

    "1201" = "Initialize and script ActiveX controls not marked safe"

    "1400" = "Active scripting"

    "2201" = "Automatic prompting for ActiveX controls"

}


try {

    if (-not (Test-Path $trustedZonePath)) {

        Write-Host "      Trusted Sites registry zone not found."
        Write-Host "      Creating Trusted Sites Zone 2 path..."

        New-Item `
            -Path $trustedZonePath `
            -Force |
            Out-Null
    }


    foreach ($settingName in $securitySettings.Keys) {

        $desiredValue = $securitySettings[$settingName]

        $description = $securityNames[$settingName]


        $existingSetting = Get-ItemProperty `
            -Path $trustedZonePath `
            -Name $settingName `
            -ErrorAction SilentlyContinue


        if ($null -ne $existingSetting) {

            $currentValue = $existingSetting.$settingName

        }
        else {

            $currentValue = $null

        }


        if ($currentValue -eq $desiredValue) {

            Write-Host ""
            Write-Host "      $settingName - $description"
            Write-Host "      SKIPPED - Already enabled." -ForegroundColor Green

        }
        else {

            New-ItemProperty `
                -Path $trustedZonePath `
                -Name $settingName `
                -PropertyType DWord `
                -Value $desiredValue `
                -Force |
                Out-Null


            Write-Host ""
            Write-Host "      $settingName - $description"
            Write-Host "      CONFIGURED - Enabled." -ForegroundColor Green

        }

    }

}
catch {

    Write-Host ""
    Write-Host "ERROR configuring Trusted Sites security:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""

    exit 1
}



# ============================================================
# 6. CONFIGURE MICROSOFT EDGE IE MODE
# ============================================================

Write-Host ""
Write-Host "[6/8] Configuring Microsoft Edge IE Mode..." -ForegroundColor Yellow


# Microsoft Edge machine policy location

$edgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"


try {

    if (-not (Test-Path $edgePolicyPath)) {

        Write-Host "      Creating Microsoft Edge policy registry path..."

        New-Item `
            -Path $edgePolicyPath `
            -Force |
            Out-Null
    }


    # --------------------------------------------------------
    # Enable Internet Explorer integration
    #
    # 0 = None
    # 1 = Internet Explorer Mode
    # 2 = Internet Explorer 11
    # --------------------------------------------------------

    $currentIELevel = Get-ItemProperty `
        -Path $edgePolicyPath `
        -Name "InternetExplorerIntegrationLevel" `
        -ErrorAction SilentlyContinue


    if (
        $null -ne $currentIELevel -and
        $currentIELevel.InternetExplorerIntegrationLevel -eq 1
    ) {

        Write-Host "      IE Mode already enabled - SKIPPED." -ForegroundColor Green

    }
    else {

        New-ItemProperty `
            -Path $edgePolicyPath `
            -Name "InternetExplorerIntegrationLevel" `
            -PropertyType DWord `
            -Value 1 `
            -Force |
            Out-Null

        Write-Host "      Microsoft Edge IE Mode enabled." -ForegroundColor Green

    }


    # --------------------------------------------------------
    # Allow sites to be manually reloaded in IE Mode
    #
    # This also matches the option shown in the DDK guide:
    #
    # Allow sites to be reloaded in Internet Explorer mode
    # --------------------------------------------------------

    $currentReload = Get-ItemProperty `
        -Path $edgePolicyPath `
        -Name "InternetExplorerIntegrationReloadInIEModeAllowed" `
        -ErrorAction SilentlyContinue


    if (
        $null -ne $currentReload -and
        $currentReload.InternetExplorerIntegrationReloadInIEModeAllowed -eq 1
    ) {

        Write-Host "      IE Mode reload already allowed - SKIPPED." -ForegroundColor Green

    }
    else {

        New-ItemProperty `
            -Path $edgePolicyPath `
            -Name "InternetExplorerIntegrationReloadInIEModeAllowed" `
            -PropertyType DWord `
            -Value 1 `
            -Force |
            Out-Null

        Write-Host "      IE Mode reload enabled." -ForegroundColor Green

    }

}
catch {

    Write-Host ""
    Write-Host "ERROR configuring Edge IE Mode:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""

    exit 1
}



# ============================================================
# 7. CREATE DDK ENTERPRISE MODE SITE LIST
# ============================================================

Write-Host ""
Write-Host "[7/8] Creating DDK IE Mode Site List..." -ForegroundColor Yellow


# ------------------------------------------------------------
# The DDK guide manually adds these three URLs:
#
# https://pki-platform.softbanktelecom.co.jp/PKI/ee/
#
# https://pki-platform.softbanktelecom.co.jp/PKI/ee/index
#
# https://pki-platform.softbanktelecom.co.jp/PKI/ee/renew/index
#
# Instead of using Edge's temporary 30-day local list,
# we create a persistent Enterprise Mode Site List.
# ------------------------------------------------------------


$siteListPath = Join-Path $PSScriptRoot "DDK_IE_Mode_Sites.xml"


$siteListXml = @"
<?xml version="1.0" encoding="utf-8"?>
<site-list version="1">

    <site url="pki-platform.softbanktelecom.co.jp/PKI/ee/">
        <compat-mode>Default</compat-mode>
        <open-in>IE11</open-in>
    </site>

    <site url="pki-platform.softbanktelecom.co.jp/PKI/ee/index">
        <compat-mode>Default</compat-mode>
        <open-in>IE11</open-in>
    </site>

    <site url="pki-platform.softbanktelecom.co.jp/PKI/ee/renew/index">
        <compat-mode>Default</compat-mode>
        <open-in>IE11</open-in>
    </site>

</site-list>
"@


try {

    # --------------------------------------------------------
    # Create/update XML
    # --------------------------------------------------------

    Set-Content `
        -Path $siteListPath `
        -Value $siteListXml `
        -Encoding UTF8


    if (Test-Path $siteListPath) {

        Write-Host "      Site List XML created." -ForegroundColor Green
        Write-Host "      $siteListPath"

    }
    else {

        throw "Site List XML could not be created."

    }


    # --------------------------------------------------------
    # Convert Windows path:
    #
    # C:\DDK_VPN_Setup\DDK_IE_Mode_Sites.xml
    #
    # to URI:
    #
    # file:///C:/DDK_VPN_Setup/DDK_IE_Mode_Sites.xml
    # --------------------------------------------------------

    $siteListUri = "file:///" + ($siteListPath -replace "\\", "/")


    # --------------------------------------------------------
    # Configure Edge to use the XML
    # --------------------------------------------------------

    New-ItemProperty `
        -Path $edgePolicyPath `
        -Name "InternetExplorerIntegrationSiteList" `
        -PropertyType String `
        -Value $siteListUri `
        -Force |
        Out-Null


    Write-Host ""
    Write-Host "      Enterprise Mode Site List configured." -ForegroundColor Green
    Write-Host "      $siteListUri"

}
catch {

    Write-Host ""
    Write-Host "ERROR configuring Enterprise Mode Site List:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""

    exit 1
}



# ============================================================
# 8. VERIFY EVERYTHING
# ============================================================

Write-Host ""
Write-Host "[8/8] Verifying configuration..." -ForegroundColor Yellow



# ============================================================
# VERIFY ANYCONNECT
# ============================================================

$finalVPNStatus = $false


foreach ($path in $vpnPaths) {

    if (Test-Path $path) {

        $finalVPNStatus = $true

        break
    }

}


if ($finalVPNStatus) {

    Write-Host ""
    Write-Host "      Cisco AnyConnect            : VERIFIED" -ForegroundColor Green

}
else {

    Write-Host ""
    Write-Host "      Cisco AnyConnect            : FAILED" -ForegroundColor Red

}



# ============================================================
# VERIFY TRUSTED SITE
# ============================================================

$trustedSiteVerified = $false


$trustedVerification = Get-ItemProperty `
    -Path $domainKey `
    -Name "https" `
    -ErrorAction SilentlyContinue


if (
    $null -ne $trustedVerification -and
    $trustedVerification.https -eq 2
) {

    Write-Host "      SoftBank PKI Trusted Site   : VERIFIED" -ForegroundColor Green

    $trustedSiteVerified = $true

}
else {

    Write-Host "      SoftBank PKI Trusted Site   : FAILED" -ForegroundColor Red

}



# ============================================================
# VERIFY SECURITY SETTINGS
# ============================================================

$securityVerified = $true


Write-Host ""
Write-Host "      Checking Trusted Sites security settings..."


foreach ($settingName in $securitySettings.Keys) {

    $desiredValue = $securitySettings[$settingName]

    $description = $securityNames[$settingName]


    $check = Get-ItemProperty `
        -Path $trustedZonePath `
        -Name $settingName `
        -ErrorAction SilentlyContinue


    if (
        $null -ne $check -and
        $check.$settingName -eq $desiredValue
    ) {

        Write-Host "      $settingName : VERIFIED - $description" -ForegroundColor Green

    }
    else {

        Write-Host "      $settingName : FAILED - $description" -ForegroundColor Red

        $securityVerified = $false

    }

}



# ============================================================
# VERIFY EDGE IE MODE
# ============================================================

$edgeVerified = $true


Write-Host ""
Write-Host "      Checking Microsoft Edge IE Mode..."


$edgeSettings = Get-ItemProperty `
    -Path $edgePolicyPath `
    -ErrorAction SilentlyContinue


if (
    $null -ne $edgeSettings -and
    $edgeSettings.InternetExplorerIntegrationLevel -eq 1
) {

    Write-Host "      IE Mode                     : VERIFIED" -ForegroundColor Green

}
else {

    Write-Host "      IE Mode                     : FAILED" -ForegroundColor Red

    $edgeVerified = $false

}


if (
    $null -ne $edgeSettings -and
    $edgeSettings.InternetExplorerIntegrationReloadInIEModeAllowed -eq 1
) {

    Write-Host "      IE Mode Reload              : VERIFIED" -ForegroundColor Green

}
else {

    Write-Host "      IE Mode Reload              : FAILED" -ForegroundColor Red

    $edgeVerified = $false

}


if (
    $null -ne $edgeSettings -and
    $edgeSettings.InternetExplorerIntegrationSiteList -eq $siteListUri
) {

    Write-Host "      Enterprise Site List Policy : VERIFIED" -ForegroundColor Green

}
else {

    Write-Host "      Enterprise Site List Policy : FAILED" -ForegroundColor Red

    $edgeVerified = $false

}


if (Test-Path $siteListPath) {

    Write-Host "      Site List XML File          : VERIFIED" -ForegroundColor Green

}
else {

    Write-Host "      Site List XML File          : FAILED" -ForegroundColor Red

    $edgeVerified = $false

}



# ============================================================
# FINAL SUMMARY
# ============================================================

Write-Host ""
Write-Host ""
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "             VERSION 4 COMPLETE"
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""


if ($finalVPNStatus) {

    Write-Host "AnyConnect       : INSTALLED" -ForegroundColor Green

}
else {

    Write-Host "AnyConnect       : NOT DETECTED" -ForegroundColor Red

}


if ($trustedSiteVerified) {

    Write-Host "SoftBank Trusted : CONFIGURED" -ForegroundColor Green

}
else {

    Write-Host "SoftBank Trusted : NOT CONFIGURED" -ForegroundColor Red

}


if ($securityVerified) {

    Write-Host "Security settings: CONFIGURED" -ForegroundColor Green

}
else {

    Write-Host "Security settings: INCOMPLETE" -ForegroundColor Red

}


if ($edgeVerified) {

    Write-Host "Edge IE Mode     : CONFIGURED" -ForegroundColor Green

}
else {

    Write-Host "Edge IE Mode     : INCOMPLETE" -ForegroundColor Red

}


Write-Host "Certificate      : NOT CHANGED" -ForegroundColor Yellow


Write-Host ""
Write-Host "============================================="
Write-Host ""
Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host "Fully close Microsoft Edge and reopen it."
Write-Host ""
Write-Host "Then check:"
Write-Host ""
Write-Host "    edge://policy"
Write-Host ""
Write-Host "and:"
Write-Host ""
Write-Host "    edge://compat/enterprise"
Write-Host ""
Write-Host "Press ENTER to close."

Read-Host