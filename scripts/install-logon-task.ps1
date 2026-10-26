#Requires -Version 5.1
<#
.SYNOPSIS
    Installs the CmdAsUser logon task, machine-wide. Must be run elevated (Administrator).

.DESCRIPTION
    Called from the repo under admin privileges. It:
      1. Invokes x64\Release\CmdAsUser.exe, which (when run from the command line) copies itself
         plus CommandClient.exe and CommandServer.exe into System32 and SysWOW64.
      2. Copies the desired PowerShell script (startup.ps1) and the logon task script
         (logon-task.cmd) into the install location.
      3. Sets the CMDASUSER_* machine environment variables via setx /M.

    Failures at any step are reported back to the caller: a message is written and the script
    exits with a non-zero exit code (the count of failed steps).

    No user-specific paths are hardcoded - locations are derived from environment variables
    ($env:ProgramData, $env:windir) and the repo layout ($PSScriptRoot).

.PARAMETER InstallHome
    Where startup.ps1 / logon-task.cmd are copied to, and what CMDASUSER_HOME points at.
    Default: "$env:ProgramData\CmdAsUser" (machine-wide, no user profile involved).

.PARAMETER BinDir
    Folder holding the built x64 binaries. Default: "<repo>\x64\Release".

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install-logon-task.ps1
#>
[CmdletBinding()]
param(
    [string]$InstallHome,
    [string]$BinDir
)

$ErrorActionPreference = 'Stop'

# Resolve the script's own folder robustly ($PSScriptRoot can be empty in some hosts).
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }
$repoRoot = Split-Path -Parent $scriptDir

# Apply defaults (no hardcoded user paths - derived from env vars and repo layout).
if (-not $InstallHome) { $InstallHome = Join-Path $env:ProgramData 'CmdAsUser' }
if (-not $BinDir)      { $BinDir      = Join-Path $repoRoot 'x64\Release' }
$failures = New-Object System.Collections.Generic.List[string]
function Fail([string]$msg) { Write-Error $msg; $script:failures.Add($msg) }

# --- Must be elevated ---------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    Write-Error 'This installer must be run elevated (Administrator).'
    exit 1
}

# --- Derived paths (all from env vars / repo layout, no hardcoded user) -------
$system32    = Join-Path $env:windir 'System32'
$cmdAsUser   = Join-Path $BinDir 'CmdAsUser.exe'
$logPath     = Join-Path $InstallHome 'logon-task.log'
$psPath      = Join-Path $InstallHome 'startup.ps1'

Write-Host "CmdAsUser logon task installer"
Write-Host "  BinDir      : $BinDir"
Write-Host "  InstallHome : $InstallHome"
Write-Host ''

# --- Step 1: deploy binaries + install the persistent SYSTEM service ----------
# "CmdAsUser /install" (run elevated) stops any running instance, deploys
# CmdAsUser/CommandClient/CommandServer into System32 and SysWOW64 (so they are
# on the PATH), then registers the auto-start LocalSystem "McbCmdAsUser" service
# and starts it. Once running, the non-elevated logon launcher can drive it over
# IPC without admin. CmdAsUser copies from its CURRENT DIRECTORY, so CWD = BinDir.
Write-Host 'Step 1: deploying binaries and installing the SYSTEM service...'
if (-not (Test-Path $cmdAsUser)) {
    Fail "CmdAsUser.exe not found at: $cmdAsUser (build the x64 Release first)."
} else {
    Push-Location $BinDir
    try {
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $out  = & $cmdAsUser /install 2>&1 | ForEach-Object { "$_" }
        $code = $LASTEXITCODE
        $ErrorActionPreference = $prevEAP
        if ($out) { $out | ForEach-Object { Write-Host "    $_" } }
        if ($code -ne 0) {
            Fail "CmdAsUser /install failed (exit $code)."
        } else {
            Write-Host '  [ok]   binaries deployed; McbCmdAsUser service installed and started'
        }
    } finally {
        Pop-Location
    }
}

# --- Step 2: copy the PS and logon task scripts into InstallHome -------------
Write-Host 'Step 2: copying scripts...'
try { New-Item -ItemType Directory -Path $InstallHome -Force | Out-Null }
catch { Fail "Could not create InstallHome '$InstallHome': $($_.Exception.Message)" }

foreach ($f in 'startup.ps1','logon-task.cmd') {
    $src = Join-Path $scriptDir $f
    $dst = Join-Path $InstallHome $f
    if (-not (Test-Path $src)) { Fail "Source script missing: $src"; continue }
    try { Copy-Item $src $dst -Force; Write-Host "  [ok]   $dst" }
    catch { Fail "Failed to copy $f -> $dst : $($_.Exception.Message)" }
}

# --- Step 2b: copy the logon launcher into the current user's Startup folder --
# This launcher runs in the USER context at each logon (the Startup folder
# cannot elevate). It is placed in the current user's Startup folder so it runs
# at that user's logon.
#
# NOTE: this installer runs elevated, so $env:APPDATA resolves to the ADMIN
# profile that approved the elevation, which may differ from the interactive
# user. Prefer the Shell "Startup" special folder, falling back to APPDATA.
Write-Host "Step 2b: copying logon launcher to the current user's Startup folder..."
try {
    $startupFolder = (New-Object -ComObject WScript.Shell).SpecialFolders('Startup')
} catch { $startupFolder = $null }
if (-not $startupFolder) {
    $startupFolder = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'
}
$launcher      = 'logon-startup-launcher.cmd'
$launcherSrc   = Join-Path $scriptDir $launcher
$launcherDst   = Join-Path $startupFolder $launcher
if (-not (Test-Path $launcherSrc)) {
    Fail "Source launcher missing: $launcherSrc"
} else {
    try {
        New-Item -ItemType Directory -Path $startupFolder -Force | Out-Null
        Copy-Item $launcherSrc $launcherDst -Force
        Write-Host "  [ok]   $launcherDst"
    } catch {
        Fail "Failed to copy $launcher -> $launcherDst : $($_.Exception.Message)"
    }
}

# --- Step 3: set machine environment variables via setx ----------------------
Write-Host 'Step 3: setting machine environment variables (setx /M)...'
$vars = [ordered]@{
    CMDASUSER_HOME = $InstallHome
    CMDASUSER_LOG  = $logPath
    CMDASUSER_PS   = $psPath
    CMDASUSER_BIN  = $system32   # binaries now live in System32 (on PATH for all users)
}
foreach ($name in $vars.Keys) {
    $value = $vars[$name]
    & setx.exe /M $name $value | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail "setx failed for $name (exit $LASTEXITCODE)" }
    else {
        [Environment]::SetEnvironmentVariable($name, $value, 'Process')  # for immediate testing
        Write-Host ("  [ok]   {0} = {1}" -f $name, $value)
    }
}

# --- Report -------------------------------------------------------------------
Write-Host ''
if ($failures.Count -gt 0) {
    Write-Error ("Install completed with {0} failure(s):" -f $failures.Count)
    $failures | ForEach-Object { Write-Error "  - $_" }
    exit $failures.Count
}

Write-Host 'Install succeeded. CMDASUSER_* variables are set machine-wide.'
Write-Host 'Note: other running processes / existing logons see the new variables only after restart or re-logon.'
exit 0
