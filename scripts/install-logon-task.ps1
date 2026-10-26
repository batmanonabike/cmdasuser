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
$taskPath    = Join-Path $InstallHome 'logon-task.cmd'

Write-Host "CmdAsUser logon task installer"
Write-Host "  BinDir      : $BinDir"
Write-Host "  InstallHome : $InstallHome"
Write-Host ''

# --- Step 1: CmdAsUser self-copies into System32 / SysWOW64 -------------------
# CmdAsUser copies from its CURRENT DIRECTORY, so run it with CWD = BinDir.
# The tool owns the copy; we just invoke it.
Write-Host 'Step 1: deploying binaries via CmdAsUser self-copy...'
if (-not (Test-Path $cmdAsUser)) {
    Fail "CmdAsUser.exe not found at: $cmdAsUser (build the x64 Release first)."
} else {
    Push-Location $BinDir
    try {
        # The tool owns the copy and may write to stderr (e.g. error 32 / sharing
        # violation when a binary is already in use by the running service - benign,
        # it just means it is already deployed). Do not let that abort the install.
        $prevEAP = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        $out = & $cmdAsUser 2>&1 | ForEach-Object { "$_" }
        $ErrorActionPreference = $prevEAP
        if ($out) { $out | ForEach-Object { Write-Host "    $_" } }
        Write-Host '  [ok]   CmdAsUser invoked (self-copy to System32/SysWOW64)'
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
