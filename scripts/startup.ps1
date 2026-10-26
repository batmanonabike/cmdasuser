# ============================================================
#  Sample startup.ps1 - run on logon by logon-task.cmd (as SYSTEM)
#
#  logon-task.cmd runs this only if the file pointed to by
#  CMDASUSER_PS exists.
#
#  IMPORTANT: do NOT write to CMDASUSER_LOG directly from here.
#  logon-task.cmd redirects this script's stdout/stderr into that
#  log and holds the file open, so a second writer here causes a
#  sharing violation. Just write to stdout (Write-Output) and the
#  cmd captures it.
#
#  See docs/logon-task-setup.md for setup instructions.
# ============================================================

function Write-Log([string]$msg) {
    Write-Output ("[{0}] {1}" -f (Get-Date -Format 's'), $msg)
}

Write-Log ("startup.ps1 running as {0}" -f (whoami))

# ------------------------------------------------------------
# Disable the Ctrl+Alt+Del logon requirement (DisableCAD).
# Runs as SYSTEM, so it has rights to the policy key. Note: if the
# setting is enforced by Group Policy it may be reverted on the next
# gpupdate/reboot - see docs/logon-task-setup.md.
# ------------------------------------------------------------
try {
    Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
        -Name 'DisableCAD' -Value 1 -Type DWord
    Write-Log 'DisableCAD set to 1 (Ctrl+Alt+Del not required)'
}
catch {
    Write-Log ("DisableCAD failed: {0}" -f $_.Exception.Message)
}

Write-Log 'startup.ps1 finished'
