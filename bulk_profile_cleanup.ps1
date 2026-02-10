<#
BulkProfileCleanup.ps1

Safely clean up stale local (and optionally domain) user profiles on a Windows machine.
Dry-run by default; only removes when -Delete is specified.
Requires Administrator privileges.

Usage Examples:
  powershell -ExecutionPolicy Bypass -File .\BulkProfileCleanup.ps1
  .\BulkProfileCleanup.ps1 -OlderThanDays 60 -Delete
  .\BulkProfileCleanup.ps1 -IncludeUsers "user1","user2" -Delete
  .\BulkProfileCleanup.ps1 -IncludeDomain -OlderThanDays 90 -Delete

NOTE:
If you encounter the error "running scripts is disabled on this system", you can bypass it by running:
  powershell -ExecutionPolicy Bypass -File .\BulkProfileCleanup.ps1
#>

param(
  [int]$OlderThanDays = 30,
  [string[]]$IncludeUsers = @(),   # user or DOMAIN\user; overrides time cutoff for matched entries
  [string[]]$ExcludeUsers = @(),   # user or DOMAIN\user exclusions
  [switch]$IncludeDomain,          # include domain users' local profiles
  [switch]$Delete                  # actually delete
)

# Require admin
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Error "Please run PowerShell as Administrator."
  exit 1
}

$cutoff   = (Get-Date).AddDays(-$OlderThanDays)
$computer = $env:COMPUTERNAME

# Built-in exclude list + current user
$builtIn = @(
  'Administrator','Default','Default User','Public',
  'All Users','WDAGUtilityAccount','systemprofile',
  'LocalService','NetworkService','defaultuser0', $env:USERNAME
)

function Split-AccountRules {
  param([string[]]$Values)

  $qualified = @()
  $unqualified = @()

  foreach ($value in $Values) {
    if ([string]::IsNullOrWhiteSpace($value)) { continue }
    $entry = $value.Trim()
    if ($entry -match '\\') {
      $qualified += $entry
    } else {
      $unqualified += $entry
    }
  }

  [pscustomobject]@{
    Qualified   = $qualified
    Unqualified = $unqualified
    HasAny      = ($qualified.Count + $unqualified.Count) -gt 0
  }
}

$excludeRules = Split-AccountRules -Values ($builtIn + $ExcludeUsers)
$includeRules = Split-AccountRules -Values $IncludeUsers

# Get profiles via CIM (faster, modern)
$profiles = Get-CimInstance Win32_UserProfile | Where-Object {
  $_.LocalPath -like 'C:\Users\*' -and -not $_.Loaded
}

# Attach NTAccount to each profile
foreach ($p in $profiles) {
  try {
    $acc = (New-Object System.Security.Principal.SecurityIdentifier($p.SID)).Translate([System.Security.Principal.NTAccount]).Value
  } catch { $acc = $null }
  $p | Add-Member -NotePropertyName NTAccount -NotePropertyValue $acc -Force
}

function Convert-LastUseTime {
  param([Parameter(Mandatory=$true)]$Value)
  if ($null -eq $Value) { return [datetime]::MinValue }
  $t = $Value.GetType().FullName
  switch ($t) {
    'System.DateTime' { return [datetime]$Value }
    'System.UInt64'   { return [datetime]::FromFileTime([int64]$Value) }
    default {
      try {
        if ($Value -is [string]) {
          return [datetime]::Parse($Value)
        } else {
          return [datetime]::FromFileTime([int64]$Value)
        }
      } catch {
        return [datetime]::MinValue
      }
    }
  }
}

$candidates = @()

foreach ($p in $profiles) {
  $name = $p.NTAccount
  $path = $p.LocalPath
  $last = Convert-LastUseTime -Value $p.LastUseTime

  # derive username
  $userName = if ($name) { ($name -split '\\')[-1] } else { Split-Path $path -Leaf }

  $matchesQualifiedInclude = $name -and ($includeRules.Qualified -contains $name)
  $matchesUnqualifiedInclude = $includeRules.Unqualified -contains $userName
  $matchesInclude = $matchesQualifiedInclude -or $matchesUnqualifiedInclude

  # exclude system/current/extra
  $matchesQualifiedExclude = $name -and ($excludeRules.Qualified -contains $name)
  $matchesUnqualifiedExclude = $excludeRules.Unqualified -contains $userName
  if ($matchesQualifiedExclude -or $matchesUnqualifiedExclude) { continue }

  # only local by default
  if (-not $IncludeDomain) {
    $isLocalAccount = (-not $name) -or ($name -like "$computer\*")
    if (-not $isLocalAccount -and -not $matchesInclude) { continue }
  }

  # IncludeUsers takes precedence
  if ($includeRules.HasAny) {
    if (-not $matchesInclude) { continue }
    # ignore time cutoff when explicitly included
  } else {
    if ($last -ge $cutoff) { continue }
  }

  $candidates += [pscustomobject]@{
    NTAccount   = $name
    UserName    = $userName
    UserFolder  = $path
    LastUseTime = $last
    CimObject   = $p
  }
}

if ($candidates.Count -eq 0) {
  Write-Host "No profiles matched. Nothing to do."
  return
}

$candidates | Select-Object NTAccount,UserFolder,LastUseTime | Format-Table -AutoSize

if (-not $Delete) {
  Write-Host "`nDRY RUN: add -Delete to actually remove." -ForegroundColor Yellow
  return
}

Write-Host "`nDeleting..." -ForegroundColor Red
foreach ($c in $candidates) {
  try {
    # remove profile (registry + files)
    Remove-CimInstance -InputObject $c.CimObject -ErrorAction Stop
    # hard delete lingering folder if any
    if (Test-Path $c.UserFolder) {
      Remove-Item $c.UserFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Host "OK  - $($c.NTAccount) -> $($c.UserFolder)"
  } catch {
    Write-Warning "FAIL- $($c.NTAccount): $($_.Exception.Message)"
  }
}
Write-Host "Done."
