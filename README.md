# BulkProfileCleanup

PowerShell script to safely list and delete stale local (and optionally domain) user profiles on Windows.

## Features

* Requires Administrator privileges
* Dry-run by default; only delete when `-Delete` is specified
* Filters by last login time (default: 30 days)
* Supports inclusion/exclusion of users and domain users
* Protects built-in and currently logged-in users
* Uses modern CIM for performance and reliability
* `-IncludeUsers` / `-ExcludeUsers` accept either `user` or `DOMAIN\\user` (qualified entries match exact account; unqualified entries match by username)

## Usage

```powershell
# To run when scripts are disallowed:
powershell -ExecutionPolicy Bypass -File .\bulk_profile_cleanup.ps1

# Dry-run
.\bulk_profile_cleanup.ps1

# Actual delete of profiles older than 60 days
.\bulk_profile_cleanup.ps1 -OlderThanDays 60 -Delete

# Include domain users in cleanup
.\bulk_profile_cleanup.ps1 -IncludeDomain -OlderThanDays 90 -Delete

# Delete specific users regardless of time
.\bulk_profile_cleanup.ps1 -IncludeUsers "user1","user2" -Delete
```
