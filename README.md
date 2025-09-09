# BulkProfileCleanup

PowerShell script to safely list and delete stale local (and optionally domain) user profiles on Windows.

## Features

- Dry-run by default; only delete when `-Delete` is specified
- Filters by last login time (default: 30 days)
- Supports inclusion/exclusion of users and domain users
- Protects built-in and currently logged-in users
- Uses modern CIM for performance and reliability
- Requires Administrator privileges

## Usage

```powershell
# To run when scripts are disallowed:
powershell -ExecutionPolicy Bypass -File .\BulkProfileCleanup.ps1

# Dry-run
.\BulkProfileCleanup.ps1

# Actual delete of profiles older than 60 days
.\BulkProfileCleanup.ps1 -OlderThanDays 60 -Delete

# Include domain users in cleanup
.\BulkProfileCleanup.ps1 -IncludeDomain -OlderThanDays 90 -Delete

# Delete specific users regardless of time
.\BulkProfileCleanup.ps1 -IncludeUsers "user1","user2" -Delete
