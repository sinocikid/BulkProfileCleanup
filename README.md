diff --git a/README.md b/README.md
index 107453e22e2d362741c2fb2dc982d79c137541d6..750808825a6a9e9bc73b24a83d5f016e595bd80e 100644
--- a/README.md
+++ b/README.md
@@ -1,31 +1,32 @@
 # BulkProfileCleanup
 
 PowerShell script to safely list and delete stale local (and optionally domain) user profiles on Windows.
 
 ## Features
 
 * Requires Administrator privileges
 * Dry-run by default; only delete when `-Delete` is specified
 * Filters by last login time (default: 30 days)
 * Supports inclusion/exclusion of users and domain users
 * Protects built-in and currently logged-in users
 * Uses modern CIM for performance and reliability
+* `-IncludeUsers` / `-ExcludeUsers` accept either `user` or `DOMAIN\\user` (qualified entries match exact account; unqualified entries match by username)
 
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
