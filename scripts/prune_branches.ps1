# Creates a safety snapshot branch and deletes all branches except main and the snapshot
Set-Location $PSScriptRoot\..\
if ((git status --porcelain) -ne '') {
    Write-Output 'WORKTREE_DIRTY'
    exit 2
}

git fetch --all --prune
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$snap = "backup-all-before-prune-$ts"
Write-Output ("Creating snapshot branch: $snap")
git branch $snap
Write-Output ("Pushing snapshot branch to origin: $snap")
git push -u origin $snap

# Delete local branches except main and snapshot
$keep = @('main', $snap)
$local = git for-each-ref --format='%(refname:short)' refs/heads | Where-Object { $keep -notcontains $_ }
foreach ($b in $local) {
    Write-Output ("Deleting local branch: $b")
    git branch -D $b
}

# Delete remote branches except origin/main and snapshot
$remotes = git for-each-ref --format='%(refname:short)' refs/remotes/origin | ForEach-Object { $_ -replace '^origin/', '' } | Where-Object { $keep -notcontains $_ }
foreach ($r in $remotes) {
    Write-Output ("Deleting remote branch: $r")
    git push origin --delete $r
}

Write-Output ("SNAPSHOT=$snap")
Write-Output 'DONE'
