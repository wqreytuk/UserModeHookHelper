Set-Location $PSScriptRoot\..\
Write-Output "Checking out main"
git checkout main
$toDelete = git for-each-ref --format='%(refname:short)' refs/heads | Where-Object { $_ -ne 'main' }
if ($toDelete) {
    Write-Output "Branches to delete:"
    $toDelete | ForEach-Object { Write-Output $_ }
    foreach ($b in $toDelete) {
        git branch -D $b
    }
} else {
    Write-Output "No local branches to delete"
}
Write-Output "Remaining branches:"
git branch --format='%(refname:short)'
