Set-Location $PSScriptRoot\..\
# Untrack helper ps1 files (if they are tracked)
$tracked = git ls-files -- "scripts/*.ps1" 2>$null
if ($tracked) {
    foreach ($f in $tracked) {
        if ($f -ne 'scripts/copy_repo_and_sys.ps1') {
            Write-Output ("Untracking: $f")
            git rm --cached -- "$f" 2>$null | Out-Null
        }
    }
    git commit -m "Untrack helper scripts" --no-verify 2>$null | Out-Null
}
# Ensure scripts/*.ps1 is in .gitignore
if (!(Test-Path .gitignore)) { New-Item -Path .gitignore -ItemType File | Out-Null }
$ignoreLine = 'scripts/*.ps1'
if (-not (Get-Content .gitignore | Select-String -SimpleMatch $ignoreLine)) {
    Add-Content -Path .gitignore -Value $ignoreLine
    git add .gitignore
    git commit -m "Add scripts/*.ps1 to .gitignore" --no-verify 2>$null | Out-Null
}
# Push changes
Write-Output 'Pushing changes to origin/main'
git push origin main
# Refresh remotes and list origin branches
git fetch --all --prune
Write-Output 'Remote branches on origin:'
git for-each-ref --format='%(refname:short)' refs/remotes/origin
