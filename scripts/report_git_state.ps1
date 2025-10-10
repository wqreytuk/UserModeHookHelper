Set-Location $PSScriptRoot\..\
Write-Output '--- git status ---'
git status -s -b
Write-Output ''
Write-Output '--- local branches ---'
git branch --format='%(refname:short)'
Write-Output ''
Write-Output '--- remote branches (origin) ---'
git for-each-ref --format='%(refname:short)' refs/remotes/origin
Write-Output ''
Write-Output '--- last 5 commits on main ---'
git log -n 5 --pretty=format:'%h %ad %s' --date=iso
Write-Output ''
Write-Output '--- remote URL ---'
git remote -v
