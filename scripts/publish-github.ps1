param(
    [string]$RepoName = 'AI-Reverse-Engineering-Studio',
    [ValidateSet('public', 'private')][string]$Visibility = 'public'
)
$ErrorActionPreference = 'Stop'
Set-Location (Resolve-Path (Join-Path $PSScriptRoot '..'))
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'Install GitHub CLI from https://cli.github.com/'
}
gh auth status
if ($LASTEXITCODE -ne 0) { throw 'Sign in using gh auth login first.' }
$owner = gh api user --jq .login
if ($owner -ne 'hossain0707') { throw "Wrong GitHub account: $owner" }
gh repo create "$owner/$RepoName" "--$Visibility" --description 'Local-first cross-platform AI Reverse Engineering Studio with Ghidra and Ollama integration' --source . --remote origin --push
if ($LASTEXITCODE -ne 0) { throw 'GitHub repository creation/push failed.' }
Write-Host "Created: https://github.com/$owner/$RepoName"
