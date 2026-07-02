<#
Pelycon Repository Security Bootstrap
Windows PowerShell Script

Purpose:
- Add/update baseline security files in a GitHub repository.
- Configure repository settings.
- Configure branch protection.
- Optionally create a harmless draft pull request to make the security workflow/check appear in GitHub.

Required environment variable:
$env:GITHUB_TOKEN = "your-token"

Recommended fine-grained PAT permissions:
- Administration: Read and write
- Contents: Read and write
- Workflows: Read and write
- Pull requests: Read and write, only needed for -CreateTestPullRequest
- Metadata: Read-only

Dry run:
.\Set-PelyconRepoSecurity.ps1 -Owner "TateWilson-dev" -Repo "claude-hooks-test" -DryRun

Apply:
.\Set-PelyconRepoSecurity.ps1 -Owner "TateWilson-dev" -Repo "claude-hooks-test"

Apply and create draft test PR:
.\Set-PelyconRepoSecurity.ps1 -Owner "TateWilson-dev" -Repo "claude-hooks-test" -CreateTestPullRequest
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Owner,

    [Parameter(Mandatory = $true)]
    [string]$Repo,

    [string]$Branch = "main",

    [int]$RequiredApprovals = 1,

    [string]$GitleaksCheckName = "gitleaks",

    [switch]$DryRun,

    [switch]$SkipFiles,

    [switch]$SkipRepoSettings,

    [switch]$SkipBranchProtection,

    [switch]$CreateTestPullRequest
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$GitHubApiBase = "https://api.github.com"
$RepoApiBase = "$GitHubApiBase/repos/$Owner/$Repo"

function Write-Step {
    param([string]$Message)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor DarkCyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor DarkCyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-DryRun {
    param([string]$Message)
    Write-Host "[DRY RUN] $Message" -ForegroundColor Yellow
}

function Get-GitHubToken {
    if ([string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
        throw "GITHUB_TOKEN is not set. Run: `$env:GITHUB_TOKEN = `"paste-token-here`""
    }

    return $env:GITHUB_TOKEN
}

function Invoke-GitHub {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [object]$Body = $null,

        [switch]$Allow404
    )

    $token = Get-GitHubToken

    $headers = @{
        "Authorization"        = "Bearer $token"
        "Accept"               = "application/vnd.github+json"
        "X-GitHub-Api-Version" = "2022-11-28"
        "User-Agent"           = "Pelycon-Repo-Security-Bootstrap"
    }

    try {
        if ($null -eq $Body) {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
        }

        $json = $Body | ConvertTo-Json -Depth 20
        return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body $json -ContentType "application/json"
    }
    catch {
        $statusCode = $null
        try {
            $statusCode = [int]$_.Exception.Response.StatusCode
        }
        catch {
            $statusCode = $null
        }

        if ($Allow404 -and $statusCode -eq 404) {
            return $null
        }

        $message = $_.Exception.Message

        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $responseBody = $reader.ReadToEnd()
            if (-not [string]::IsNullOrWhiteSpace($responseBody)) {
                $message = "$message`n$responseBody"
            }
        }
        catch {
            # Ignore response parsing failure.
        }

        throw $message
    }
}

function Test-RepositoryAccess {
    Write-Step "Checking repository access"

    if ($DryRun) {
        Write-DryRun "Would check repo access for $Owner/$Repo."
    }

    $repoInfo = Invoke-GitHub -Method "GET" -Uri $RepoApiBase
    Write-Ok ("Repository found: {0}" -f $repoInfo.full_name)

    $defaultBranch = $repoInfo.default_branch
    Write-Host ("GitHub default branch: {0}" -f $defaultBranch)

    if ($Branch -ne $defaultBranch) {
        Write-Warn ("Script branch is '{0}', but GitHub default branch is '{1}'." -f $Branch, $defaultBranch)
        Write-Warn "Use -Branch '$defaultBranch' if this repo does not use '$Branch'."
    }
}

function Get-FileSha {
    param([string]$Path)

    $encodedPath = [System.Uri]::EscapeDataString($Path).Replace("%2F", "/")
    $uri = "$RepoApiBase/contents/$encodedPath`?ref=$Branch"

    $result = Invoke-GitHub -Method "GET" -Uri $uri -Allow404

    if ($null -eq $result) {
        return $null
    }

    return $result.sha
}

function Set-RepositoryFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    if ($DryRun) {
        Write-DryRun ("Would create/update file: {0}" -f $Path)
        return
    }

    $sha = Get-FileSha -Path $Path

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    $encodedContent = [System.Convert]::ToBase64String($bytes)

    $body = @{
        message = $Message
        content = $encodedContent
        branch  = $Branch
    }

    if (-not [string]::IsNullOrWhiteSpace($sha)) {
        $body.sha = $sha
    }

    $encodedPath = [System.Uri]::EscapeDataString($Path).Replace("%2F", "/")
    $uri = "$RepoApiBase/contents/$encodedPath"

    Invoke-GitHub -Method "PUT" -Uri $uri -Body $body | Out-Null
    Write-Ok ("Created/updated {0}" -f $Path)
}

function Get-ClaudeMdContent {
@'
# CLAUDE.md — Pelycon Secure Vibe Coding Rules

## Security rules

- Never hardcode secrets, passwords, tokens, private keys, connection strings, or client secrets.
- Use approved secret storage such as GitHub Actions secrets, Azure Key Vault, environment variables, or the project-approved secret manager.
- Do not weaken authentication, authorization, tenant isolation, logging, or audit controls without explicit human approval.
- Treat this file as a repository security control. Change it only through pull request review.

## Workflow rules

- Work on a feature branch. Do not commit directly to `main` or `master`.
- Every change must go through a pull request before merge.
- A human reviewer must approve before code is merged.
- Do not use `--no-verify` to bypass local Git hooks.
- If a security check fails, stop and fix the issue instead of bypassing the control.

## Secret scanning requirement

All code must be scanned with Gitleaks before it is committed, pushed, or opened as a pull request.

Claude must follow this workflow:

1. Before committing, verify Gitleaks is available:

   ```bash
   gitleaks version
   ```

2. Before committing, run:

   ```bash
   gitleaks git --pre-commit --staged --redact --no-banner --exit-code 1
   ```

3. Before pushing, run:

   ```bash
   gitleaks git --redact --no-banner --exit-code 1 .
   ```

4. If Gitleaks finds a secret, stop immediately.

5. Do not reveal, print, summarize, or copy the secret value. Only identify the file, line, and rule/fingerprint if needed.

6. If a finding appears to be a false positive, request review before adding anything to `.gitleaksignore`.

The local device-level Pelycon Git bootstrap should also run Gitleaks automatically on every commit and push. GitHub Actions runs it again as the server-side backstop.
'@
}

function Get-GitleaksTomlContent {
@'
title = "Pelycon Gitleaks Configuration"

[extend]
useDefault = true
'@
}

function Get-GitleaksIgnoreContent {
@'
# Approved false-positive fingerprints can go here after review.
# Do not use this file to hide real secrets.
'@
}

function Get-SecurityWorkflowContent {
@'
name: security

on:
  pull_request:
  push:
    branches: ["**"]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  gitleaks:
    name: gitleaks
    runs-on: ubuntu-latest

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Gitleaks scan
        run: >
          docker run --rm -v "$PWD:/repo"
          ghcr.io/gitleaks/gitleaks:latest git /repo
          --redact --no-banner --exit-code 1
'@
}

function Set-SecurityFiles {
    if ($SkipFiles) {
        Write-Warn "Skipping security file creation/update."
        return
    }

    Write-Step "Creating/updating security files"

    Set-RepositoryFile -Path "CLAUDE.md" -Content (Get-ClaudeMdContent) -Message "Add Pelycon CLAUDE.md security rules"
    Set-RepositoryFile -Path ".gitleaks.toml" -Content (Get-GitleaksTomlContent) -Message "Add Pelycon Gitleaks config"
    Set-RepositoryFile -Path ".gitleaksignore" -Content (Get-GitleaksIgnoreContent) -Message "Add Pelycon Gitleaks ignore file"
    Set-RepositoryFile -Path ".github/workflows/security.yml" -Content (Get-SecurityWorkflowContent) -Message "Add Pelycon security workflow"
}

function Set-RepositorySettings {
    if ($SkipRepoSettings) {
        Write-Warn "Skipping repository settings."
        return
    }

    Write-Step "Configuring repository settings"

    $body = @{
        allow_squash_merge          = $true
        allow_merge_commit          = $false
        allow_rebase_merge          = $false
        allow_auto_merge            = $false
        delete_branch_on_merge      = $true
        allow_update_branch         = $true
        squash_merge_commit_title   = "PR_TITLE"
        squash_merge_commit_message = "PR_BODY"
    }

    if ($DryRun) {
        Write-DryRun "Would configure squash merge only and auto-delete branches."
        return
    }

    Invoke-GitHub -Method "PATCH" -Uri $RepoApiBase -Body $body | Out-Null
    Write-Ok "Repository settings configured."
}

function Set-BranchProtection {
    if ($SkipBranchProtection) {
        Write-Warn "Skipping branch protection."
        return
    }

    Write-Step "Configuring branch protection"

    $encodedBranch = [System.Uri]::EscapeDataString($Branch)
    $uri = "$RepoApiBase/branches/$encodedBranch/protection"

    $body = @{
        required_status_checks = @{
            strict   = $true
            contexts = @($GitleaksCheckName)
        }
        enforce_admins = $true
        required_pull_request_reviews = @{
            required_approving_review_count = $RequiredApprovals
            dismiss_stale_reviews           = $true
            require_code_owner_reviews      = $false
            require_last_push_approval      = $true
        }
        restrictions = $null
        required_linear_history = $true
        allow_force_pushes = $false
        allow_deletions = $false
        block_creations = $false
        required_conversation_resolution = $false
        lock_branch = $false
        allow_fork_syncing = $true
    }

    if ($DryRun) {
        Write-DryRun ("Would configure branch protection for {0}." -f $Branch)
        Write-DryRun ("Would require status check: {0}" -f $GitleaksCheckName)
        Write-DryRun ("Would require approvals: {0}" -f $RequiredApprovals)
        return
    }

    Invoke-GitHub -Method "PUT" -Uri $uri -Body $body | Out-Null
    Write-Ok ("Branch protection configured for {0}." -f $Branch)
}

function Get-BranchSha {
    param([string]$BranchName)

    $encodedBranch = [System.Uri]::EscapeDataString($BranchName)
    $uri = "$RepoApiBase/git/ref/heads/$encodedBranch"
    $ref = Invoke-GitHub -Method "GET" -Uri $uri
    return $ref.object.sha
}

function Test-GitRefExists {
    param([string]$RefName)

    $encodedRef = [System.Uri]::EscapeDataString($RefName).Replace("%2F", "/")
    $uri = "$RepoApiBase/git/ref/$encodedRef"
    $result = Invoke-GitHub -Method "GET" -Uri $uri -Allow404
    return ($null -ne $result)
}

function New-GitRef {
    param(
        [string]$RefName,
        [string]$Sha
    )

    $body = @{
        ref = $RefName
        sha = $Sha
    }

    Invoke-GitHub -Method "POST" -Uri "$RepoApiBase/git/refs" -Body $body | Out-Null
}

function New-TestPullRequest {
    if (-not $CreateTestPullRequest) {
        return
    }

    Write-Step "Creating test branch and draft pull request"

    $testBranch = "pelycon/security-bootstrap-test"
    $testRef = "refs/heads/$testBranch"
    $testFilePath = ".pelycon/security-bootstrap-test.txt"
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss K")

    if ($DryRun) {
        Write-DryRun ("Would create/update branch: {0}" -f $testBranch)
        Write-DryRun ("Would create/update harmless test file: {0}" -f $testFilePath)
        Write-DryRun "Would open a draft pull request back into the protected branch."
        return
    }

    $baseSha = Get-BranchSha -BranchName $Branch

    if (-not (Test-GitRefExists -RefName "heads/$testBranch")) {
        New-GitRef -RefName $testRef -Sha $baseSha
        Write-Ok ("Created test branch: {0}" -f $testBranch)
    }
    else {
        Write-Warn ("Test branch already exists: {0}" -f $testBranch)
    }

    $content = @"
Pelycon security bootstrap test

This harmless file was created to trigger the GitHub Actions security workflow
and make the required Gitleaks status check visible in GitHub.

Created: $timestamp
Repository: $Owner/$Repo
Base branch: $Branch

Do not merge this pull request. Close it after confirming the security check appears.
"@

    $oldBranch = $script:Branch
    $script:Branch = $testBranch

    try {
        Set-RepositoryFile -Path $testFilePath -Content $content -Message "Add Pelycon security bootstrap test file"
    }
    finally {
        $script:Branch = $oldBranch
    }

    $existingPrsUri = "$RepoApiBase/pulls?state=open&head=$Owner`:$testBranch&base=$Branch"
    $existingPrs = Invoke-GitHub -Method "GET" -Uri $existingPrsUri

    if ($existingPrs.Count -gt 0) {
        Write-Warn ("A test pull request already exists: {0}" -f $existingPrs[0].html_url)
        return
    }

    $prBody = @{
        title = "Pelycon security bootstrap test"
        head  = $testBranch
        base  = $Branch
        body  = "This draft PR exists only to trigger the security workflow and confirm the required Gitleaks check appears. Do not merge it. Close it after verification."
        draft = $true
    }

    $pr = Invoke-GitHub -Method "POST" -Uri "$RepoApiBase/pulls" -Body $prBody
    Write-Ok ("Draft test pull request opened: {0}" -f $pr.html_url)
}

function Show-NextSteps {
    Write-Step "Next steps"

    if ($DryRun) {
        Write-Host "This was a dry run. No repository changes were made."
        Write-Host ""
        Write-Host "To apply changes, rerun without -DryRun:"
        Write-Host ("  .\Set-PelyconRepoSecurity.ps1 -Owner `"{0}`" -Repo `"{1}`" -CreateTestPullRequest" -f $Owner, $Repo)
        return
    }

    Write-Host "Check these areas in GitHub:"
    Write-Host ""
    Write-Host "1. Code tab:"
    Write-Host "   - CLAUDE.md"
    Write-Host "   - .gitleaks.toml"
    Write-Host "   - .gitleaksignore"
    Write-Host "   - .github/workflows/security.yml"
    Write-Host ""
    Write-Host "2. Actions tab:"
    Write-Host "   - Confirm the 'security' workflow runs."
    Write-Host "   - Confirm the 'gitleaks' job appears."
    Write-Host ""
    Write-Host "3. Settings -> Branches:"
    Write-Host ("   - Confirm branch protection exists for {0}." -f $Branch)
    Write-Host "   - Confirm pull request review and the gitleaks check are required."
    Write-Host ""
    if ($CreateTestPullRequest) {
        Write-Host "4. Draft test PR:"
        Write-Host "   - Open the draft PR created by the script."
        Write-Host "   - Confirm the gitleaks check appears and passes."
        Write-Host "   - Confirm the PR cannot be merged without approval."
        Write-Host "   - Close the test PR when done. Do not merge it."
    }
    else {
        Write-Host "4. To automatically create a test PR later, rerun with:"
        Write-Host ("   .\Set-PelyconRepoSecurity.ps1 -Owner `"{0}`" -Repo `"{1}`" -SkipFiles -SkipRepoSettings -SkipBranchProtection -CreateTestPullRequest" -f $Owner, $Repo)
    }
}

try {
    Write-Step "Starting Pelycon repository security bootstrap"

    Test-RepositoryAccess
    Set-SecurityFiles
    Set-RepositorySettings
    Set-BranchProtection
    New-TestPullRequest
    Show-NextSteps

    Write-Host ""
    if ($DryRun) {
        Write-Host "DRY RUN COMPLETE" -ForegroundColor Yellow
    }
    else {
        Write-Host "DONE" -ForegroundColor Green
    }
}
catch {
    Write-Host ""
    Write-Host "FAILED" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Common fixes:"
    Write-Host "  - Confirm `$env:GITHUB_TOKEN is set in this PowerShell window."
    Write-Host "  - Confirm the token has Administration, Contents, and Workflows write permissions."
    Write-Host "  - Add Pull requests write permission if using -CreateTestPullRequest."
    Write-Host "  - Confirm -Owner and -Repo match the GitHub URL."
    Write-Host "  - Confirm the branch name with -Branch, for example -Branch `"master`"."
    exit 1
}
