<#
Set-PelyconRepoSecurity.ps1

Pelycon GitHub Repository Security Bootstrap

What this script configures:
1. Adds/updates CLAUDE.md.
2. Adds/updates .gitleaks.toml.
3. Adds/updates .gitleaksignore.
4. Adds/updates .github/workflows/security.yml.
5. Configures safe repository merge settings.
6. Protects the default branch with:
   - Pull request required before merge
   - Required approval count
   - Dismiss stale approvals
   - Require approval of most recent push
   - Require status check named "gitleaks"
   - Block force pushes
   - Block branch deletion
   - Require linear history

Token requirements:
- Fine-grained PAT:
  - Repository Administration: Read and write
  - Repository Contents: Read and write
  - Repository Workflows: Read and write
- Classic PAT:
  - repo
  - workflow

Example:
$env:GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxx"
.\Set-PelyconRepoSecurity.ps1 -Owner "PelyconTechnologies" -Repo "client-app"

Dry run:
.\Set-PelyconRepoSecurity.ps1 -Owner "PelyconTechnologies" -Repo "client-app" -DryRun

Notes:
- Run this before the branch is locked down when possible.
- If the branch is already protected, committing files directly to the protected branch may fail. In that case, add the files through a PR first, then rerun this script with -SkipFiles.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Owner,

    [Parameter(Mandatory = $true)]
    [string]$Repo,

    [string]$Branch = "main",

    [ValidateRange(1,6)]
    [int]$RequiredApprovals = 1,

    [string]$RequiredCheckName = "gitleaks",

    [string]$GitHubToken = $env:GITHUB_TOKEN,

    [string]$ApiVersion = "2022-11-28",

    [switch]$SkipFiles,
    [switch]$SkipRepoSettings,
    [switch]$SkipBranchProtection,
    [switch]$EnableGitHubSecretScanningIfAvailable,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

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

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Gray
}

function Test-Token {
    if ([string]::IsNullOrWhiteSpace($GitHubToken)) {
        throw "No GitHub token found. Set `$env:GITHUB_TOKEN or pass -GitHubToken."
    }
}

function ConvertTo-JsonBody {
    param([object]$Body)

    if ($null -eq $Body) {
        return $null
    }

    return ($Body | ConvertTo-Json -Depth 50)
}

function Invoke-GitHubApi {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("GET","POST","PUT","PATCH","DELETE")]
        [string]$Method,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [object]$Body = $null,

        [switch]$Allow404
    )

    Test-Token

    $headers = @{
        "Accept"               = "application/vnd.github+json"
        "Authorization"        = "Bearer $GitHubToken"
        "X-GitHub-Api-Version" = $ApiVersion
        "User-Agent"           = "Pelycon-Repo-Security-Bootstrap"
    }

    $uri = "https://api.github.com$Path"
    $jsonBody = ConvertTo-JsonBody -Body $Body

    if ($DryRun -and $Method -ne "GET") {
        Write-Host ""
        Write-Host "[DRY RUN] $Method $uri" -ForegroundColor Yellow
        if ($null -ne $Body) {
            Write-Host $jsonBody
        }
        return $null
    }

    try {
        if ($null -ne $Body) {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -Body $jsonBody -ContentType "application/json"
        }
        else {
            return Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
        }
    }
    catch {
        $response = $_.Exception.Response

        if ($Allow404 -and $null -ne $response -and [int]$response.StatusCode -eq 404) {
            return $null
        }

        $message = $_.Exception.Message

        try {
            $reader = New-Object System.IO.StreamReader($response.GetResponseStream())
            $bodyText = $reader.ReadToEnd()
            if (-not [string]::IsNullOrWhiteSpace($bodyText)) {
                $message = "$message`nGitHub response:`n$bodyText"
            }
        }
        catch {
            # Ignore response-body parsing errors.
        }

        throw $message
    }
}

function Get-RepoInfo {
    Write-Step "Checking repository"

    $repoInfo = Invoke-GitHubApi -Method GET -Path "/repos/$Owner/$Repo"

    Write-Ok "Repository found: $($repoInfo.full_name)"
    Write-Info "Default branch reported by GitHub: $($repoInfo.default_branch)"

    if ([string]::IsNullOrWhiteSpace($Branch)) {
        $script:Branch = $repoInfo.default_branch
    }

    return $repoInfo
}

function ConvertTo-GitHubContentBase64 {
    param([string]$Content)

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
    return [Convert]::ToBase64String($bytes)
}

function ConvertTo-GitHubPath {
    param([string]$Path)

    # Keep slashes as path separators, but URL-encode each segment.
    $parts = $Path -split "/"
    $encodedParts = foreach ($part in $parts) {
        [System.Uri]::EscapeDataString($part)
    }

    return ($encodedParts -join "/")
}

function Set-RepositoryFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [string]$CommitMessage
    )

    $encodedPath = ConvertTo-GitHubPath -Path $Path
    $existing = Invoke-GitHubApi -Method GET -Path "/repos/$Owner/$Repo/contents/$encodedPath?ref=$Branch" -Allow404

    $body = @{
        message = $CommitMessage
        content = ConvertTo-GitHubContentBase64 -Content $Content
        branch  = $Branch
    }

    if ($null -ne $existing -and $existing.sha) {
        $body.sha = $existing.sha
        Write-Info "Updating $Path"
    }
    else {
        Write-Info "Creating $Path"
    }

    Invoke-GitHubApi -Method PUT -Path "/repos/$Owner/$Repo/contents/$encodedPath" -Body $body | Out-Null
    Write-Ok "$Path committed to $Branch"
}

function Get-ClaudeMd {
@"
# CLAUDE.md — Pelycon Secure Vibe Coding Rules

This repository follows Pelycon's secure vibe-coding workflow. These rules apply to Claude Code and to human contributors.

## Security Rules

- Never hardcode secrets, passwords, tokens, API keys, client secrets, private keys, or production connection strings.
- Use approved secret storage such as GitHub Actions secrets, Azure Key Vault, environment variables, or the project's approved secret-management method.
- Treat client data, regulated data, internal security data, and credentials as sensitive.
- Do not weaken authentication, authorization, tenant isolation, logging, or audit controls without explicit approval.
- Flag any request that would weaken these rules instead of silently implementing it.

## Workflow Rules

- Work on a feature branch.
- Do not commit directly to `main` or the default branch.
- Open a pull request for review before merging.
- Do not approve your own pull request.
- Do not bypass required checks, branch protection, rulesets, or review requirements.
- Change this file only through a pull request.

## Secret Scanning Requirement

This repository requires Gitleaks secret scanning before code is committed, pushed, or merged.

Claude must follow this workflow:

1. Before committing, verify Gitleaks is available:

   ```bash
   gitleaks version
   ```

2. Before committing, run a staged secret scan:

   ```bash
   gitleaks git --pre-commit --staged --redact --no-banner --exit-code 1
   ```

3. Before pushing, run a repository secret scan:

   ```bash
   gitleaks git --redact --no-banner --exit-code 1 .
   ```

4. If Gitleaks finds a secret, stop immediately. Do not commit, push, bypass, ignore, or remove the finding without fixing the secret exposure.

5. Do not use `--no-verify`, skip hooks, disable Gitleaks, change `core.hooksPath`, or bypass checks unless a Pelycon administrator explicitly approves it.

6. If a finding appears to be a false positive, document it and request review before adding anything to `.gitleaksignore`.

The local device-level Pelycon Git Security bootstrap should also run Gitleaks automatically through global Git hooks. The GitHub Actions workflow is the server-side backstop.
"@
}

function Get-GitleaksToml {
@"
title = "Pelycon Gitleaks Configuration"

[extend]
useDefault = true
"@
}

function Get-GitleaksIgnore {
@"
# Approved false-positive fingerprints can go here after review.
# Do not use this file to hide real secrets.
"@
}

function Get-SecurityWorkflow {
@"
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
          docker run --rm -v "`$PWD:/repo"
          ghcr.io/gitleaks/gitleaks:latest git /repo
          --redact --no-banner --exit-code 1
"@
}

function Set-StandardFiles {
    Write-Step "Creating/updating repository security files"

    Set-RepositoryFile `
        -Path "CLAUDE.md" `
        -Content (Get-ClaudeMd) `
        -CommitMessage "Add Pelycon Claude security rules"

    Set-RepositoryFile `
        -Path ".gitleaks.toml" `
        -Content (Get-GitleaksToml) `
        -CommitMessage "Add Gitleaks configuration"

    Set-RepositoryFile `
        -Path ".gitleaksignore" `
        -Content (Get-GitleaksIgnore) `
        -CommitMessage "Add Gitleaks ignore file"

    Set-RepositoryFile `
        -Path ".github/workflows/security.yml" `
        -Content (Get-SecurityWorkflow) `
        -CommitMessage "Add Pelycon security workflow"
}

function Set-RepositorySettings {
    Write-Step "Configuring repository settings"

    $body = @{
        allow_squash_merge     = $true
        allow_merge_commit     = $false
        allow_rebase_merge     = $false
        allow_auto_merge       = $false
        delete_branch_on_merge = $true
        allow_update_branch    = $true
    }

    Invoke-GitHubApi -Method PATCH -Path "/repos/$Owner/$Repo" -Body $body | Out-Null

    Write-Ok "Repository merge settings configured:"
    Write-Host "  - Squash merge: enabled"
    Write-Host "  - Merge commits: disabled"
    Write-Host "  - Rebase merge: disabled"
    Write-Host "  - Auto-delete head branches: enabled"
}

function Enable-SecretScanningIfAvailable {
    if (-not $EnableGitHubSecretScanningIfAvailable) {
        return
    }

    Write-Step "Attempting to enable GitHub native secret scanning / push protection"

    $body = @{
        security_and_analysis = @{
            secret_scanning = @{
                status = "enabled"
            }
            secret_scanning_push_protection = @{
                status = "enabled"
            }
        }
    }

    try {
        Invoke-GitHubApi -Method PATCH -Path "/repos/$Owner/$Repo" -Body $body | Out-Null
        Write-Ok "GitHub native secret scanning/push protection enabled or already enabled."
    }
    catch {
        Write-Warn "Could not enable GitHub native secret scanning/push protection."
        Write-Warn "This is usually licensing/plan/organization-policy related. Gitleaks workflow still protects the repo."
        Write-Warn $_.Exception.Message
    }
}

function Set-BranchProtection {
    Write-Step "Configuring branch protection on $Branch"

    $body = @{
        required_status_checks = @{
            strict   = $true
            contexts = @($RequiredCheckName)
        }
        enforce_admins = $true
        required_pull_request_reviews = @{
            dismissal_restrictions = @{}
            dismiss_stale_reviews = $true
            require_code_owner_reviews = $false
            required_approving_review_count = $RequiredApprovals
            require_last_push_approval = $true
            bypass_pull_request_allowances = @{}
        }
        restrictions = $null
        required_linear_history = $true
        allow_force_pushes = $false
        allow_deletions = $false
        block_creations = $false
        required_conversation_resolution = $true
        lock_branch = $false
        allow_fork_syncing = $false
    }

    Invoke-GitHubApi -Method PUT -Path "/repos/$Owner/$Repo/branches/$Branch/protection" -Body $body | Out-Null

    Write-Ok "Branch protection configured for $Branch:"
    Write-Host "  - Pull request required"
    Write-Host "  - Required approvals: $RequiredApprovals"
    Write-Host "  - Most recent push must be approved by someone else"
    Write-Host "  - Stale approvals dismissed on new commits"
    Write-Host "  - Required status check: $RequiredCheckName"
    Write-Host "  - Force pushes blocked"
    Write-Host "  - Branch deletion blocked"
    Write-Host "  - Linear history required"
}

function Show-Summary {
    Write-Step "Summary"

    Write-Host "Repository:"
    Write-Host "  https://github.com/$Owner/$Repo"
    Write-Host ""
    Write-Host "Branch protected:"
    Write-Host "  $Branch"
    Write-Host ""
    Write-Host "Required status check:"
    Write-Host "  $RequiredCheckName"
    Write-Host ""
    Write-Host "Important next step:"
    Write-Host "  Push a test branch or open a pull request so the 'gitleaks' check appears in GitHub."
    Write-Host ""
    Write-Host "Recommended validation:"
    Write-Host "  1. Create a branch."
    Write-Host "  2. Add a fake test secret."
    Write-Host "  3. Open a PR."
    Write-Host "  4. Confirm the gitleaks check fails."
    Write-Host "  5. Remove the fake secret."
    Write-Host "  6. Confirm the gitleaks check passes."
    Write-Host "  7. Confirm the PR requires another approver before merge."
}

try {
    Write-Step "Starting Pelycon GitHub repository security bootstrap"

    Test-Token
    Get-RepoInfo | Out-Null

    if (-not $SkipFiles) {
        Set-StandardFiles
    }
    else {
        Write-Warn "Skipping repository file creation/update because -SkipFiles was used."
    }

    if (-not $SkipRepoSettings) {
        Set-RepositorySettings
        Enable-SecretScanningIfAvailable
    }
    else {
        Write-Warn "Skipping repository settings because -SkipRepoSettings was used."
    }

    if (-not $SkipBranchProtection) {
        Set-BranchProtection
    }
    else {
        Write-Warn "Skipping branch protection because -SkipBranchProtection was used."
    }

    Show-Summary

    Write-Host ""
    Write-Host "DONE" -ForegroundColor Green
}
catch {
    Write-Host ""
    Write-Host "FAILED" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Common fixes:"
    Write-Host "  - Make sure the token has Administration: write, Contents: write, and Workflows: write."
    Write-Host "  - If the branch is already protected, run with -SkipFiles after adding files through a PR."
    Write-Host "  - Make sure the branch name exists. Try -Branch main or -Branch master."
    exit 1
}
