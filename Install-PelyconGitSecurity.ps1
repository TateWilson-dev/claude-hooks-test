<#
Pelycon Device-Level Git Security Bootstrap
Windows PowerShell Script

Purpose:
- Install/configure Git and Gitleaks once per Windows user profile.
- Configure global Git hooks so every repo automatically runs Gitleaks.
- Redact secret values by default so Claude Code does not see the secret in terminal output.

Normal install:
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Install-PelyconGitSecurity.ps1

Optional self-test:
.\Install-PelyconGitSecurity.ps1 -RunSelfTest

Force Gitleaks update:
.\Install-PelyconGitSecurity.ps1 -ForceUpdate

Uninstall hook/Gitleaks setup:
.\Install-PelyconGitSecurity.ps1 -Uninstall

Sandbox/admin-only mode that may show actual secret values:
.\Install-PelyconGitSecurity.ps1 -ShowSecretsInReports
#>

[CmdletBinding()]
param(
    [switch]$SkipGitInstall,
    [switch]$RunSelfTest,
    [switch]$ForceUpdate,
    [switch]$ShowSecretsInReports,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$PelyconRoot = Join-Path $env:LOCALAPPDATA "Pelycon"
$ToolsRoot = Join-Path $PelyconRoot "Tools"
$PortableGitDir = Join-Path $ToolsRoot "PortableGit"
$GitleaksDir = Join-Path $ToolsRoot "gitleaks"
$HooksDir = Join-Path $PelyconRoot "GitHooks"
$LogDir = Join-Path $PelyconRoot "Logs"
$GitleaksExe = Join-Path $GitleaksDir "gitleaks.exe"

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

function Test-Command {
    param([string]$Name)
    return $null -ne (Get-Command $Name -ErrorAction SilentlyContinue)
}

function Download-File {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$OutFile
    )

    if ($PSVersionTable.PSVersion.Major -le 5) {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing
    }
    else {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile
    }
}

function Refresh-CurrentSessionPath {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")

    $extraPaths = @(
        "C:\Program Files\Git\cmd",
        "C:\Program Files\Git\mingw64\bin",
        "C:\Program Files\Git\usr\bin",
        "$env:LOCALAPPDATA\Programs\Git\cmd",
        "$env:LOCALAPPDATA\Programs\Git\mingw64\bin",
        "$env:LOCALAPPDATA\Programs\Git\usr\bin",
        "$PortableGitDir\cmd",
        "$PortableGitDir\mingw64\bin",
        "$PortableGitDir\usr\bin",
        $GitleaksDir
    ) | Where-Object { $_ -and (Test-Path $_) }

    $env:Path = (($extraPaths + ($machinePath -split ";") + ($userPath -split ";")) |
        Where-Object { $_ -and $_.Trim() -ne "" } |
        Select-Object -Unique) -join ";"
}

function Add-DirectoryToUserPath {
    param([string]$Directory)

    if (-not (Test-Path $Directory)) {
        return
    }

    $currentUserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @()

    if (-not [string]::IsNullOrWhiteSpace($currentUserPath)) {
        $parts = $currentUserPath -split ";" | Where-Object { $_ -and $_.Trim() -ne "" }
    }

    $alreadyExists = $false
    foreach ($part in $parts) {
        if ($part.TrimEnd("\") -ieq $Directory.TrimEnd("\")) {
            $alreadyExists = $true
            break
        }
    }

    if (-not $alreadyExists) {
        $newPath = ($parts + $Directory | Select-Object -Unique) -join ";"
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Ok "Added to user PATH: $Directory"
    }
    else {
        Write-Ok "Already in user PATH: $Directory"
    }

    Refresh-CurrentSessionPath
}

function Convert-ToGitShellPath {
    param([string]$WindowsPath)

    $p = $WindowsPath -replace "\\", "/"

    if ($p -match "^([A-Za-z]):/(.*)$") {
        $drive = $matches[1].ToLower()
        $rest = $matches[2]
        return "/$drive/$rest"
    }

    return $p
}

function Convert-ToGitConfigPath {
    param([string]$WindowsPath)
    return ($WindowsPath -replace "\\", "/")
}

function Invoke-GitHubApi {
    param([string]$Uri)

    $headers = @{
        "User-Agent" = "Pelycon-Git-Security-Bootstrap"
        "Accept"     = "application/vnd.github+json"
    }

    return Invoke-RestMethod -Uri $Uri -Headers $headers
}

function Install-GitIfMissing {
    Write-Step "Checking Git"
    Refresh-CurrentSessionPath

    if (Test-Command "git.exe") {
        Write-Ok "Git is already installed."
        git --version
        return
    }

    if ($SkipGitInstall) {
        throw "Git is not installed and -SkipGitInstall was used."
    }

    Write-Warn "Git was not found. Downloading PortableGit directly from GitHub."
    Write-Warn "This avoids winget and avoids requiring admin rights for Git."

    $release = Invoke-GitHubApi -Uri "https://api.github.com/repos/git-for-windows/git/releases/latest"
    $asset = $release.assets |
        Where-Object { $_.name -match "^PortableGit-.*-64-bit\.7z\.exe$" } |
        Select-Object -First 1

    if (-not $asset) {
        throw "Could not find the latest 64-bit PortableGit release asset from GitHub."
    }

    New-Item -ItemType Directory -Force -Path $ToolsRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

    if (Test-Path $PortableGitDir) {
        Write-Warn "Removing old PortableGit folder before reinstalling."
        Remove-Item -Path $PortableGitDir -Recurse -Force
    }

    New-Item -ItemType Directory -Force -Path $PortableGitDir | Out-Null

    $installerPath = Join-Path $env:TEMP $asset.name
    Write-Host "Downloading $($asset.name)..."
    Download-File -Uri $asset.browser_download_url -OutFile $installerPath

    Write-Host "Extracting PortableGit to $PortableGitDir ..."
    $extractArg = "-o`"$PortableGitDir`""
    $process = Start-Process -FilePath $installerPath -ArgumentList @("-y", $extractArg) -Wait -PassThru

    if ($process.ExitCode -ne 0) {
        throw "PortableGit extraction exited with code $($process.ExitCode)."
    }

    Add-DirectoryToUserPath -Directory (Join-Path $PortableGitDir "cmd")
    Add-DirectoryToUserPath -Directory (Join-Path $PortableGitDir "mingw64\bin")
    Add-DirectoryToUserPath -Directory (Join-Path $PortableGitDir "usr\bin")
    Refresh-CurrentSessionPath

    if (-not (Test-Command "git.exe")) {
        throw "PortableGit was extracted, but git.exe is still not available. Close and reopen PowerShell, then rerun this script."
    }

    Write-Ok "PortableGit installed successfully."
    git --version
}

function Get-WindowsArchitectureForGitleaks {
    $archText = "$env:PROCESSOR_ARCHITECTURE $env:PROCESSOR_ARCHITEW6432"

    if ($archText -match "ARM64") {
        return "arm64"
    }

    return "x64"
}

function Install-Gitleaks {
    Write-Step "Checking Gitleaks"
    New-Item -ItemType Directory -Force -Path $GitleaksDir | Out-Null

    if ((Test-Path $GitleaksExe) -and (-not $ForceUpdate)) {
        try {
            Write-Ok "Gitleaks is already installed. Skipping download."
            & $GitleaksExe version
            Add-DirectoryToUserPath -Directory $GitleaksDir
            Refresh-CurrentSessionPath
            return
        }
        catch {
            Write-Warn "Existing Gitleaks copy appears broken. Re-downloading."
        }
    }

    Write-Step "Installing Gitleaks"
    $arch = Get-WindowsArchitectureForGitleaks
    Write-Host "Detected Windows architecture: $arch"

    $release = Invoke-GitHubApi -Uri "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
    $assetPattern = "gitleaks_.*_windows_$arch\.zip$"

    $asset = $release.assets |
        Where-Object { $_.name -match $assetPattern } |
        Select-Object -First 1

    if (-not $asset) {
        throw "Could not find a Gitleaks Windows $arch release asset."
    }

    $zipPath = Join-Path $env:TEMP $asset.name
    $extractDir = Join-Path $env:TEMP ("gitleaks-" + [guid]::NewGuid().ToString())

    Write-Host "Downloading $($asset.name)..."
    Download-File -Uri $asset.browser_download_url -OutFile $zipPath

    Write-Host "Extracting Gitleaks..."
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    $downloadedExe = Get-ChildItem -Path $extractDir -Filter "gitleaks.exe" -Recurse | Select-Object -First 1

    if (-not $downloadedExe) {
        throw "Could not find gitleaks.exe inside the downloaded ZIP."
    }

    Copy-Item -Path $downloadedExe.FullName -Destination $GitleaksExe -Force
    $release.tag_name | Set-Content -Path (Join-Path $GitleaksDir "version.txt") -Encoding UTF8

    Add-DirectoryToUserPath -Directory $GitleaksDir
    Refresh-CurrentSessionPath

    Write-Ok "Gitleaks installed to $GitleaksExe"
    & $GitleaksExe version
}

function Write-GlobalGitHooks {
    Write-Step "Creating global Git hooks"
    New-Item -ItemType Directory -Force -Path $HooksDir | Out-Null

    $gitleaksShellPath = Convert-ToGitShellPath -WindowsPath $GitleaksExe
    $showSecretsValue = "false"
    $redactText = "--redact"

    if ($ShowSecretsInReports) {
        $showSecretsValue = "true"
        $redactText = ""
        Write-Warn "ShowSecretsInReports is enabled. Secret values may be printed in terminal output."
        Write-Warn "Do not use this mode with Claude Code or normal users."
    }

    $preCommit = @'
#!/bin/sh
set -u

GL="__GITLEAKS_PATH__"
SHOW_SECRETS="__SHOW_SECRETS__"
REDACT_FLAG="__REDACT_FLAG__"

if [ ! -x "$GL" ]; then
  echo ""
  echo "Pelycon Git Security: Gitleaks was not found at:"
  echo "  $GL"
  echo "Rerun Install-PelyconGitSecurity.ps1."
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  exit 0
fi

echo "Pelycon Git Security: running Gitleaks pre-commit scan..."

if [ -n "$REDACT_FLAG" ]; then
  "$GL" git --pre-commit --staged --redact --no-banner --exit-code 1
else
  "$GL" git --pre-commit --staged --no-banner --exit-code 1
fi

STATUS=$?

if [ "$STATUS" -ne 0 ]; then
  echo ""
  echo "------------------------------------------------------------"
  echo "Pelycon Git Security: COMMIT BLOCKED"
  echo "------------------------------------------------------------"
  echo "Gitleaks found a possible secret in the staged changes."
  echo "Review the Gitleaks output above for the file, line, rule, and fingerprint."
  if [ "$SHOW_SECRETS" = "true" ]; then
    echo "WARNING: secret-display mode is enabled. The output above may include the actual secret value."
  else
    echo "Secret values are redacted by default so they are not exposed to Claude Code, logs, or screenshots."
  fi
  echo ""
  echo "Fix steps:"
  echo "  1. Remove the secret from the listed file."
  echo "  2. Put the value in an approved secret store such as Azure Key Vault or GitHub Secrets."
  echo "  3. If it was a real secret, rotate/revoke it."
  echo "  4. Stage the cleaned file and commit again."
  echo ""
  echo "Do not bypass this with --no-verify unless a Pelycon administrator approves it."
  exit "$STATUS"
fi

exit 0
'@

    $prePush = @'
#!/bin/sh
set -u

GL="__GITLEAKS_PATH__"
SHOW_SECRETS="__SHOW_SECRETS__"
REDACT_FLAG="__REDACT_FLAG__"

if [ ! -x "$GL" ]; then
  echo ""
  echo "Pelycon Git Security: Gitleaks was not found at:"
  echo "  $GL"
  echo "Rerun Install-PelyconGitSecurity.ps1."
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  exit 0
fi

ROOT="$(git rev-parse --show-toplevel)"

echo "Pelycon Git Security: running Gitleaks pre-push scan..."

if [ -n "$REDACT_FLAG" ]; then
  "$GL" git --redact --no-banner --exit-code 1 "$ROOT"
else
  "$GL" git --no-banner --exit-code 1 "$ROOT"
fi

STATUS=$?

if [ "$STATUS" -ne 0 ]; then
  echo ""
  echo "------------------------------------------------------------"
  echo "Pelycon Git Security: PUSH BLOCKED"
  echo "------------------------------------------------------------"
  echo "Gitleaks found a possible secret in this repository/history."
  echo "Review the Gitleaks output above for the file, line, rule, and fingerprint."
  if [ "$SHOW_SECRETS" = "true" ]; then
    echo "WARNING: secret-display mode is enabled. The output above may include the actual secret value."
  else
    echo "Secret values are redacted by default so they are not exposed to Claude Code, logs, or screenshots."
  fi
  echo ""
  echo "Fix steps:"
  echo "  1. Remove the secret from the listed file/history."
  echo "  2. Put the value in an approved secret store such as Azure Key Vault or GitHub Secrets."
  echo "  3. If it was a real secret, rotate/revoke it."
  echo "  4. Commit the cleaned change and push again."
  echo ""
  echo "Do not bypass this with --no-verify unless a Pelycon administrator approves it."
  exit "$STATUS"
fi

exit 0
'@

    $preCommit = $preCommit.Replace("__GITLEAKS_PATH__", $gitleaksShellPath)
    $preCommit = $preCommit.Replace("__SHOW_SECRETS__", $showSecretsValue)
    $preCommit = $preCommit.Replace("__REDACT_FLAG__", $redactText)

    $prePush = $prePush.Replace("__GITLEAKS_PATH__", $gitleaksShellPath)
    $prePush = $prePush.Replace("__SHOW_SECRETS__", $showSecretsValue)
    $prePush = $prePush.Replace("__REDACT_FLAG__", $redactText)

    Set-Content -Path (Join-Path $HooksDir "pre-commit") -Value $preCommit -Encoding ASCII
    Set-Content -Path (Join-Path $HooksDir "pre-push") -Value $prePush -Encoding ASCII

    $hooksGitConfigPath = Convert-ToGitConfigPath -WindowsPath $HooksDir
    $existingHooksPath = $null

    try {
        $existingHooksPath = git config --global --get core.hooksPath
    }
    catch {
        $existingHooksPath = $null
    }

    if (-not [string]::IsNullOrWhiteSpace($existingHooksPath) -and ($existingHooksPath -ne $hooksGitConfigPath)) {
        Write-Warn "Existing global core.hooksPath will be replaced."
        Write-Warn "Old: $existingHooksPath"
        Write-Warn "New: $hooksGitConfigPath"
    }

    git config --global core.hooksPath "$hooksGitConfigPath"

    Write-Ok "Global Git hooks written to $HooksDir"
    Write-Ok "Git global core.hooksPath set to $hooksGitConfigPath"
}

function Test-Installation {
    Write-Step "Verifying installation"

    Refresh-CurrentSessionPath

    if (-not (Test-Command "git.exe")) {
        throw "Git is not available."
    }

    if (-not (Test-Path $GitleaksExe)) {
        throw "Gitleaks is not installed at $GitleaksExe"
    }

    $configuredHooks = git config --global --get core.hooksPath

    if ([string]::IsNullOrWhiteSpace($configuredHooks)) {
        throw "Git global core.hooksPath is not configured."
    }

    Write-Ok "Git version:"
    git --version

    Write-Ok "Gitleaks version:"
    & $GitleaksExe version

    Write-Ok "Global hooks path:"
    Write-Host $configuredHooks

    if ($ShowSecretsInReports) {
        Write-Warn "Secret values may be shown because -ShowSecretsInReports is enabled."
    }
    else {
        Write-Ok "Secret values are redacted by default."
    }

    Write-Ok "Device-level Git security bootstrap is installed."
}

function Run-SelfTest {
    Write-Step "Running optional self-test"

    $testRoot = Join-Path $env:TEMP ("pelycon-gitleaks-selftest-" + [guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Force -Path $testRoot | Out-Null

    Push-Location $testRoot

    try {
        git init | Out-Null
        git config user.email "security-test@example.com"
        git config user.name "Pelycon Security Test"

        "hello" | Set-Content -Path "ok.txt" -Encoding UTF8
        git add ok.txt

        Write-Host ""
        Write-Host "Self-test step 1: committing a clean file. This should succeed." -ForegroundColor Cyan
        git commit -m "clean test"

        if ($LASTEXITCODE -ne 0) {
            throw "Self-test stopped: clean commit failed. The hook may be misconfigured."
        }

@"
GITHUB_TOKEN=ghp_1234567890abcdefghijABCDEFGHIJ123456
AZURE_CLIENT_SECRET=Ab78Q~zK4mP9xQ2wL7vR3nT8sB6yD1fG5hJ0cA
"@ | Set-Content -Path "secret-test.txt" -Encoding UTF8

        git add secret-test.txt

        Write-Host ""
        Write-Host "Self-test step 2: committing fake secrets. This should be blocked by Gitleaks." -ForegroundColor Cyan
        git commit -m "secret test should be blocked"

        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            throw "Self-test failed: the fake secret commit was not blocked."
        }

        Write-Host ""
        Write-Host "Self-test result:" -ForegroundColor Yellow
        Write-Host "The second commit was blocked because fake secrets were detected." -ForegroundColor Yellow
        Write-Host "That is the expected result for the self-test." -ForegroundColor Yellow
        Write-Host "For real work, the user should remove the listed secret and commit again." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Test repo location:"
        Write-Host "  $testRoot"
    }
    finally {
        Pop-Location
    }
}

function Uninstall-PelyconGitSecurity {
    Write-Step "Uninstalling Pelycon Git security bootstrap"
    Refresh-CurrentSessionPath

    if (Test-Command "git.exe") {
        $configuredHooks = $null

        try {
            $configuredHooks = git config --global --get core.hooksPath
        }
        catch {
            $configuredHooks = $null
        }

        $expectedHooksPath = Convert-ToGitConfigPath -WindowsPath $HooksDir

        if ($configuredHooks -eq $expectedHooksPath) {
            git config --global --unset core.hooksPath
            Write-Ok "Removed global Git core.hooksPath."
        }
        elseif (-not [string]::IsNullOrWhiteSpace($configuredHooks)) {
            Write-Warn "Global core.hooksPath is set to a different path, so it was not removed:"
            Write-Warn $configuredHooks
        }
    }

    if (Test-Path $HooksDir) {
        Remove-Item -Path $HooksDir -Recurse -Force
        Write-Ok "Removed Pelycon Git hooks folder."
    }

    if (Test-Path $GitleaksDir) {
        Remove-Item -Path $GitleaksDir -Recurse -Force
        Write-Ok "Removed Pelycon Gitleaks folder."
    }

    Write-Ok "Uninstall complete. Git itself was not removed."
}

try {
    if ($Uninstall) {
        Uninstall-PelyconGitSecurity
        exit 0
    }

    Write-Step "Starting Pelycon device-level Git security bootstrap"

    New-Item -ItemType Directory -Force -Path $PelyconRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $ToolsRoot | Out-Null
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

    Install-GitIfMissing
    Install-Gitleaks
    Write-GlobalGitHooks
    Test-Installation

    if ($RunSelfTest) {
        Run-SelfTest
    }

    Write-Host ""
    Write-Host "DONE" -ForegroundColor Green
    Write-Host "This device is now configured for Pelycon Git secret scanning." -ForegroundColor Green
    Write-Host ""
    Write-Host "What this means:"
    Write-Host "  - Every Git commit on this Windows profile runs Gitleaks."
    Write-Host "  - Every Git push on this Windows profile runs Gitleaks."
    Write-Host "  - This applies to every repo because Git global core.hooksPath is configured."
    Write-Host "  - Secret values are redacted by default."
    Write-Host ""
    Write-Host "Recommended next step:"
    Write-Host "  Close and reopen PowerShell, Git Bash, and Claude Code so they reload PATH."
    Write-Host ""
    Write-Host "Optional test command:"
    Write-Host "  .\Install-PelyconGitSecurity.ps1 -RunSelfTest"
}
catch {
    Write-Host ""
    Write-Host "FAILED" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Try closing and reopening PowerShell, then rerun the script."
    exit 1
}
