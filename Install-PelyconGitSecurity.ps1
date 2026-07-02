<#
Pelycon Device-Level Git Security Bootstrap
Windows PowerShell script

What this does:
1. Checks whether Git is installed.
2. If Git is missing, downloads Git for Windows directly from GitHub and installs it.
3. Downloads the latest Gitleaks Windows release directly from GitHub.
4. Installs Gitleaks to the user's local AppData folder.
5. Creates global Git pre-commit and pre-push hooks.
6. Sets Git's global core.hooksPath so every repo uses those hooks automatically.
7. Adds Gitleaks to the user's PATH.
8. Optionally runs a self-test with a fake secret.

Normal user command:
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Install-PelyconGitSecurity.ps1

Optional self-test:
.\Install-PelyconGitSecurity.ps1 -RunSelfTest

Uninstall:
.\Install-PelyconGitSecurity.ps1 -Uninstall
#>

[CmdletBinding()]
param(
    [switch]$SkipGitInstall,
    [switch]$RunSelfTest,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

# GitHub requires modern TLS.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$PelyconRoot = Join-Path $env:LOCALAPPDATA "Pelycon"
$ToolsRoot = Join-Path $PelyconRoot "Tools"
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

    if ([string]::IsNullOrWhiteSpace($currentUserPath)) {
        [Environment]::SetEnvironmentVariable("Path", $Directory, "User")
        Refresh-CurrentSessionPath
        return
    }

    $parts = $currentUserPath -split ";" | Where-Object { $_ -and $_.Trim() -ne "" }

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
        Refresh-CurrentSessionPath
        Write-Ok "Added Gitleaks folder to the user's PATH."
    }
    else {
        Write-Ok "Gitleaks folder is already in the user's PATH."
    }
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

    Write-Warn "Git was not found. Downloading Git for Windows directly from GitHub..."

    $release = Invoke-GitHubApi -Uri "https://api.github.com/repos/git-for-windows/git/releases/latest"

    $asset = $release.assets |
        Where-Object { $_.name -match "^Git-.*-64-bit\.exe$" } |
        Select-Object -First 1

    if (-not $asset) {
        throw "Could not find the latest 64-bit Git for Windows installer from GitHub."
    }

    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

    $installerPath = Join-Path $env:TEMP $asset.name

    Write-Host "Downloading $($asset.name)..."
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $installerPath

    Write-Host "Installing Git for Windows silently..."
    $gitArgs = @(
        "/VERYSILENT",
        "/NORESTART",
        "/NOCANCEL",
        "/SP-",
        "/CLOSEAPPLICATIONS",
        "/RESTARTAPPLICATIONS",
        "/LOG=`"$LogDir\git-install.log`""
    )

    $process = Start-Process `
        -FilePath $installerPath `
        -ArgumentList $gitArgs `
        -Wait `
        -PassThru

    if ($process.ExitCode -ne 0) {
        throw "Git installer exited with code $($process.ExitCode). Check $LogDir\git-install.log."
    }

    Refresh-CurrentSessionPath

    if (-not (Test-Command "git.exe")) {
        throw "Git installed, but this PowerShell window cannot see it yet. Close and reopen PowerShell, then rerun this script."
    }

    Write-Ok "Git installed successfully."
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
    Write-Step "Installing Gitleaks"

    New-Item -ItemType Directory -Force -Path $GitleaksDir | Out-Null

    $arch = Get-WindowsArchitectureForGitleaks

    Write-Host "Detected Windows architecture: $arch"
    Write-Host "Checking latest Gitleaks release..."

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
    Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zipPath

    Write-Host "Extracting Gitleaks..."
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force

    $downloadedExe = Get-ChildItem -Path $extractDir -Filter "gitleaks.exe" -Recurse |
        Select-Object -First 1

    if (-not $downloadedExe) {
        throw "Could not find gitleaks.exe inside the downloaded ZIP."
    }

    Copy-Item -Path $downloadedExe.FullName -Destination $GitleaksExe -Force

    $versionFile = Join-Path $GitleaksDir "version.txt"
    $release.tag_name | Set-Content -Path $versionFile -Encoding UTF8

    Add-DirectoryToUserPath -Directory $GitleaksDir
    Refresh-CurrentSessionPath

    if (-not (Test-Path $GitleaksExe)) {
        throw "Gitleaks installation failed. Expected file missing: $GitleaksExe"
    }

    Write-Ok "Gitleaks installed to $GitleaksExe"
    & $GitleaksExe version
}

function Write-GlobalGitHooks {
    Write-Step "Creating global Git hooks"

    New-Item -ItemType Directory -Force -Path $HooksDir | Out-Null

    $gitleaksShellPath = Convert-ToGitShellPath -WindowsPath $GitleaksExe

    $preCommit = @'
#!/bin/sh
set -eu

GL="__GITLEAKS_PATH__"

if [ ! -x "$GL" ]; then
  echo "Pelycon Git Security: Gitleaks was not found at $GL"
  echo "Rerun Install-PelyconGitSecurity.ps1."
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  exit 0
fi

echo "Pelycon Git Security: running Gitleaks pre-commit scan..."
"$GL" git --pre-commit --staged --redact --no-banner --exit-code 1
'@

    $prePush = @'
#!/bin/sh
set -eu

GL="__GITLEAKS_PATH__"

if [ ! -x "$GL" ]; then
  echo "Pelycon Git Security: Gitleaks was not found at $GL"
  echo "Rerun Install-PelyconGitSecurity.ps1."
  exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  exit 0
fi

ROOT="$(git rev-parse --show-toplevel)"

echo "Pelycon Git Security: running Gitleaks pre-push scan..."
"$GL" git --redact --no-banner --exit-code 1 "$ROOT"
'@

    $preCommit = $preCommit.Replace("__GITLEAKS_PATH__", $gitleaksShellPath)
    $prePush = $prePush.Replace("__GITLEAKS_PATH__", $gitleaksShellPath)

    $preCommitPath = Join-Path $HooksDir "pre-commit"
    $prePushPath = Join-Path $HooksDir "pre-push"

    Set-Content -Path $preCommitPath -Value $preCommit -Encoding ASCII
    Set-Content -Path $prePushPath -Value $prePush -Encoding ASCII

    $hooksGitConfigPath = Convert-ToGitConfigPath -WindowsPath $HooksDir

    $existingHooksPath = $null
    try {
        $existingHooksPath = git config --global --get core.hooksPath
    }
    catch {
        $existingHooksPath = $null
    }

    if (-not [string]::IsNullOrWhiteSpace($existingHooksPath) -and ($existingHooksPath -ne $hooksGitConfigPath)) {
        Write-Warn "Existing global core.hooksPath will be replaced:"
        Write-Warn "Old: $existingHooksPath"
        Write-Warn "New: $hooksGitConfigPath"
    }

    git config --global core.hooksPath "$hooksGitConfigPath"

    Write-Ok "Global Git hooks written to $HooksDir"
    Write-Ok "Git global core.hooksPath set to $hooksGitConfigPath"
}

function Test-Installation {
    Write-Step "Verifying installation"

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
        git commit -m "clean test" | Out-Host

        if ($LASTEXITCODE -ne 0) {
            throw "Clean commit failed during self-test."
        }

        @"
GITHUB_TOKEN=ghp_1234567890abcdefghijABCDEFGHIJ123456
AZURE_CLIENT_SECRET=Ab78Q~zK4mP9xQ2wL7vR3nT8sB6yD1fG5hJ0cA
"@ | Set-Content -Path "secret-test.txt" -Encoding UTF8

        git add secret-test.txt

        $outputFile = Join-Path $testRoot "blocked-output.txt"

        git commit -m "secret test should fail" *> $outputFile
        $exitCode = $LASTEXITCODE

        if ($exitCode -eq 0) {
            throw "Self-test failed: the secret commit was not blocked."
        }

        Write-Ok "Self-test passed. The fake secret commit was blocked."
        Write-Host "Self-test output saved to: $outputFile"
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
    Write-Host "  - Every Git commit on this device runs Gitleaks."
    Write-Host "  - Every Git push on this device runs Gitleaks."
    Write-Host "  - This applies to every repo because Git global core.hooksPath is configured."
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
