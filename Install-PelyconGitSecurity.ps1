<#
Pelycon Device-Level Git Security Bootstrap
Windows PowerShell Script

Purpose:
- Install/configure Git and Gitleaks once per Windows user profile.
- Configure global Git hooks so every repo automatically runs Gitleaks.
- Give clear blocked-commit/blocked-push messages with file, line, rule, and fingerprint.

Normal install:
Set-ExecutionPolicy -Scope Process Bypass -Force
.\Install-PelyconGitSecurity.ps1

Self-test:
.\Install-PelyconGitSecurity.ps1 -RunSelfTest

Force Gitleaks update:
.\Install-PelyconGitSecurity.ps1 -ForceUpdate

Uninstall:
.\Install-PelyconGitSecurity.ps1 -Uninstall

Show actual secret values in reports:
.\Install-PelyconGitSecurity.ps1 -ShowSecretsInReports

Default behavior redacts secrets.
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

# GitHub requires modern TLS.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$PelyconRoot = Join-Path $env:LOCALAPPDATA "Pelycon"
$ToolsRoot = Join-Path $PelyconRoot "Tools"
$GitleaksDir = Join-Path $ToolsRoot "gitleaks"
$HooksDir = Join-Path $PelyconRoot "GitHooks"
$LogDir = Join-Path $PelyconRoot "Logs"
$ReportsDir = Join-Path $PelyconRoot "GitleaksReports"
$GitleaksExe = Join-Path $GitleaksDir "gitleaks.exe"
$FindingHelper = Join-Path $PelyconRoot "Show-GitleaksFindingSummary.ps1"

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
        Write-Ok "Added Gitleaks folder to the user's PATH."
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
            Write-Warn "Existing Gitleaks copy appears broken. Re-downloading..."
        }
    }

    Write-Step "Installing Gitleaks"

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
        throw "
