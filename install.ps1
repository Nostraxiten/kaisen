<#
.SYNOPSIS
    Kaisen universal installer for Windows.
.DESCRIPTION
    Works on Windows via PowerShell. It ensures a Rust toolchain is available,
    builds the release binary, and installs `kaisen.exe` (plus `kai.exe` and `kaison.exe` aliases)
    into a directory on PATH — preferring a user-writable location so admin is never required.

    irm https://raw.githubusercontent.com/nostraxiten/kaisen/main/install.ps1 | iex
#>

$ErrorActionPreference = "Stop"

$RepoUrl = "https://github.com/nostraxiten/kaisen.git"
$Branch = if ($env:KAISEN_BRANCH) { $env:KAISEN_BRANCH } else { "main" }

function Write-Info($Message) {
    Write-Host "[kaisen] " -ForegroundColor Cyan -NoNewline
    Write-Host $Message
}

function Write-Warn($Message) {
    Write-Host "[kaisen] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
}

function Write-Err($Message) {
    Write-Host "[kaisen] " -ForegroundColor Red -NoNewline
    Write-Host $Message
}

function Ensure-Rust {
    if (Get-Command cargo -ErrorAction SilentlyContinue) {
        $CargoVer = (cargo --version).Trim()
        Write-Info "Found cargo: $CargoVer"
        return
    }

    Write-Info "Rust toolchain not found — installing via rustup..."
    $RustupInit = Join-Path $env:TEMP "rustup-init.exe"
    Invoke-WebRequest -Uri "https://win.rustup.rs" -OutFile $RustupInit
    & $RustupInit -y --default-host x86_64-pc-windows-msvc | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Rust installation failed."
        exit 1
    }

    # Add cargo to path for current session
    $env:PATH += ";$env:USERPROFILE\.cargo\bin"
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Err "cargo is still not in PATH after installation."
        exit 1
    }
}

Ensure-Rust

$SrcDir = ""
if (Test-Path "Cargo.toml") {
    if (Select-String -Path "Cargo.toml" -Pattern 'name = "kaisen"' -Quiet) {
        $SrcDir = (Get-Location).Path
        Write-Info "Building from current checkout: $SrcDir"
    }
}

if ($SrcDir -eq "") {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Err "git is required to clone the repository."
        exit 1
    }
    
    $SrcDir = Join-Path $env:TEMP "kaisen-src-$(New-Guid)"
    Write-Info "Cloning $RepoUrl ($Branch) into $SrcDir"
    git clone --depth 1 --branch $Branch $RepoUrl $SrcDir | Out-Null
}

Write-Info "Building release binary (this can take a few minutes)..."
Push-Location $SrcDir
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        Write-Err "Cargo build failed."
        exit 1
    }
}
finally {
    Pop-Location
}

$BinPath = Join-Path $SrcDir "target\release\kaisen.exe"
if (-not (Test-Path $BinPath)) {
    Write-Err "Build did not produce $BinPath"
    exit 1
}

# Determine installation directory
$BinDir = "$env:USERPROFILE\.cargo\bin"
if (-not (Test-Path $BinDir)) {
    New-Item -ItemType Directory -Path $BinDir | Out-Null
}

Write-Info "Installing to $BinDir"

$KaisenExe = Join-Path $BinDir "kaisen.exe"
$KaiExe = Join-Path $BinDir "kai.exe"
$KaisonExe = Join-Path $BinDir "kaison.exe"

Copy-Item -Path $BinPath -Destination $KaisenExe -Force
Copy-Item -Path $BinPath -Destination $KaiExe -Force
Copy-Item -Path $BinPath -Destination $KaisonExe -Force

$Paths = [Environment]::GetEnvironmentVariable("PATH", "User") -split ";"
if ($Paths -notcontains $BinDir) {
    Write-Warn "$BinDir is not in your user PATH."
    Write-Warn "Adding it now..."
    $NewPath = [Environment]::GetEnvironmentVariable("PATH", "User") + ";$BinDir"
    [Environment]::SetEnvironmentVariable("PATH", $NewPath, "User")
    $env:PATH += ";$BinDir"
}

Write-Info "Done! Installed: kaisen.exe, kai.exe, kaison.exe"
& $KaisenExe --version
Write-Info "Try: kaisen --help"
