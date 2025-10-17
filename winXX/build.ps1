#!/usr/bin/env pwsh
#
# Windows build script for ngrep
# Requires: Visual Studio 2022, vcpkg
#

param(
    [string]$NpcapSdkDir = "C:\npcap-sdk",
    [string]$BuildType = "Release",
    [switch]$SkipNpcapDownload,
    [switch]$SkipVcpkg
)

$ErrorActionPreference = "Stop"

Write-Host "==> Building ngrep for Windows" -ForegroundColor Cyan

# Download and install Npcap SDK if needed
if (-Not $SkipNpcapDownload) {
    if (-Not (Test-Path "$NpcapSdkDir\Include\pcap.h")) {
        Write-Host "==> Downloading Npcap SDK..." -ForegroundColor Yellow
        $sdkUrl = "https://npcap.com/dist/npcap-sdk-1.13.zip"
        $sdkZip = "$env:TEMP\npcap-sdk.zip"

        Invoke-WebRequest -Uri $sdkUrl -OutFile $sdkZip
        Expand-Archive -Path $sdkZip -DestinationPath $NpcapSdkDir -Force
        Remove-Item $sdkZip

        if (-Not (Test-Path "$NpcapSdkDir\Include\pcap.h")) {
            Write-Error "Npcap SDK installation failed"
            exit 1
        }
        Write-Host "==> Npcap SDK installed to $NpcapSdkDir" -ForegroundColor Green
    } else {
        Write-Host "==> Npcap SDK already installed at $NpcapSdkDir" -ForegroundColor Green
    }
}

# Check for vcpkg and install PCRE2
if (-Not $SkipVcpkg) {
    # Check if vcpkg is available
    $vcpkgCmd = Get-Command vcpkg -ErrorAction SilentlyContinue

    if (-Not $vcpkgCmd) {
        Write-Host "==> vcpkg not found. Checking common locations..." -ForegroundColor Yellow

        # Check common vcpkg locations
        $vcpkgPaths = @(
            "C:\vcpkg\vcpkg.exe",
            "$env:USERPROFILE\vcpkg\vcpkg.exe",
            "$env:ProgramFiles\vcpkg\vcpkg.exe"
        )

        $vcpkgExe = $null
        foreach ($path in $vcpkgPaths) {
            if (Test-Path $path) {
                $vcpkgExe = $path
                break
            }
        }

        if (-Not $vcpkgExe) {
            Write-Host "==> vcpkg not found. Installing to C:\vcpkg..." -ForegroundColor Yellow

            # Clone vcpkg
            if (-Not (Test-Path "C:\vcpkg")) {
                git clone https://github.com/microsoft/vcpkg.git C:\vcpkg
                if ($LASTEXITCODE -ne 0) {
                    Write-Error "Failed to clone vcpkg"
                    exit 1
                }
            }

            # Bootstrap vcpkg
            & C:\vcpkg\bootstrap-vcpkg.bat
            if ($LASTEXITCODE -ne 0) {
                Write-Error "Failed to bootstrap vcpkg"
                exit 1
            }

            $vcpkgExe = "C:\vcpkg\vcpkg.exe"
            Write-Host "==> vcpkg installed successfully" -ForegroundColor Green
        } else {
            Write-Host "==> Found vcpkg at $vcpkgExe" -ForegroundColor Green
        }

        # Use the found/installed vcpkg
        $env:PATH = "$(Split-Path $vcpkgExe);$env:PATH"
    }

    Write-Host "==> Installing PCRE2 via vcpkg..." -ForegroundColor Yellow
    vcpkg install pcre2:x64-windows
    if ($LASTEXITCODE -ne 0) {
        Write-Error "vcpkg install failed"
        exit 1
    }
    Write-Host "==> PCRE2 installed" -ForegroundColor Green
}

# Check for CMake
$cmakeCmd = Get-Command cmake -ErrorAction SilentlyContinue
if (-Not $cmakeCmd) {
    Write-Host "==> CMake not found. Installing via winget..." -ForegroundColor Yellow

    # Try winget first (Windows 10+)
    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetCmd) {
        winget install --id Kitware.CMake --silent --accept-package-agreements --accept-source-agreements
        if ($LASTEXITCODE -eq 0) {
            # Refresh PATH
            $env:PATH = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
            Write-Host "==> CMake installed successfully" -ForegroundColor Green
        } else {
            Write-Error "Failed to install CMake via winget. Please install manually from https://cmake.org/download/"
            exit 1
        }
    } else {
        Write-Error "CMake not found and winget unavailable. Please install CMake from https://cmake.org/download/"
        exit 1
    }
}

# Configure with CMake
Write-Host "==> Configuring with CMake..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $scriptDir "build"

cmake -B $buildDir -S $scriptDir `
    -G "Visual Studio 17 2022" -A x64 `
    -DCMAKE_TOOLCHAIN_FILE="C:/vcpkg/scripts/buildsystems/vcpkg.cmake" `
    -DNPCAP_SDK_DIR="$NpcapSdkDir"

if ($LASTEXITCODE -ne 0) {
    Write-Error "CMake configuration failed"
    exit 1
}

# Build
Write-Host "==> Building..." -ForegroundColor Yellow
cmake --build $buildDir --config $BuildType

if ($LASTEXITCODE -ne 0) {
    Write-Error "Build failed"
    exit 1
}

# Verify output
$exePath = Join-Path $buildDir "bin\$BuildType\ngrep.exe"
if (-Not (Test-Path $exePath)) {
    Write-Error "ngrep.exe was not built at $exePath"
    exit 1
}

Write-Host "==> Build successful!" -ForegroundColor Green
Write-Host "==> Executable: $exePath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note: To run ngrep.exe, you need to install Npcap runtime from:" -ForegroundColor Yellow
Write-Host "      https://npcap.com/#download" -ForegroundColor Yellow
