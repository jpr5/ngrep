#!/usr/bin/env pwsh
#
# Windows build script for ngrep
# Requires: Visual Studio 2022, vcpkg
#

param(
    [string]$NpcapSdkDir = "C:\npcap-sdk",
    [string]$BuildType = "Release",
    [switch]$SkipNpcapDownload,
    [switch]$SkipVcpkg,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

# Handle clean operation
if ($Clean) {
    Write-Host "==> Cleaning build artifacts..." -ForegroundColor Cyan
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $buildDir = Join-Path $scriptDir "build"

    if (Test-Path $buildDir) {
        Write-Host "==> Removing build directory: $buildDir" -ForegroundColor Yellow
        Remove-Item -Recurse -Force $buildDir
        Write-Host "==> Clean complete!" -ForegroundColor Green
    } else {
        Write-Host "==> Build directory does not exist, nothing to clean" -ForegroundColor Yellow
    }
    exit 0
}

Write-Host "==> Building ngrep for Windows" -ForegroundColor Cyan

# Check for Visual Studio 2022 FIRST (needed for vcpkg to compile packages)
Write-Host "==> Checking for Visual Studio 2022..." -ForegroundColor Yellow
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstalled = $false

# Check using vswhere if available
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -version "[17.0,18.0)" -property installationPath 2>$null
    if ($vsPath) {
        Write-Host "==> Visual Studio 2022 found at $vsPath" -ForegroundColor Green
        $vsInstalled = $true
    }
}

# Fallback: Check common VS 2022 installation paths
if (-Not $vsInstalled) {
    $vsPaths = @(
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Community",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Professional",
        "${env:ProgramFiles}\Microsoft Visual Studio\2022\Enterprise",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Community",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Professional",
        "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\Enterprise"
    )

    foreach ($path in $vsPaths) {
        if (Test-Path "$path\VC\Auxiliary\Build\vcvarsall.bat") {
            Write-Host "==> Visual Studio 2022 found at $path" -ForegroundColor Green
            $vsInstalled = $true
            break
        }
    }
}

if (-Not $vsInstalled) {
    Write-Host "==> Visual Studio 2022 not found. Installing via winget..." -ForegroundColor Yellow
    Write-Host "==> This will take 10-20 minutes. Please be patient..." -ForegroundColor Yellow

    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if ($wingetCmd) {
        # Install VS 2022 Community with C++ Desktop workload
        winget install --id Microsoft.VisualStudio.2022.Community --silent --accept-package-agreements --accept-source-agreements --override "--quiet --add Microsoft.VisualStudio.Workload.NativeDesktop --includeRecommended"

        if ($LASTEXITCODE -eq 0) {
            Write-Host "==> Visual Studio 2022 Community installed successfully" -ForegroundColor Green
            Write-Host "==> Please restart PowerShell and run this script again" -ForegroundColor Yellow
            exit 0
        } else {
            Write-Error "Failed to install Visual Studio 2022. Please install manually from https://visualstudio.microsoft.com/downloads/"
            exit 1
        }
    } else {
        Write-Error "Visual Studio 2022 not found and winget unavailable. Please install manually from https://visualstudio.microsoft.com/downloads/"
        exit 1
    }
}

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

    # Set default triplet to x64-windows (works on both x64 and ARM64 via emulation)
    $env:VCPKG_DEFAULT_TRIPLET = "x64-windows"

    # On ARM64 Windows, vcpkg may have issues. Try to install, but don't fail if it doesn't work
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($arch -eq "ARM64") {
        Write-Host "==> Detected ARM64 Windows. Attempting vcpkg install..." -ForegroundColor Yellow
        Write-Host "==> If this fails, you may need to manually install PCRE2 or use a different approach" -ForegroundColor Yellow
    }

    # Run vcpkg integrate first to set up MSBuild integration
    vcpkg integrate install

    vcpkg install pcre2:x64-windows --allow-unsupported
    if ($LASTEXITCODE -ne 0) {
        Write-Host "==> vcpkg install failed. This is expected on ARM64 Windows." -ForegroundColor Yellow
        Write-Host "==> The build will continue and attempt to use system PCRE2 if available" -ForegroundColor Yellow
        Write-Host "==> You may need to manually install PCRE2 or build without vcpkg using -SkipVcpkg" -ForegroundColor Yellow
    } else {
        Write-Host "==> PCRE2 installed" -ForegroundColor Green
    }
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

# Detect architecture and set CMake platform
$arch = $env:PROCESSOR_ARCHITECTURE
$cmakeArch = "x64"  # Default to x64

if ($arch -eq "ARM64") {
    # Check if Npcap SDK has ARM64 libraries
    if (Test-Path "$NpcapSdkDir\Lib\ARM64") {
        $cmakeArch = "ARM64"
        Write-Host "==> Detected ARM64 Windows with ARM64 Npcap SDK - building native ARM64 binary" -ForegroundColor Green
    } else {
        Write-Host "==> Detected ARM64 Windows but no ARM64 Npcap libs - building x64 binary (will run via emulation)" -ForegroundColor Yellow
    }
} else {
    Write-Host "==> Building for x64 architecture" -ForegroundColor Green
}

cmake -B $buildDir -S $scriptDir `
    -G "Visual Studio 17 2022" -A $cmakeArch `
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
Write-Host "==> Architecture: $cmakeArch" -ForegroundColor Cyan
Write-Host ""
Write-Host "IMPORTANT: To run ngrep.exe, you need:" -ForegroundColor Yellow
Write-Host "  1. Install Npcap runtime from: https://npcap.com/#download" -ForegroundColor Yellow
Write-Host ""
if ($cmakeArch -eq "ARM64") {
    Write-Host "Built native ARM64 binary - will run natively on ARM64 Windows" -ForegroundColor Green
} elseif ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    Write-Host "Built x64 binary on ARM64 Windows - will run via x64 emulation" -ForegroundColor Yellow
}
