#!/usr/bin/env pwsh
#
# Windows build script for ngrep
# Auto-downloads all deps as needed, including Visual Studio, vcpkg, PCRE2, cmake and NpcapSDK.
#

param(
    [string]$NpcapSdkDir = "",
    [string]$PCRE2Dir = "",
    [string]$BuildType = "Release",
    [switch]$SkipNpcapSdkInstall,
    [switch]$SkipPCRE2,
    [switch]$Clean,
    [switch]$Help
)

$ErrorActionPreference = "Stop"

# Handle help option
if ($Help) {
    Write-Host "ngrep Windows Build Script" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Usage: .\build.ps1 [options]" -ForegroundColor White
    Write-Host ""
    Write-Host "Options:" -ForegroundColor Yellow
    Write-Host "  -BuildType <type>         Build type: Release or Debug (default: Release)"
    Write-Host "  -NpcapSdkDir <path>       Use Npcap SDK at path (instead of auto-installing)"
    Write-Host "  -PCRE2Dir <path>          Use PCRE2 at path (instead of auto-installing)"
    Write-Host "  -SkipNpcapSdkInstall      Skip downloading Npcap SDK (uses default location)"
    Write-Host "  -SkipPCRE2                Skip PCRE2 installation and use bundled regex-0.12"
    Write-Host "  -Clean                    Remove build directory and exit"
    Write-Host "  -Help                     Show this help message"
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Yellow
    Write-Host "  .\build.ps1                           # Full build with auto-detection"
    Write-Host "  .\build.ps1 -Clean                    # Clean build artifacts"
    Write-Host "  .\build.ps1 -SkipPCRE2                # Build without PCRE2"
    Write-Host "  .\build.ps1 -BuildType Debug          # Build debug version"
    Write-Host ""
    exit 0
}

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

# Handle directory parameters - if specified, auto-skip installation
if ($NpcapSdkDir -ne "") {
    $SkipNpcapSdkInstall = $true
    Write-Host "==> Using Npcap SDK from: $NpcapSdkDir" -ForegroundColor Cyan
} else {
    $NpcapSdkDir = "C:\npcap-sdk"
}

if ($PCRE2Dir -ne "") {
    $SkipPCRE2 = $true
    Write-Host "==> Using PCRE2 from: $PCRE2Dir" -ForegroundColor Cyan
}

# Check for Visual Studio 2022+ FIRST (needed for vcpkg to compile packages)
Write-Host "==> Checking for Visual Studio 2022 or later..." -ForegroundColor Yellow
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsInstalled = $false

# Check using vswhere if available
if (Test-Path $vswhere) {
    $vsPath = & $vswhere -all -prerelease -version "[17.0,)" -property installationPath -latest 2>$null
    if ($vsPath) {
        Write-Host "==> Visual Studio found at $vsPath" -ForegroundColor Green
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
            Write-Host "ERROR: Failed to install Visual Studio 2022. Please install manually from https://visualstudio.microsoft.com/downloads/" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "ERROR: Visual Studio 2022 not found and winget unavailable. Please install manually from https://visualstudio.microsoft.com/downloads/" -ForegroundColor Red
        exit 1
    }
}

# Download and install Npcap SDK if needed
if (-Not $SkipNpcapSdkInstall) {
    if (-Not (Test-Path "$NpcapSdkDir\Include\pcap.h")) {
        Write-Host "==> Downloading Npcap SDK..." -ForegroundColor Yellow
        $sdkUrl = "https://npcap.com/dist/npcap-sdk-1.13.zip"
        $sdkZip = "$env:TEMP\npcap-sdk.zip"

        Invoke-WebRequest -Uri $sdkUrl -OutFile $sdkZip
        Expand-Archive -Path $sdkZip -DestinationPath $NpcapSdkDir -Force
        Remove-Item $sdkZip

        if (-Not (Test-Path "$NpcapSdkDir\Include\pcap.h")) {
            Write-Host "ERROR: Npcap SDK installation failed" -ForegroundColor Red
            exit 1
        }
        Write-Host "==> Npcap SDK installed to $NpcapSdkDir" -ForegroundColor Green
    } else {
        Write-Host "==> Npcap SDK already installed at $NpcapSdkDir" -ForegroundColor Green
    }
}

# Check for vcpkg and install PCRE2
if (-Not $SkipPCRE2) {
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
                    Write-Host "ERROR: Failed to clone vcpkg" -ForegroundColor Red
                    exit 1
                }
            }

            # Bootstrap vcpkg
            & C:\vcpkg\bootstrap-vcpkg.bat
            if ($LASTEXITCODE -ne 0) {
                Write-Host "ERROR: Failed to bootstrap vcpkg" -ForegroundColor Red
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

    # Detect architecture and set appropriate vcpkg triplet
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($arch -eq "ARM64") {
        $vcpkgTriplet = "arm64-windows"
        Write-Host "==> Detected ARM64 Windows - using arm64-windows triplet" -ForegroundColor Yellow
    } else {
        $vcpkgTriplet = "x64-windows"
    }

    # Set default triplet
    $env:VCPKG_DEFAULT_TRIPLET = $vcpkgTriplet

    # Ensure VCPKG_FORCE_SYSTEM_BINARIES is not set (can cause download failures)
    if ($env:VCPKG_FORCE_SYSTEM_BINARIES) {
        Remove-Item Env:\VCPKG_FORCE_SYSTEM_BINARIES
        Write-Host "==> Removed VCPKG_FORCE_SYSTEM_BINARIES environment variable" -ForegroundColor Yellow
    }

    # Run vcpkg integrate first to set up MSBuild integration
    vcpkg integrate install

    vcpkg install "pcre2:$vcpkgTriplet"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "==> vcpkg install failed." -ForegroundColor Yellow
        Write-Host "==> The build will continue with bundled regex-0.12 library" -ForegroundColor Yellow
        Write-Host "==> To skip PCRE2 installation, use: .\build.ps1 -SkipPCRE2" -ForegroundColor Yellow
    } else {
        Write-Host "==> PCRE2 installed for $vcpkgTriplet" -ForegroundColor Green
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
            Write-Host "ERROR: Failed to install CMake via winget. Please install manually from https://cmake.org/download/" -ForegroundColor Red
            exit 1
        }
    } else {
        Write-Host "ERROR: CMake not found and winget unavailable. Please install CMake from https://cmake.org/download/" -ForegroundColor Red
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

# Build CMake command with optional parameters
$cmakeArgs = @(
    "-B", $buildDir,
    "-S", $scriptDir,
    "-G", "Visual Studio 17 2022",
    "-A", $cmakeArch,
    "-DNPCAP_SDK_DIR=$NpcapSdkDir"
)

# Handle PCRE2 configuration
if ($PCRE2Dir -ne "") {
    # User specified PCRE2Dir - use it directly
    $cmakeArgs += "-DPCRE2_INCLUDE_DIR=$PCRE2Dir\include"
    $cmakeArgs += "-DPCRE2_LIBRARY=$PCRE2Dir\lib\pcre2-8.lib"
} elseif (-Not $SkipPCRE2) {
    # Use vcpkg toolchain to find PCRE2
    # Detect vcpkg root from environment or command location
    $vcpkgRoot = $env:VCPKG_ROOT
    if (-Not $vcpkgRoot) {
        $vcpkgCmd = Get-Command vcpkg -ErrorAction SilentlyContinue
        if ($vcpkgCmd) {
            $vcpkgRoot = Split-Path -Parent $vcpkgCmd.Source
        } elseif (Test-Path "C:\vcpkg\vcpkg.exe") {
            $vcpkgRoot = "C:\vcpkg"
        }
    }
    
    if ($vcpkgRoot) {
        $vcpkgToolchain = Join-Path $vcpkgRoot "scripts\buildsystems\vcpkg.cmake"
        if (Test-Path $vcpkgToolchain) {
            $cmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$vcpkgToolchain"
            Write-Host "==> Using vcpkg toolchain: $vcpkgToolchain" -ForegroundColor Green
        } else {
            Write-Host "==> Warning: vcpkg toolchain not found at $vcpkgToolchain" -ForegroundColor Yellow
            Write-Host "==> Will attempt to build without vcpkg integration" -ForegroundColor Yellow
        }
    } else {
        Write-Host "==> Warning: Could not locate vcpkg root" -ForegroundColor Yellow
        Write-Host "==> Will attempt to build without vcpkg integration" -ForegroundColor Yellow
    }
} else {
    # Skip PCRE2 entirely - use bundled regex
    Write-Host "==> Skipping PCRE2 - will use bundled regex-0.12" -ForegroundColor Yellow
}

cmake @cmakeArgs

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: CMake configuration failed" -ForegroundColor Red
    exit 1
}

# Build
Write-Host "==> Building..." -ForegroundColor Yellow
cmake --build $buildDir --config $BuildType

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Build failed" -ForegroundColor Red
    exit 1
}

# Verify output
$exePath = Join-Path $buildDir "bin\$BuildType\ngrep.exe"
if (-Not (Test-Path $exePath)) {
    Write-Host "ERROR: ngrep.exe was not built at $exePath" -ForegroundColor Red
    exit 1
}

Write-Host "==> Build successful!" -ForegroundColor Green
Write-Host "==> Executable: $exePath" -ForegroundColor Cyan
Write-Host "==> Architecture: $cmakeArch" -ForegroundColor Cyan
Write-Host ""

# Check if Npcap runtime is installed
$npcapInstalled = $false
$npcapService = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
if ($npcapService) {
    $npcapInstalled = $true
    Write-Host "Npcap runtime is installed and ready" -ForegroundColor Green
} else {
    # Also check for wpcap.dll in System32
    $wpcapDll = Join-Path $env:SystemRoot "System32\wpcap.dll"
    if (Test-Path $wpcapDll) {
        $npcapInstalled = $true
        Write-Host "Npcap runtime is installed and ready" -ForegroundColor Green
    }
}

if (-Not $npcapInstalled) {
    Write-Host "IMPORTANT: To run ngrep.exe, you need to install Npcap runtime:" -ForegroundColor Yellow
    Write-Host "           https://npcap.com/#download" -ForegroundColor Yellow
    Write-Host ""
}

# Show architecture info
$hostArch = $env:PROCESSOR_ARCHITECTURE

# Normalize architecture names for comparison (AMD64 and x64 are the same)
$normalizedHost = if ($hostArch -eq "AMD64") { "x64" } else { $hostArch }
$normalizedTarget = $cmakeArch

if ($normalizedTarget -eq $normalizedHost) {
    Write-Host "Built native $cmakeArch binary for this system" -ForegroundColor Green
} else {
    Write-Host "Built $cmakeArch binary (cross-compiled on $hostArch)" -ForegroundColor Cyan
    if ($normalizedHost -eq "ARM64" -and $normalizedTarget -eq "x64") {
        Write-Host "Note: x64 binary will run via emulation on ARM64 Windows" -ForegroundColor Yellow
    }
}
