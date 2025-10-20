#!/usr/bin/env pwsh
#
# Windows build script for ngrep
# Auto-downloads all deps as needed: Visual Studio, vcpkg, PCRE2, cmake, NpcapSDK and git
#
# If you can't run this script, execute:
#
#    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
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

$script:vsGenerator = $null
$script:vsPlatformToolset = $null
$script:scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:buildDir = Join-Path $script:scriptDir "build"

#region Helper Functions

function Show-Help {
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
}

function Invoke-Clean {
    Write-Host "==> Cleaning build artifacts..." -ForegroundColor Cyan

    if (Test-Path $script:buildDir) {
        Write-Host "==> Removing build directory: $script:buildDir" -ForegroundColor Yellow
        Remove-Item -Recurse -Force $script:buildDir
        Write-Host "==> Clean complete!" -ForegroundColor Green
    } else {
        Write-Host "==> Build directory does not exist, nothing to clean" -ForegroundColor Yellow
    }
}

function Initialize-Paths {
    param(
        [ref]$NpcapSdkDirRef,
        [ref]$SkipNpcapSdkInstallRef,
        [ref]$SkipPCRE2Ref,
        [string]$PCRE2Dir
    )

    if ($NpcapSdkDirRef.Value -ne "") {
        $SkipNpcapSdkInstallRef.Value = $true
        Write-Host "==> Using Npcap SDK from: $($NpcapSdkDirRef.Value)" -ForegroundColor Cyan
    } else {
        if ($env:NPCAP_SDK_DIR) {
            $NpcapSdkDirRef.Value = $env:NPCAP_SDK_DIR
        } else {
            $NpcapSdkDirRef.Value = Join-Path $env:USERPROFILE "npcap-sdk"
        }
    }

    if ($PCRE2Dir -ne "") {
        $SkipPCRE2Ref.Value = $true
        Write-Host "==> Using PCRE2 from: $PCRE2Dir" -ForegroundColor Cyan
    }
}

#endregion

#region Dependency Installation Functions

function Ensure-VisualStudio {
    Write-Host "==> Checking for Visual Studio 2022 or later..." -ForegroundColor Yellow
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $vsInstalled = $false

    # Check using vswhere if available
    if (-Not (Test-Path $vswhere)) {
        # vswhere not available, skip to fallback
    } else {
        $vsPath = & $vswhere -all -prerelease -version "[17.0,)" -property installationPath -latest 2>$null
        if (-Not $vsPath) {
            # No VS found via vswhere
        } else {
            # Get the major version
            $vsMajorVersion = & $vswhere -all -prerelease -version "[17.0,)" -property installationVersion -latest 2>$null
            if (-Not $vsMajorVersion) {
                # Version not detected
            } else {
                $vsMajor = [int]($vsMajorVersion.Split('.')[0])
                Write-Host "==> Visual Studio found at $vsPath (version $vsMajorVersion)" -ForegroundColor Green

                # Map VS version to CMake generator and platform toolset
                switch ($vsMajor) {
                    17 {
                        $script:vsGenerator = "Visual Studio 17 2022"
                        $script:vsPlatformToolset = "v143"
                    }
                    18 {
                        $script:vsGenerator = "Visual Studio 18 2026"
                        $script:vsPlatformToolset = "v145"
                    }
                    default {
                        # For future versions, use the detected version
                        $script:vsGenerator = "Visual Studio $vsMajor"
                        $script:vsPlatformToolset = "v$($vsMajor)5"  # Guess pattern: v145, v155, etc.
                    }
                }

                Write-Host "==> Using CMake generator: $script:vsGenerator with toolset: $script:vsPlatformToolset" -ForegroundColor Cyan
                $vsInstalled = $true
            }
        }
    }

    # Fallback: Check common VS installation paths for 2022 and 2026
    if ($vsInstalled) {
        return  # Already found via vswhere
    }

    $vsVersions = @(
        @{Year="2026"; Major=18; Generator="Visual Studio 18 2026"; Toolset="v145"},
        @{Year="2022"; Major=17; Generator="Visual Studio 17 2022"; Toolset="v143"}
    )

    foreach ($vsVer in $vsVersions) {
        if ($vsInstalled) { break }

        $vsPaths = @(
            "${env:ProgramFiles}\Microsoft Visual Studio\$($vsVer.Year)\Community",
            "${env:ProgramFiles}\Microsoft Visual Studio\$($vsVer.Year)\Professional",
            "${env:ProgramFiles}\Microsoft Visual Studio\$($vsVer.Year)\Enterprise",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\$($vsVer.Year)\Community",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\$($vsVer.Year)\Professional",
            "${env:ProgramFiles(x86)}\Microsoft Visual Studio\$($vsVer.Year)\Enterprise"
        )

        foreach ($path in $vsPaths) {
            if (-Not (Test-Path "$path\VC\Auxiliary\Build\vcvarsall.bat")) {
                continue
            }

            Write-Host "==> Visual Studio $($vsVer.Year) found at $path" -ForegroundColor Green
            $script:vsGenerator = $vsVer.Generator
            $script:vsPlatformToolset = $vsVer.Toolset
            Write-Host "==> Using CMake generator: $script:vsGenerator with toolset: $script:vsPlatformToolset" -ForegroundColor Cyan
            $vsInstalled = $true
            break
        }
    }

    if ($vsInstalled) {
        return
    }

    Write-Host "==> Visual Studio not found. Installing via winget..." -ForegroundColor Yellow
    Write-Host "==> This will take 10-20 minutes, please wait..." -ForegroundColor Yellow

    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if (-Not $wingetCmd) {
        Write-Host "ERROR: Visual Studio not found and winget unavailable. Please install manually from https://visualstudio.microsoft.com/downloads/" -ForegroundColor Red
        exit 1
    }

    winget install --id Microsoft.VisualStudio.2026.Community --silent --accept-package-agreements --accept-source-agreements --override "--quiet --add Microsoft.VisualStudio.Workload.NativeDesktop --includeRecommended"

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install Visual Studio. Please install manually from https://visualstudio.microsoft.com/downloads/" -ForegroundColor Red
        exit 1
    }

    Write-Host "==> Visual Studio 2026 Community installed successfully" -ForegroundColor Green
    Write-Host "==> Please restart PowerShell and run this script again" -ForegroundColor Yellow
    exit 0
}

function Ensure-Git {
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if ($gitCmd) {
        return
    }

    Write-Host "==> git not found. Installing via winget..." -ForegroundColor Yellow

    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if (-Not $wingetCmd) {
        Write-Host "ERROR: git is required to install vcpkg but was not found" -ForegroundColor Red
        Write-Host "       winget is also unavailable to auto-install git" -ForegroundColor Red
        Write-Host "       Please install git from https://git-scm.com/download/win" -ForegroundColor Red
        Write-Host "       Or use -SkipPCRE2 to build without PCRE2 support" -ForegroundColor Yellow
        exit 1
    }

    winget install --id Git.Git --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install git via winget" -ForegroundColor Red
        Write-Host "       Please install git manually from https://git-scm.com/download/win" -ForegroundColor Red
        Write-Host "       Or use -SkipPCRE2 to build without PCRE2 support" -ForegroundColor Yellow
        exit 1
    }

    # Refresh PATH to pick up newly installed git
    $env:PATH = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    Write-Host "==> git installed successfully" -ForegroundColor Green

    # Verify git is now available
    $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    if (-Not $gitCmd) {
        Write-Host "ERROR: git was installed but still not found in PATH" -ForegroundColor Red
        Write-Host "       Please restart PowerShell and run this script again" -ForegroundColor Yellow
        Write-Host "       Or use -SkipPCRE2 to build without PCRE2 support" -ForegroundColor Yellow
        exit 1
    }
}

function Ensure-NpcapSDK {
    param(
        [string]$NpcapSdkDir,
        [bool]$SkipInstall
    )

    if ($SkipInstall) {
        return
    }

    if (Test-Path "$NpcapSdkDir\Include\pcap.h") {
        Write-Host "==> Npcap SDK already installed at $NpcapSdkDir" -ForegroundColor Green
        return
    }

    Write-Host "==> Downloading Npcap SDK..." -ForegroundColor Yellow
    $npcapVersion = if ($env:NPCAP_SDK_VERSION) { $env:NPCAP_SDK_VERSION } else { "1.13" }
    $sdkUrl = "https://npcap.com/dist/npcap-sdk-$npcapVersion.zip"
    $sdkZip = "$env:TEMP\npcap-sdk.zip"

    try {
        Invoke-WebRequest -Uri $sdkUrl -OutFile $sdkZip -ErrorAction Stop
        Expand-Archive -Path $sdkZip -DestinationPath $NpcapSdkDir -Force
        Remove-Item $sdkZip
    } catch {
        Write-Host "ERROR: Failed to download Npcap SDK from $sdkUrl" -ForegroundColor Red
        Write-Host "       $_" -ForegroundColor Red
        exit 1
    }

    if (-Not (Test-Path "$NpcapSdkDir\Include\pcap.h")) {
        Write-Host "ERROR: Npcap SDK installation failed" -ForegroundColor Red
        exit 1
    }
    Write-Host "==> Npcap SDK installed to $NpcapSdkDir" -ForegroundColor Green
}

function Ensure-Vcpkg {
    $vcpkgCmd = Get-Command vcpkg -ErrorAction SilentlyContinue
    if ($vcpkgCmd) {
        return
    }

    Write-Host "==> vcpkg not found. Checking common locations..." -ForegroundColor Yellow

    # Determine default vcpkg installation path
    $defaultVcpkgPath = if ($env:VCPKG_ROOT) { $env:VCPKG_ROOT } else { Join-Path $env:USERPROFILE "vcpkg" }

    # Check common vcpkg locations
    $vcpkgPaths = @(
        "$defaultVcpkgPath\vcpkg.exe",
        "$env:USERPROFILE\vcpkg\vcpkg.exe",
        "C:\vcpkg\vcpkg.exe",
        "$env:ProgramFiles\vcpkg\vcpkg.exe"
    )

    $vcpkgExe = $null
    foreach ($path in $vcpkgPaths) {
        if (Test-Path $path) {
            $vcpkgExe = $path
            break
        }
    }

    if ($vcpkgExe) {
        Write-Host "==> Found vcpkg at $vcpkgExe" -ForegroundColor Green
        $env:PATH = "$(Split-Path $vcpkgExe);$env:PATH"
        return
    }

    Write-Host "==> vcpkg not found. Installing to $defaultVcpkgPath..." -ForegroundColor Yellow

    Ensure-Git

    if (-Not (Test-Path $defaultVcpkgPath)) {
        Write-Host "==> Cloning vcpkg repository..." -ForegroundColor Yellow
        git clone --depth 1 https://github.com/microsoft/vcpkg.git $defaultVcpkgPath
        if ($LASTEXITCODE -ne 0) {
            Write-Host "ERROR: Failed to clone vcpkg" -ForegroundColor Red
            exit 1
        }
    }

    $bootstrapScript = Join-Path $defaultVcpkgPath "bootstrap-vcpkg.bat"
    & $bootstrapScript
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to bootstrap vcpkg" -ForegroundColor Red
        exit 1
    }

    $vcpkgExe = Join-Path $defaultVcpkgPath "vcpkg.exe"
    Write-Host "==> vcpkg installed successfully" -ForegroundColor Green

    $env:PATH = "$(Split-Path $vcpkgExe);$env:PATH"
}

function Ensure-PCRE2 {
    Write-Host "==> Installing PCRE2 via vcpkg..." -ForegroundColor Yellow

    # Detect architecture and set appropriate vcpkg triplet
    $arch = $env:PROCESSOR_ARCHITECTURE
    if ($arch -eq "ARM64") {
        $vcpkgTriplet = "arm64-windows"
        Write-Host "==> Detected ARM64 Windows - using arm64-windows triplet" -ForegroundColor Yellow
    } else {
        $vcpkgTriplet = "x64-windows"
    }

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

function Ensure-CMake {
    $cmakeCmd = Get-Command cmake -ErrorAction SilentlyContinue
    if ($cmakeCmd) {
        return
    }

    Write-Host "==> CMake not found. Installing via winget..." -ForegroundColor Yellow

    $wingetCmd = Get-Command winget -ErrorAction SilentlyContinue
    if (-Not $wingetCmd) {
        Write-Host "ERROR: CMake not found and winget unavailable. Please install CMake from https://cmake.org/download/" -ForegroundColor Red
        exit 1
    }

    winget install --id Kitware.CMake --silent --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to install CMake via winget. Please install manually from https://cmake.org/download/" -ForegroundColor Red
        exit 1
    }

    $env:PATH = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
    Write-Host "==> CMake installed successfully" -ForegroundColor Green
}

#endregion

#region Build Functions

function Invoke-CMakeConfiguration {
    param(
        [string]$NpcapSdkDir,
        [string]$PCRE2Dir,
        [bool]$SkipPCRE2,
        [string]$BuildType
    )

    # Detect architecture and set CMake platform
    $arch = $env:PROCESSOR_ARCHITECTURE
    $cmakeArch = "x64"

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

    if (-Not $script:vsGenerator -or -Not $script:vsPlatformToolset) {
        Write-Host "ERROR: Visual Studio generator or toolset not properly detected" -ForegroundColor Red
        Write-Host "       Generator: $script:vsGenerator" -ForegroundColor Red
        Write-Host "       Toolset: $script:vsPlatformToolset" -ForegroundColor Red
        exit 1
    }

    $cmakeArgs = @(
        "-B", $script:buildDir,
        "-S", $script:scriptDir,
        "-G", $script:vsGenerator,
        "-A", $cmakeArch,
        "-T", $script:vsPlatformToolset,
        "-DNPCAP_SDK_DIR=$NpcapSdkDir"
    )

    if ($PCRE2Dir -ne "") {
        $cmakeArgs += "-DPCRE2_INCLUDE_DIR=$PCRE2Dir\include"
        $cmakeArgs += "-DPCRE2_LIBRARY=$PCRE2Dir\lib\pcre2-8.lib"
    } elseif (-Not $SkipPCRE2) {
        $vcpkgCmd = Get-Command vcpkg -ErrorAction SilentlyContinue
        if ($vcpkgCmd) {
            $vcpkgRoot = Split-Path -Parent $vcpkgCmd.Source
            $vcpkgToolchain = Join-Path $vcpkgRoot "scripts\buildsystems\vcpkg.cmake"
            $cmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$vcpkgToolchain"
            Write-Host "==> Using vcpkg toolchain: $vcpkgToolchain" -ForegroundColor Green
        } else {
            Write-Host "==> Warning: vcpkg not found, building without PCRE2" -ForegroundColor Yellow
        }
    } else {
        Write-Host "==> Skipping PCRE2 - will use bundled regex-0.12" -ForegroundColor Yellow
    }

    cmake @cmakeArgs | Out-Host

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: CMake configuration failed" -ForegroundColor Red
        exit 1
    }

    return $cmakeArch
}

function Invoke-Build {
    param(
        [string]$BuildType
    )

    Write-Host "==> Building..." -ForegroundColor Yellow
    cmake --build $script:buildDir --config $BuildType | Out-Host

    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Build failed" -ForegroundColor Red
        exit 1
    }

    $exePath = Join-Path $script:buildDir "bin\$BuildType\ngrep.exe"
    if (-Not (Test-Path $exePath)) {
        Write-Host "ERROR: ngrep.exe was not built at $exePath" -ForegroundColor Red
        exit 1
    }

    return $exePath
}

function Show-BuildSummary {
    param(
        [string]$ExePath,
        [string]$CmakeArch
    )

    Write-Host ""
    Write-Host "==> Build successful!" -ForegroundColor Green
    Write-Host "==> Executable: $ExePath" -ForegroundColor Cyan
    Write-Host "==> Architecture: $CmakeArch" -ForegroundColor Cyan
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

    $hostArch = $env:PROCESSOR_ARCHITECTURE

    # Normalize architecture names for comparison (AMD64 and x64 are the same)
    $normalizedHost = if ($hostArch -eq "AMD64") { "x64" } else { $hostArch }
    $normalizedTarget = $CmakeArch

    if ($normalizedTarget -eq $normalizedHost) {
        Write-Host "Built native $CmakeArch binary for this system" -ForegroundColor Green
    } else {
        Write-Host "Built $CmakeArch binary (cross-compiled on $hostArch)" -ForegroundColor Cyan
        if ($normalizedHost -eq "ARM64" -and $normalizedTarget -eq "x64") {
            Write-Host "Note: x64 binary will run via emulation on ARM64 Windows" -ForegroundColor Yellow
        }
    }
}

#endregion

#region Main Execution

if ($Help) {
    Show-Help
    exit 0
}

if ($Clean) {
    Invoke-Clean
    exit 0
}

Write-Host "==> Building ngrep for Windows" -ForegroundColor Cyan

Initialize-Paths ([ref]$NpcapSdkDir) ([ref]$SkipNpcapSdkInstall) ([ref]$SkipPCRE2) $PCRE2Dir

Ensure-VisualStudio
Ensure-NpcapSDK $NpcapSdkDir $SkipNpcapSdkInstall

if (-Not $SkipPCRE2) {
    Ensure-Vcpkg
    Ensure-PCRE2
}

Ensure-CMake

$cmakeArch = Invoke-CMakeConfiguration $NpcapSdkDir $PCRE2Dir $SkipPCRE2 $BuildType
$exePath = Invoke-Build $BuildType

Show-BuildSummary $exePath $cmakeArch

#endregion
