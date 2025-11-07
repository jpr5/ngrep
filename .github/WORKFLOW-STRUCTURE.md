# GitHub Actions Workflow Structure

This document explains the workflow architecture for ngrep CI/CD.

## Overview

The workflows use a **reusable workflow pattern** to eliminate code duplication between CI validation and release builds.

## Workflow Files

### `matrix.yml` (Reusable Workflow)
**Purpose**: Core build logic for all platforms

**Features**:
- Defines the complete build matrix (14 platform/compiler combinations)
- Contains all build steps for Linux, macOS, BSD, Solaris, and Windows
- Accepts `create_artifacts` input parameter to control artifact generation
- Conditionally packages binaries based on the input parameter

**Called by**: `build.yml` and `release.yml`

### `build.yml` (CI Validation)
**Purpose**: Continuous integration validation on every commit

**Triggers**:
- Push to `master` branch (when source files change)
- Pull requests
- Manual workflow dispatch

**Behavior**:
- Calls `matrix.yml` with `create_artifacts: false`
- Builds all platforms to verify compilation
- Does NOT create or upload artifacts
- Fast feedback for development

### `release.yml` (Release Builds)
**Purpose**: Create distributable artifacts for releases

**Triggers**:
- Git tags matching `v*` (e.g., `v1.0.0`, `v2.1.3`)

**Behavior**:
- Calls `matrix.yml` with `create_artifacts: true`
- Builds all platforms and packages artifacts
- Creates GitHub Release with:
  - Binary-only packages (`.tar.gz` / `.zip`)
  - Full installation packages (`-full.tar.gz`)
  - SHA256 checksums
  - Professional release notes

### `docker.yml` (Container Builds)
**Purpose**: Build and publish Docker containers to GitHub Container Registry

**Triggers**:
- Push to `master` branch
- Git tags matching `v*` (e.g., `v1.0.0`, `v2.1.3`)
- Manual workflow dispatch

**Behavior**:
- Builds multi-architecture Docker images (amd64, arm64)
- Uses Alpine Linux for minimal image size (~15-20MB)
- Publishes to `ghcr.io/jpr5/ngrep`
- Creates build attestations for supply chain security
- Tags appropriately based on trigger:
  - `latest` - Latest master build
  - `1.0.0`, `1.0`, `1` - Version tags
  - `master`, `master-<sha>` - Branch tags

## Artifact Generation

Artifacts are only created when `create_artifacts: true`:

### Unix/BSD/Solaris Platforms
- `ngrep-<platform>.tar.gz` - Binary only
- `ngrep-<platform>-full.tar.gz` - Complete installation

### Windows Platform
- `ngrep-windows-x86_64.zip` - Contains:
  - `ngrep.exe`
  - `pcre2-8.dll` (automatically detected)
  - `README.txt`

## Platform Matrix

The build matrix includes:

| Platform | Compiler | Architecture | Artifact Name |
|----------|----------|--------------|---------------|
| Ubuntu Latest | GCC | x86_64 | `ngrep-linux-x86_64` |
| Ubuntu Latest | GCC | ARM64 | `ngrep-linux-arm64` |
| Ubuntu Latest | Clang | x86_64 | (CI only) |
| macOS 15 | Clang | ARM64 | `ngrep-macos-15-arm64` |
| macOS 26 | Clang | ARM64 | `ngrep-macos-26-arm64` |
| FreeBSD 15 | GCC | x86_64 | `ngrep-freebsd-15-x86_64` |
| FreeBSD 15 | Clang | x86_64 | (CI only) |
| OpenBSD 7 | GCC | x86_64 | `ngrep-openbsd-7-x86_64` |
| OpenBSD 7 | Clang | x86_64 | (CI only) |
| NetBSD 10 | GCC | x86_64 | `ngrep-netbsd-10-x86_64` |
| NetBSD 10 | Clang | x86_64 | (CI only) |
| Solaris 11 | GCC | x86_64 | `ngrep-solaris-11-x86_64` |
| Solaris 11 | Clang | x86_64 | (CI only) |
| Windows Latest | MSVC | x86_64 | `ngrep-windows-x86_64` |

**Note**: Clang variants provide CI validation but don't generate release artifacts (GCC builds are sufficient for distribution).

## Making Changes

### Adding a New Platform
1. Edit `matrix.yml`
2. Add to `matrix.name` array
3. Add to `matrix.include` with `artifact_name` (if releasing)
4. Add build step with appropriate `if` condition

### Changing Build Steps
1. Edit `matrix.yml`
2. Modify the relevant platform's build step
3. Changes apply to both CI and releases automatically

### Modifying Release Process
1. Edit `release.yml`
2. Modify the `create-release` job
3. Build steps remain unchanged in `matrix.yml`

## Workflow Execution

### Normal Development
```
git push → build.yml → matrix.yml (artifacts: false) → Validation only
         → docker.yml → Build & publish container → ghcr.io/jpr5/ngrep:latest
```

### Creating a Release
```
git tag -a v1.0.0 -m "Release 1.0.0"
git push origin v1.0.0 → release.yml → matrix.yml (artifacts: true) → GitHub Release
                       → docker.yml → Build & publish container → ghcr.io/jpr5/ngrep:1.0.0
```

## Version Management

ngrep uses a **centralized version system**:

- **Single Source**: `VERSION` file in repository root
- **Unix builds**: `configure.ac` reads `VERSION` → generates `config.h`
- **Windows builds**: `CMakeLists.txt` reads `VERSION` → passes to compiler
- **Result**: All builds get version from one place

See [RELEASE.md](RELEASE.md) for detailed version management documentation.

## Distribution Channels

ngrep is distributed through multiple channels:

1. **Binary Releases** - Platform-specific binaries via GitHub Releases
   - Linux (x86_64, ARM64)
   - macOS (ARM64)
   - FreeBSD, OpenBSD, NetBSD, Solaris (x86_64)
   - Windows (x86_64)

2. **Docker Containers** - Multi-architecture containers via GHCR
   - `ghcr.io/jpr5/ngrep:latest` - Latest master build
   - `ghcr.io/jpr5/ngrep:1.0.0` - Specific version
   - Alpine-based (~15-20MB)
   - Supports linux/amd64 and linux/arm64

3. **Source Code** - Via GitHub repository
   - Autotools-based build system
   - CMake for Windows
