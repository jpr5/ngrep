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

## Benefits of This Architecture

### 1. **DRY (Don't Repeat Yourself)**
- Build steps defined once in `matrix.yml`
- Changes automatically apply to both CI and releases
- Reduces maintenance burden

### 2. **Clear Separation of Concerns**
- `build.yml`: Validation only
- `release.yml`: Distribution
- `matrix.yml`: Shared build logic

### 3. **Conditional Behavior**
- Same build steps, different outcomes
- Artifacts only created when needed
- Saves storage and bandwidth

### 4. **Easy to Extend**
- Add new platform: Edit `matrix.yml` only
- Change build steps: One place to update
- Modify release process: Edit `release.yml` only

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
```

### Creating a Release
```
git tag v1.0.0
git push origin v1.0.0 → release.yml → matrix.yml (artifacts: true) → GitHub Release
```
