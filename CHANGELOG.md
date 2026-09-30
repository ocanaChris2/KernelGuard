# Changelog

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). The current version lives in [`VERSION`](VERSION);
`tools/version.py` keeps the copies embedded in the sources in step.

Changes to `windows/` cannot be built or run on the maintainer's Linux host. Those entries are
marked **(unverified on Windows)** until a Windows CI run or a manual test confirms them.

## [Unreleased]

### Added

- Per-directory licensing (`linux/` GPL-2.0-only, everything else MIT) with `LICENSES/` and a
  REUSE-compliant `REUSE.toml`.
- `VERSION` file and `tools/version.py` to keep the embedded versions consistent.
- `SECURITY.md`, `CONTRIBUTING.md`, `.editorconfig`, `.gitattributes`, issue and pull-request templates.

### Changed

- SPDX identifiers in `linux/` normalized from the deprecated `GPL-2.0` to `GPL-2.0-only`.
- README corrected against the Windows source: RDTSC/CR4.TSD handling, PMU alert codes and the
  DMA half of Module 2 are documented as inactive; removed the CMake section (no CMake files exist).
- `windows/scripts/stop_driver.bat` now stops and deletes the `KernelGuard` service (it named a
  stale `ScpdDriver`). **(unverified on Windows)**

### Removed

- 95 build artifacts (MSBuild output, `.obj/.pdb/.sys/.exe`) and a local PowerShell transcript are
  no longer tracked; they remain ignored via `.gitignore`.

## [1.0.0]

Initial Windows driver and monitor, Linux port (module, `kgmon`, QEMU test suite), interactive
`build.py`.
