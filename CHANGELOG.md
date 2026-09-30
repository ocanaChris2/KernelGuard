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
- GitHub Actions: `lint` (REUSE, versions, markdownlint, shellcheck, ruff, actionlint), `linux` (module and
  monitor build with `W=1`, sparse, monitor self-test, QEMU module tests), `codeql`, `release` (tag-driven:
  source tarball, static `kgmon`, SPDX SBOM, checksums, provenance) and a manual `windows` build.
  Dependabot keeps actions and CI tool pins current. The workflows are validated with `actionlint`;
  none has run on GitHub yet.
- **Linux: alert escalation policy in `kgmon`.** `/etc/kernelguard/policy.conf` (or `--policy FILE`) maps alerts to
  actions and escalates an incident that repeats (`repeat=N/SEC`) or stays unacknowledged (`unacked=SEC`); new
  commands `kgmon ack` and `kgmon policy check`. Actions run without a shell, with a minimal environment, in their
  own process group, killed at their timeout; policy and action files must not be writable by others; a
  notification that fails its HMAC only raises `FORGED` and never selects an action. `kgmon` speaks `sd_notify`
  (`READY`, `WATCHDOG`, `STOPPING`), and the unit is now `Type=notify` with `WatchdogSec=30`. Example policy and
  wall / webhook / mail actions in `linux/scripts/`, installed inactive by `kg-deploy.sh persist`. New QEMU suite
  `escalate` (52 checks) and unit tests in `kgmon selftest`.
- `ROADMAP.md` (lab, pilot and production stages with checkable gates) and `docs/THREAT_MODEL.md`.
- **Linux: graduated response.** A posture ladder (NORMAL < ELEVATED < HIGH < FAIL-SAFE) replaces the single
  fixed reaction: `max_posture` bounds what the module raises by itself, ELEVATED decays after
  `posture_decay_s`, HIGH and FAIL-SAFE are stepped down by an operator (`kgmon posture set`,
  `KG_IOC_SET_POSTURE`) and announced with the new alert `POSTURE_CHANGED` (0x0032); `auto_enforce=1` switches
  on active enforcement only once the posture reaches HIGH. New ioctls `KG_IOC_GET_POSTURE` /
  `KG_IOC_SET_POSTURE` leave the existing structures untouched. New QEMU suite `posture` (68 checks).

### Fixed

- **Linux: the response to an IDT-hook or control-register alert did not last.** It set every CPU to
  full-spectrum, and the PMU sampler put each CPU back to its baseline strategy a few seconds later. HIGH is now
  a floor that the relax step respects.
- **Linux: a second policy-state corruption would have gone unreported** after the first was answered, because
  the once-only latch was never cleared (found by reading the code; no test can corrupt the table yet).

### Changed

- `kgmon` no longer ignores `SIGCHLD`: helper processes (desktop notifications, policy actions) are tracked, reaped
  every poll, capped at 32, and killed with their process group when they overrun their timeout.
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
