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
- **Windows: enforcement policy and hypervisor guard** **(unverified on Windows)**. The driver reads
  `Parameters\Enforce` (absent = automatic: enforce on bare metal, detect-only when `CPUID.1:ECX[31]` reports a
  hypervisor; `0` detect only; `1` always enforce). In detect-only mode unauthorized keyboard filters are
  reported once and left alone and unauthorized DMA is reported, not blocked. `Deploy-KernelGuard.ps1` gains
  `-Enforcement auto|detect|enforce`. The mode sits in the hashed policy block of the shared state.
- **Windows monitor: Application event log reporting** **(unverified on Windows)**. Source `KernelGuard`; events
  900-902 for the monitor, `1000 + alert code` for alerts, 1999 for a notification that failed its HMAC; the
  deploy script registers and removes the source.
- **Linux packaging:** `linux/packaging/build-deb.sh` builds a Debian package (DKMS module source, `kgmon`, systemd
  unit, udev rule, man page `kgmon(8)`, example policy and actions); `dkms.conf`. Built and DKMS-built here;
  installing the package was not tested.
- **Linux:** fuzz harness for the escalation policy parser and engine (`make -C linux/monitor fuzz`), run in CI.
- `tools/wdk_syntax_check.py`, run by the `lint` workflow: fetches the Windows 11 WDK/SDK headers from NuGet
  (about 160 MB) and type-checks every file in `windows/src` and `windows/usermode` with clang. Compile-only.
- `ROADMAP.md` (lab, pilot and production stages with checkable gates) and `docs/THREAT_MODEL.md`.
- **Linux: graduated response.** A posture ladder (NORMAL < ELEVATED < HIGH < FAIL-SAFE) replaces the single
  fixed reaction: `max_posture` bounds what the module raises by itself, ELEVATED decays after
  `posture_decay_s`, HIGH and FAIL-SAFE are stepped down by an operator (`kgmon posture set`,
  `KG_IOC_SET_POSTURE`) and announced with the new alert `POSTURE_CHANGED` (0x0032); `auto_enforce=1` switches
  on active enforcement only once the posture reaches HIGH. New ioctls `KG_IOC_GET_POSTURE` /
  `KG_IOC_SET_POSTURE` leave the existing structures untouched. New QEMU suite `posture` (68 checks).
- **Bring-your-own-vulnerable-driver (BYOVD) mitigation, both ports.** New alert codes `0x0025 VULN_DRIVER`,
  `0x0026 DRIVER_BLOCKED` (Linux only) and `0x0027 LOAD_POLICY`; `0x0024 MODULE_LOADED` is now used by both ports.
  - **Linux: driver-load gate** (`kg_modgate.c`, Module 3.5). A module notifier at `MODULE_STATE_COMING` reports and,
    while enforcing (`enforce=1`, or `auto_enforce=1` once the posture is HIGH), **refuses** a load with `EPERM`
    before `init()` runs. `mod_deny=NAME[@SRCVERSION],...` is the deny list (the name and `srcversion` are inside
    the signed ELF; `mod->build_id` does not exist on distribution kernels); `mod_lock=1` is lock mode (refuse or,
    without `enforce`, report every module not loaded when the lock was switched on and not in `mod_allow=`);
    `modgate=0` switches it off. At load it audits `module.sig_enforce`, lockdown and Secure Boot
    (`LOAD_POLICY`). A denied module that loaded raises the posture to HIGH; a refusal to ELEVATED. New ioctl
    `KG_IOC_GET_MODGATE`; `kgmon status` shows the gate and the audit. New QEMU suite `modgate` (150 checks).
  - **Linux: `kgmon modid [--entry] FILE|-`** prints the exact `mod_deny=` entry of a `.ko`, its version, whether a
    signature is appended, and its SHA-256, from a bounds-checked ELF reader (`kg_modid.c`, unit-tested in
    `kgmon selftest`; also run ad hoc under AddressSanitizer and UBSan against 300 000 mutated modules).
  - **Windows: driver-load guard** (`driver_load_guard.c`, Module 3.4) **(unverified on Windows)**. A
    `PsSetLoadImageNotifyRoutine` callback queues kernel-image paths; a worker thread computes each driver file's
    **Authenticode SHA-256** (`pe_authenticode.c`) and looks it up in a built-in table generated from
    [LOLDrivers](https://www.loldrivers.io) (Apache-2.0: 1,874 unique digests from 698 drivers, 2026-09-29) and in
    `Parameters\DriverDenyHashes` / `DriverAllowHashes`. A listed driver loaded after start (or any *malicious* one)
    raises `VULN_DRIVER` at level 2 and puts the driver in fail-safe; one already loaded at start is a warning.
    `Parameters\LockMode` reports every driver that appears after start. At load it audits HVCI, test signing and the
    Microsoft vulnerable-driver blocklist (`LOAD_POLICY`). **It cannot refuse a load**; prevention there is Code
    Integrity's blocklist and HVCI. `-LockMode`, `-DenyDriverHash` and `-AllowDriverHash` in `Deploy-KernelGuard.ps1`.
    The monitor shows the new alerts. The policy block's `Reserved0` became `LockMode` (`KG_POLICY_VERSION` 2).
  - **Tools:** `tools/import_loldrivers.py` (deterministic; `--check` reports whether the table is out of date),
    `tools/pe_authentihash.py` (an independent Authenticode digest, and the digest recorded in a signature) and
    `tools/test_pe_authenticode.py`, which builds `pe_authenticode.c` on Linux and checks it against the digests
    recorded in real Microsoft signatures (32-bit, 64-bit and ARM64), against the independent implementation, and
    against hostile input, and `tools/test_digest_table.py` for `digest_table.c` (hex parsing and lookup, tested
    against the real generated table); both also run under AddressSanitizer and UBSan, and both are in the `lint`
    workflow.

### Fixed

- **Linux: raising the posture while a monitor was off touched an uninitialised work item.** The posture ladder
  kicks the PCI/DMA and integrity monitors on every raise, and both used a stop flag that started out clear, so
  with `hw=0` or `integrity=0` (or during start-up) the kick queued a work item nobody had initialised: a kernel
  `WARNING`, and the guest wedged. The flags now start set and are cleared only after the work item exists.
  Reproduced in the QEMU guest before the fix; the `posture` suite has a regression step.

- **Windows (unverified on Windows):** the keyboard class driver was whitelisted as `Kbclass`; its name is
  `Kbdclass`. **Windows:** the shared-state hash covered counters that change at run time, so the driver entered
  fail-safe by itself on the first integrity check after any event; the counters are now outside the hashed
  range. **Windows:** the HMAC key came from `RDTSC` and the clock; it now comes from `BCryptGenRandom` and the
  channel refuses to start without it. All three compile against the 10.0.26100 WDK headers under a clang
  syntax check and have not been built with MSBuild or run.
- **Linux: the response to an IDT-hook or control-register alert did not last.** It set every CPU to
  full-spectrum, and the PMU sampler put each CPU back to its baseline strategy a few seconds later. HIGH is now
  a floor that the relax step respects.
- **Linux: a second policy-state corruption would have gone unreported** after the first was answered, because
  the once-only latch was never cleared (found by reading the code; no test can corrupt the table yet).

### Changed

- **Linux: every module load now emits one `LOAD_POLICY` alert** (from the driver-load gate's audit), *watch* when
  `sig_enforce`, lockdown or Secure Boot is off, which is the usual case on a desktop. A policy rule that matches
  `alert=*` at `level=warning` will therefore fire once per boot; match the alerts you mean. The `monitor` suite
  now expects that alert in the ring.
- `linux/monitor/Makefile` no longer loses `-I../include` when `CFLAGS` is given on the command line (every
  distribution build does), which broke `make CFLAGS=...`.
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
