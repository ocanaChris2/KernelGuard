# Roadmap: from lab to production

KernelGuard is **experimental**. This page says what "ready" means at each stage and which gates have to be met to
move up. A gate is something you can check, not a feeling. Items marked *(done)* are true today.

## Stage 0: lab (where the project is)

- *(done)* Linux module, `kgmon`, deploy scripts and a 13-suite QEMU/KVM test rig (328 checks); the module builds
  warning-free on kernels 6.8 to 7.0.
- *(done)* Graduated response and an escalation policy on Linux, both tested end to end in QEMU.
- *(done)* Continuous-integration workflows written and linted (lint, Linux build and QEMU tests, CodeQL, release).
  **None has run on GitHub yet.**
- *(done)* The Windows sources type-check against the Windows 11 (10.0.26100) WDK and SDK headers with clang
  (`tools/wdk_syntax_check.py`, part of the `lint` workflow). That is a compile check, not an MSBuild build.
- Windows driver and monitor exist and build on the maintainer's machine; **nothing in this repository has been built
  or run on a hosted Windows runner**, and the driver is test-signed with HVCI off.

## Stage 1: pilot (a handful of machines you can reach quickly)

To enter:

- [ ] CI is green on `main` for `lint`, `linux` and `codeql`; the manual `windows` workflow has built the driver and
      monitor at least once on a hosted runner.
- [ ] Windows: a hypervisor guard (`CPUID` leaf 1 ECX bit 31) so the driver does not neutralise a hypervisor's
      keyboard filter, and a detect-only mode selected by the registry, matching Linux's `enforce=`.
- [ ] Windows: the shared-state hash stops covering counters that change at run time (the driver otherwise enters
      fail-safe by itself; see *Observation 1* in the Linux README).
- [ ] A tagged release with checksums, an SPDX SBOM and build provenance.
- [ ] Linux: packaging that survives a kernel update (DKMS or a distribution package) with the module re-signed
      for Secure Boot.
- [ ] Validated on at least three real hardware models per platform, including one AMD, with the keyboard allow-list
      checked on each and assistive technology tested.
- [ ] Recovery procedures rehearsed: stopping the driver without the local keyboard, and posture reset on Linux.
- [ ] Alerts reach a system staff watch (syslog/CSV forwarded, the escalation policy wired to a real webhook or mail).

To stay: one patch cycle (kernel update, Windows hotfix) with no unexplained fail-safe, and every alert explained.

## Stage 2: production

- [ ] Windows: production signing (EV certificate and Microsoft attestation or WHQL) and operation with HVCI on
      (or a documented reason it cannot be), Secure Boot on.
- [ ] Windows: HMAC key sealed to the TPM instead of derived from `RDTSC` and time; ECAM (MCFG) and VT-d (DMAR)
      discovery implemented, or the DMA half removed from the documentation.
- [ ] Baselines persisted where a reboot cannot rewrite them (TPM NV index or a signed file), removing
      trust-on-first-use for the load-time state.
- [ ] The kernel-facing code reviewed by someone independent, and the ioctl / `mmap` surface fuzzed (syzkaller
      descriptions or an equivalent harness) for a stated time without findings.
- [ ] A soak of at least 30 days on the pilot fleet with no unexplained alerts, then a written upgrade and
      rollback procedure that has been used once.
- [ ] A support policy: which OS and kernel versions, how long, how vulnerabilities are handled (see
      [SECURITY.md](SECURITY.md)).

## Beyond

Ideas that are not commitments: a Windows counterpart of the graduated response and the escalation policy
(Event Log, then a policy engine in the monitor), per-tenant policies for multi-user hosts, ARM64 for Linux.

## How this page is kept honest

A gate moves to *(done)* only with the evidence in the same pull request: a CI run, a test, a release, a review
report. Anything that could only be checked by reading the code stays unchecked and says so.
