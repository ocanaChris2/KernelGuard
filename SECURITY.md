# Security policy

KernelGuard is a Ring 0 / kernel-module project. Bugs in it can crash a machine or weaken the
protection it is meant to give, so please report security problems privately.

## Reporting a vulnerability

Use GitHub's private reporting: **Security → Report a vulnerability** on
<https://github.com/ocanaChris2/KernelGuard/security/advisories/new>.

Please include the affected component (Windows driver, Linux module, `kgmon`, build or deploy
scripts), the version (`kgmon --version`, or the `DriverVer` in `KernelGuard.inf`), the OS and
kernel build, and steps to reproduce. A crash log or `dmesg` excerpt helps.

Please do not open a public issue for anything that lets an attacker bypass detection, forge or
suppress alerts, or crash a machine.

The maintainer aims to acknowledge a report within 7 days. This is a small project without a bug-bounty
programme; fixes are released as soon as they are verified and reporters are credited unless they
ask otherwise.

## Supported versions

Only the latest release and the `main` branch receive fixes.

## Scope

In scope: privilege escalation or denial of service through the driver/module interfaces (IOCTLs,
shared-memory ring, `/dev/kernelguard`), HMAC or sequence-number bypass, ways to disable the
protection without raising an alert, and unsafe defaults in the deploy scripts.

Out of scope (documented limitations, see the README's *Known limitations*): attacks that
require a kernel compromise present before the baseline is taken (trust on first use), passive
inline hardware keyloggers, and the test-signing setup used for pilots.
