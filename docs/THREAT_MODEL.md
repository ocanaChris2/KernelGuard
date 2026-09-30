# Threat model

What KernelGuard is meant to stop, what it assumes, and what it does not try to do. It condenses the
per-module discussions in the [README](../README.md#real-world-attack-scenarios) and the
[Linux README](../linux/README.md); where the two differ, the platform-specific text wins.

## What is protected

| Asset | Why it matters |
| --- | --- |
| Keystrokes (passwords, PINs, card numbers) typed on a machine strangers or other tenants can touch | The main prize of a hardware or kernel keylogger |
| Integrity of the running kernel (its code, IDT, syscall and control-register state, input callbacks) | A patched kernel can hide anything, including this project |
| Secrets in memory that a co-resident attacker could read through the cache or microarchitectural state | Side channels turn shared hardware into a leak |
| The alert channel: an operator seeing the truth about the three assets above | An attacker who can silence or forge alerts wins quietly |

## Adversaries

| Adversary | Capability assumed | In scope |
| --- | --- | --- |
| **Walk-up attacker** | Minutes alone with the case, ports and cables of a public or shared machine; can plug in devices | Yes: rogue PCIe/Thunderbolt/M.2 devices, keyboard-path drivers they get loaded |
| **Local unprivileged user** | Runs code, no admin rights; wants to read another process's data through the cache | Yes: Module 1 detects the pattern (Linux: names the offender); mitigation is per CPU and reactive |
| **Local administrator or malware that reaches ring 0 after KernelGuard loaded** | Loads a driver or module, patches kernel code, hooks the IDT or an input callback | Yes: Module 3 detects it; the response is graduated (Linux) or fail-safe (Windows) |
| **Privileged attacker bringing a signed, vulnerable driver or module (BYOVD)** | Has administrator or root; loads a driver or module that is legitimately signed but has a known kernel read/write bug, to get a primitive that driver signing was meant to deny, then uses it against KernelGuard or the kernel | Partly: Linux refuses a listed module while enforcing; Windows reports a listed driver, enters fail-safe and audits the OS's own defences (it cannot refuse a load). A vulnerable driver nobody has listed is not recognised |
| **A rootkit trying to hide from KernelGuard** | Can hook dispatch routines, drop or forge notifications, replay old ones | Partly: the HMAC ring, sequence numbers and (Linux) the `FORGED` / `OVERRUN` / `TAMPER` alerts catch forgery, suppression and replay *while the monitor runs and the module is intact* |
| **A kernel already compromised before load** | Owns the machine at boot | **No.** Baselines are taken at load (trust on first use); Secure Boot and measured boot are the answer |
| **Passive hardware keylogger, USB HID injector** | Invisible to the OS or indistinguishable from a keyboard | **No.** Inspection and USB policy are the answer |
| **Network attacker** | Remote, no code on the host | **No.** Not a network security product |

## Trust boundaries and assumptions

- **Load-time baseline.** IDT, `.text`, input handlers and PCI devices present at load are trusted (Linux: also
  a trust-on-first-use baseline of bus masters). Load early, from a state you inspected.
- **The module or driver stays loaded and the monitor stays running.** Removing either is invisible to the
  other. Treat a missing monitor or module as an alert: the provided systemd unit restarts a hung monitor
  (watchdog) and `udev` logs critical alerts even when the monitor is dead.
- **The HMAC key** is generated per boot by the kernel side and handed only to a privileged monitor. On Windows it is
  derived from `RDTSC` and time (weak; see Known limitations), on Linux from `get_random_bytes()`.
- **The deny lists are third-party or operator data.** The Windows table is a snapshot of the public LOLDrivers
  dataset (Apache-2.0), refreshed with `tools/import_loldrivers.py`; it lists drivers that legitimate software also
  installs, which is why a listed driver that was already loaded at boot is only a warning, and why an operator can
  vouch for an exact build (`DriverAllowHashes`). The Linux gate ships with no list: the operator builds one.
- **Identity is only as good as the signature.** The Linux gate matches a module by the name and `srcversion` inside
  its signed ELF, which cannot be renamed around while signatures are enforced; the Windows driver matches the
  Authenticode digest, because a Windows file name is not signed. If the OS does not enforce signatures an attacker
  needs no vulnerable driver, and the load-policy audit (`LOAD_POLICY`) says whether it does.
- **Root is trusted on Linux** to reset the response posture (`kgmon posture set`); that is audited in the ring
  (`POSTURE_CHANGED`) and refused when the policy state was found corrupted. An attacker with root can also simply
  unload the module, or write `enforce=0` / `mod_lock=0`, which switches the driver-load gate off:
  KernelGuard raises the cost, it is not a barrier against a compromised administrator.
- **Escalation actions run as root.** The policy file and every action program must be root-owned and not writable
  by others; notifications that fail authentication never select an action.

## Coverage by module

| Module | Detects | Reacts | Blind spots (see the README's *Known limitations*) |
| --- | --- | --- | --- |
| M1 PMU side-channel | abnormal cache-miss rates; Linux names the top user task | flush and full-spectrum on the affected core and SMT siblings; posture ELEVATED | a miss-rate detector cannot tell Flush+Reload from a memory-bound workload; the Windows PMU path does not notify the monitor |
| M2 keylogger / DMA | unauthorised keyboard-path handlers or filter drivers; bus masters that were not there at load; hidden or mismatched PCI devices | alert; with enforcement, detach the handler or clear bus mastering (Linux: `enforce=1`, or automatically at posture HIGH with `auto_enforce=1`) | Windows DMA half is inactive (`PciGetEcamBaseFromAcpi` is a stub); a passive inline keylogger; false positives on non-standard hardware |
| M3 kernel integrity | IDT and syscall-MSR/CR tampering, `.text` patches (with a classifier for benign ftrace/jump-label patching), input-callback hijacks, suspicious module loads | posture HIGH or FAIL-SAFE | not exercised against BPF/kprobe-heavy tooling, livepatch or proprietary modules on real hardware |
| M3.5 driver-load gate (BYOVD) | a listed vulnerable or malicious driver or module being loaded (Linux: by name and `srcversion`; Windows: by Authenticode SHA-256); in lock mode any driver that appears after start; whether the OS's own defences (`sig_enforce`, lockdown, Secure Boot / HVCI, test signing, the Microsoft blocklist) are on | Linux: refuse the load while enforcing, posture HIGH if a listed module ran. Windows: fail-safe for a listed driver loaded after start; never refuses | a vulnerable driver that is on no list; a driver loaded before KernelGuard started (reported, not refused); Linux sees only the module loader (not built-in code, kexec, `/dev/mem`, BPF); on Windows the driver's `DriverEntry` may already have run when the report arrives; a root or administrator attacker who unloads the guard first |
| M4 mitigation | shared-state corruption | strategy per CPU, flush, fail-safe | Windows never installs its per-context-switch hook; Linux relies on the kernel's own mitigations plus one-shot flushes |
| M5 communication | forged, suppressed, lost or replayed notifications | authenticated ring, sequence numbers, uevent fallback, escalation policy | the Windows MSR fallback has no reader; a rootkit that owns the monitor's machine can still stop the monitor |

## Non-goals

Full-disk or boot-chain protection, USB device control, user-mode malware, network intrusion, protecting a machine
whose kernel was compromised before KernelGuard loaded, and defending against a fully privileged local attacker who
is willing to unload the driver. Preventing a Windows driver load is also outside what this driver can do: the
Microsoft vulnerable-driver blocklist and HVCI are the prevention there, and the driver only reports whether they
are on. The [Usage recommendations](../README.md#usage-recommendations) list what to put
around KernelGuard for each.

## Change control

Anything that changes what is detected, what is trusted or who may change the posture updates this document in the
same pull request. Report weaknesses privately: see [SECURITY.md](../SECURITY.md).
