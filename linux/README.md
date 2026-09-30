# KernelGuard for Linux

A Linux x86-64 loadable kernel module (`kernelguard.ko`) plus a user-space monitor (`kgmon`) that
implement the same five modules as the Windows driver in this repository — side-channel detection and
mitigation, hardware-keylogger and DMA detection, kernel-integrity monitoring, a cache/microarchitectural
mitigation engine, and an authenticated kernel→user alert channel.

This is a **port, not a transliteration.** Several Windows techniques (raw PMU/APIC programming, editing
VT-d tables, writing `IA32_SPEC_CTRL`, patching another driver's dispatch table, a covert MSR channel) are
either impossible or actively harmful on Linux, because Linux subsystems own the state they poke.
Each such case is replaced by the mechanism Linux actually supports, and every deviation is listed in
[What differs from the Windows driver](#what-differs-from-the-windows-driver).

---

> **READ BEFORE LOADING**
>
> This is Ring-0 code. It was load-tested **only inside throw-away QEMU/KVM guests** (kernels 7.0.0-31 and
> 6.14.0-29) — never on real hardware. Keep a recovery plan and try it on a machine or VM you can afford to
> reboot. See [Safety model](#safety-model) and [Recovery](#recovery).
>
> On a **Secure Boot** system (like the one this was developed on: `sig_enforce=Y`, lockdown `integrity`)
> an unsigned module will not load at all; see [Secure Boot and module signing](#secure-boot-and-module-signing).

---

## Table of contents

- [Safety model](#safety-model)
- [What differs from the Windows driver](#what-differs-from-the-windows-driver)
- [Architecture](#architecture)
- [Module details](#module-details)
- [Graduated response](#graduated-response)
- [Prerequisites](#prerequisites)
- [Repository layout](#repository-layout)
- [Build](#build)
- [Secure Boot and module signing](#secure-boot-and-module-signing)
- [Deploy](#deploy)
- [The monitor: `kgmon`](#the-monitor-kgmon)
- [Alert protocol](#alert-protocol)
- [ioctl and mmap reference](#ioctl-and-mmap-reference)
- [Module parameters](#module-parameters)
- [Tuning and false positives](#tuning-and-false-positives)
- [Testing](#testing)
- [Security design notes](#security-design-notes)
- [Known limitations](#known-limitations)
- [Recovery](#recovery)
- [Licence](#licence)

---

## Safety model

| Behaviour | Windows driver | Linux module |
| --- | --- | --- |
| Detects and reports | yes | yes |
| Takes **active** mitigation (clears PCI bus mastering, detaches an input handler) | always | **only with `enforce=1`**; default is detect-only |
| Writes MSRs it does not own | `SPEC_CTRL`, PMU, `0x150` | only `IA32_FLUSH_CMD` and `IA32_PRED_CMD` (one-shot commands) |
| Can be switched off at run time without unloading | no | `echo 0 > /sys/module/kernelguard/parameters/enforce` |
| Reaction to a kernel-integrity alert | fixed; fail-safe until unload | a [posture ladder](#graduated-response): bounded by `max_posture`, stepped down by an operator without unloading |
| Fatal init failures | M3, M4, M5 | core only (state, channel, mitigation, device); the four monitors degrade |

The Windows README documents keyboard loss on VMs and on non-standard hardware as the price of acting
unconditionally. On a Linux workstation that default would be hostile, so acting is opt-in.

**What the module can break even in detect-only mode:** nothing it does is destructive, but it does hold
~25–100 MiB of kernel memory for text baselines (see [Tuning](#tuning-and-false-positives)), takes NMIs
from two perf counters per CPU, and taints the kernel (out-of-tree + unsigned unless you sign it).

---

## What differs from the Windows driver

| Area | Windows driver | Linux port | Why |
| --- | --- | --- | --- |
| **M1 counters** | Programs `IA32_PERFEVTSELx/PMCx/PERF_GLOBAL_*` directly, maps the xAPIC, connects vector `0xE4` | Two kernel **perf counters per CPU** (L1D read-miss, last-level-cache miss) with an overflow handler that runs in NMI context | `perf` owns the PMU, the LVT entry, the NMI handler and one counter for the NMI watchdog. Generic events also map to the right raw event on every Intel/AMD/hybrid CPU instead of hard-coded Skylake encodings |
| **M1 L2 counter** | `L2_RQSTS.MISS` | Last-level-cache miss (`ALERT_PMU_L2_ANOMALY` code kept) | `perf` has no generic L2 event; the LLC is what cross-core attacks work on |
| **M1 escalation** | 3 overflows *ever* → critical forever | Overflows/second per CPU, hysteresis, decay after 3 quiet windows, offender attribution | Windows never decays, so any system ends up permanently "critical"; and its PMI path never notifies user mode at all |
| **M1 RDTSC trap** (`CR4.TSD`) | Implemented but **disabled** in the shipped driver | Not implemented (`ALERT_PMU_RDTSC_RATE` reserved, never emitted) | Without hooking the IDT, `CR4.TSD` makes the vDSO's `clock_gettime()` SIGSEGV and breaks most programs. Per-thread `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` is the supported alternative |
| **M2 ECAM** | `PciGetEcamBaseFromAcpi` is an unimplemented stub | MCFG parsed for real; tree walked by following bridge secondary-bus registers | — |
| **M2 discrepancy** | Claimed in the README, not implemented | ECAM view vs. PCI-core view: hidden / missing / identity mismatch, debounced over two scans | — |
| **M2 authorisation** | Empty allow-list ⇒ *every* DMA device is "unauthorised" | Everything present at load is authorised (trust on first use) + `dma_allow=` | With the Windows default, wiring up VT-d/ECAM would cut off the boot disk |
| **M2 VT-d edits** (clear context entry, register-based invalidation) | Tier 1 | **Not ported**; the IOMMU is *audited* through the IOMMU API and reported | `intel-iommu`/`amd-iommu` keep private copies of those tables, serialise with their own locks and use queued invalidation; a module writing them races the driver and can take down DMA for every device |
| **M2 BME clear** | Tier 2 | Through the PCI core, verified against ECAM, raw ECAM write if the OS view disagrees | same intent, done safely |
| **M2 keyboard "filters"** | Walk `KeyboardClass0..9` device stacks, whitelist by driver name | Walk every keyboard's **input handlers** (`dev->h_list`); stock names + load-time baseline + `kbd_allow=` | A Linux kernel keylogger is an `input_handler`; the handle list is the device stack |
| **M2 neutralise** | Overwrite the foreign driver's `MajorFunction[]`; `IoDetachDevice` | Unlink the offender's `input_handle` from `dev->h_list`, leave its node self-linked | A handler's function pointers cannot be replaced without racing the event path; unlinking is exactly `IoDetachDevice`, and the self-link makes the owner's later `disconnect()` harmless (tested) |
| **M3 IDT** | Current CPU, 3 vectors, range check | **Every CPU**, all 256 vectors against a baseline, plus `MSR_LSTAR/CSTAR/STAR/SYSCALL_MASK/SYSENTER_EIP`, `CR0.WP`, `CR4` pins, `SPEC_CTRL.IBRS` (read-only) | The syscall MSR and `CR0.WP` are what Linux rootkits actually touch |
| **M3 dispatch hooks** | 6 prologue byte patterns | Handler callbacks must resolve to a symbol in the **same module as their handler**; entry must not `JMP`/`PUSH-RET`/`MOV-JMP` into a *different* module | Prologue bytes alone false-positive on `endbr64`/`__fentry__`/kprobes |
| **M3 `.text`** | SHA-256 per module, compared constant-time | **Baseline copy** + classification of every difference (see below), kernel image *and* all modules | Linux kernel text legitimately self-modifies (jump labels, ftrace, static calls, kprobes); a plain hash would fire the first time anyone runs `perf` |
| **M3 module loads** | (mentioned in comments, never done) | `register_module_notifier`: baselines follow modules; every load is reported (unsigned ⇒ warning) | — |
| **M4 strategy** | `ARCH_CAPABILITIES` bits | The kernel's own `X86_BUG_*` determination (covers CPUs identified by model) | The Windows header aliases `L1TF_NO` and `SSB_NO` to bit 4 and never sets `CPU_FEAT_IBPB` |
| **M4 `VERW`** | MASM routine, selector `0x2B` | Inline `verw` (memory operand) with `__KERNEL_DS` | same instruction; the memory form is the one documented to clear buffers |
| **M4 `SPEC_CTRL`** | Sets/clears IBRS/STIBP | **Never written.** Escalation uses one-shot IBPB | The kernel caches and rewrites it per CPU/task; clearing bit 0 on an eIBRS CPU silently weakens the whole system |
| **M4 CAT** | Programs `PQR_ASSOC` / `L3_MASKn` | Capability probe + the same partition plan; applied through **resctrl** | resctrl owns those MSRs |
| **M4 sensitive processes** | Page registry + a context-switch hook that nothing registers | `kg_sens_alloc()/kg_sens_free()` registry (exported) and `kgmon run --sensitive` (L1D flush, IBPB/STIBP, SSBD, core scheduling) | The kernel already has per-task controls for exactly this |
| **M4 shared-state hash** | Hashes counters that change on every alert | Hash covers the policy table only; counters live outside it | Windows' `VerifySharedStateIntegrity` fails, and enters fail-safe, as soon as anything happens after load |
| **M5 ring** | MDL-mapped section, writable mapping, publish race between writers | One page, **read-only** `mmap`, seqlock-style slots (`magic` = 0 while rewritten), `poll()` wake-up | see [Alert protocol](#alert-protocol) |
| **M5 key** | `RDTSC ⊕ system time` | `get_random_bytes()` | — |
| **M5 fallback** | Write an alert code to MSR `0x150` | **uevent** (`KOBJ_CHANGE`) + kernel log | `0x150` is `#GP` on most CPUs, has no reader, and an implemented-but-unrelated MSR would be corrupted. uevents reach udev/systemd with no polling |
| **Monitor** | Tray icon, balloon, log window | `kgmon`: stdout, CSV log (same columns), syslog, `notify-send`, `status`, `run` | — |
| **Install** | `windows/scripts/Deploy-KernelGuard.ps1`, test-signing | `scripts/kg-deploy.sh`, Secure Boot MOK signing | — |
| **Emergency stop** | `windows/scripts/stop_driver.bat` | `scripts/kg-stop.sh` | — |
| **Boot start** | INF `SERVICE_SYSTEM_START` | `persist` → `modules-load.d` | — |

### Observations about the Windows implementation

Found while porting; nothing on the Windows side was changed. All are checkable in the source.

1. `VerifySharedStateIntegrity()` hashes the range `[0, StateLock)` of `DRIVER_SHARED_STATE`, which contains
   counters incremented by `SecureCommNotify`, `LogAlert`, the DMA/discrepancy paths, etc. The hash is
   computed once (`UpdateSharedStateHash()` in `DriverEntry`) and never refreshed, so the first 30-second check
   after any counter moved raises `ALERT_SHARED_STATE_CORRUPT` and enters fail-safe.
2. `PmiIsr` updates counters and flushes but never calls `SecureCommNotify`/`DispatchCrossModuleEvent`, so
   PMU anomalies are never delivered to the monitor.
3. `HardenedKeyboardIsr`, `SensContextSwitchHook` (and through it `SmtIsolateSensitiveProcess`,
   `CatAssignClos`, `IsProcessSensitive`), `RdtscGpHandler` and `EnableTSD` have no caller.
4. `IsAuthorizedDmaDevice` reads an empty list; once `g_VtdMmioBase`/`g_EcamBase` are populated, every device
   is "unauthorised" and its context entry / BME is cleared.
5. `IA32_ARCH_CAPABILITIES`: `ARCH_CAP_L1TF_NO` and `ARCH_CAP_SSB_NO` are both `1<<4`; `CPU_FEAT_IBRS_ALL` is
   set from CPUID.7 EDX[26] (IBRS/IBPB) rather than the MSR; `CPU_FEAT_IBPB` is never set.
6. `PciEcamRead/Write` use `Bus << 20` without subtracting the MCFG start bus number.
7. `windows/scripts/stop_driver.bat` stops and deletes a service named `ScpdDriver`, while the README and deploy script name
   it `KernelGuard`, so the documented recovery script does not match the installed service.
8. The MSR "covert channel" writes MSR `0x150` (described as both `IA32_SMRR_PHYSBASE` and an alias of
   `IA32_MCG_CAP`, which is `0x179`); there is no reader for it.

---

## Architecture

```text
┌────────────────────────────────────────────────────────────────────┐
│                     user space                                     │
│  kgmon ── mmap(/dev/kernelguard) read-only ring ── verifies HMAC   │
│    │      poll() wake-up, ioctl(GET_HMAC_KEY / GET_INFO / CPU_INFO)│
│    └── stdout · CSV · syslog · notify-send        udev ◄── uevent  │
└──────────────────────────────┬─────────────────────────────────────┘
                               │
┌──────────────────────────────▼─────────────────────────────────────┐
│                     kernelguard.ko                                 │
│                                                                    │
│  ┌────────┐  ┌───────────────┐  ┌──────────┐  ┌───────────────┐    │
│  │ M1 PMU │  │ M2 hardware   │  │ M3       │  │ M4 mitigation │    │
│  │ perf   │  │  kg_hw  PCI   │  │ integrity│  │  strategy per │    │
│  │ NMI    │  │  kg_input kbd │  │ text/IDT │  │  CPU, VERW,   │    │
│  └───┬────┘  └──────┬────────┘  └────┬─────┘  │  L1D, IBPB    │    │
│      │              │                │        └───────▲───────┘    │
│      └──────────────┴────────────────┴────────────────┘            │
│                 kg_report() → kg_dispatch()  (cross-module events) │
│                              │                                     │
│                      ┌───────▼────────┐                            │
│                      │ M5 kg_comms    │  HMAC ring · uevent · log  │
│                      └────────────────┘                            │
└────────────────────────────────────────────────────────────────────┘
```

**Context rules** (the Linux analogue of the IRQL discipline):

| Context | What may run |
| --- | --- |
| NMI | `kg_pmu` overflow handler **only**: per-CPU atomics, a forced `VERW`/L1D flush, `irq_work_queue()`. No locks, no allocation, no `kg_report()` |
| process context | everything else, including `kg_report()` (which takes a spinlock, computes an HMAC and never sleeps) |

Init order (as `DriverEntry`): state → secure channel → mitigation engine → integrity baseline (captured
*before* any monitor starts) → PCI/DMA → keyboard path → PMU → device node last. Unload is the reverse.

### Cross-module event flow

| Trigger | Response | Posture |
| --- | --- | --- |
| M1 critical cache-miss rate on a CPU | M4 escalates that CPU **and its SMT siblings** to full-spectrum and flushes them | ELEVATED |
| M2 unauthorised bus master | M4 flush per the CPU's strategy | ELEVATED |
| M2 PCI discrepancy | M3 immediate keyboard-path scan | ELEVATED |
| M2 unauthorised keyboard handler, handler neutralised, bus mastering cleared | alert only (plus enforcement when enabled) | ELEVATED |
| M3 suspicious module load | alert only | ELEVATED |
| M3 IDT / syscall MSR / `CR0.WP` / `CR4` tamper | M4 full-spectrum on every CPU, held as a floor | HIGH |
| M3 critical `.text` patch or input-callback hook | fail-safe: full-spectrum everywhere | FAIL-SAFE |
| M4 policy-state hash mismatch | fail-safe | FAIL-SAFE |

Every raise is bounded by `max_posture`; see [Graduated response](#graduated-response).

--- | --- |
| M1 critical cache-miss rate on a CPU | M4 escalates that CPU **and its SMT siblings** to full-spectrum and flushes them |
| M2 unauthorised bus master | M4 flush per the CPU's strategy |
| M2 PCI discrepancy | M3 immediate keyboard-path scan |
| M3 IDT / syscall MSR / `CR0.WP` / `CR4` tamper | M4 full-spectrum on every CPU |
| M3 critical `.text` patch or input-callback hook | fail-safe (full-spectrum everywhere, irreversible until unload) |
| M4 policy-state hash mismatch | fail-safe |

---

## Module details

### Module 1 — side-channel detection (`kg_pmu.c`)

- Per online CPU, two kernel perf counters with a sample period: **L1D read misses** (period 100000) and
  **LLC misses** (period 20000). CPU hotplug is handled with `cpuhp`; a CPU coming online never fails
  because of us. Counters are not pinned, so they coexist with `perf stat`.
- The overflow handler runs in **NMI** context. It increments a per-CPU atomic, keeps a Boyer–Moore
  majority vote of the user-mode task that was running (the *offender*), and when the per-window count
  reaches the critical threshold it runs an unconditional `VERW` + L1D flush (Windows `PmiIsr` does the same).
- A 1-second sampler converts counts to overflows/second per CPU/event, applies warn/critical thresholds with
  hysteresis (3 quiet windows to de-escalate; at least 1 s between alerts for a CPU/event; repeat every 10 s
  while it lasts) and raises `ALERT_PMU_L1D_ANOMALY` / `ALERT_PMU_L2_ANOMALY` naming the offender.
- The module never alarms on itself: its own multi-MiB integrity scans run with a per-CPU flag that the NMI
  handler honours.
- Tunables are sanitised (`warn ≥ 1`, `crit > warn`, sample period ≥ 1000) so a typo cannot cause an NMI storm.

**Alerts:** `ALERT_PMU_L1D_ANOMALY`, `ALERT_PMU_L2_ANOMALY` (LLC).

### Module 2 — hardware keylogger and DMA detection (`kg_hw.c`, `kg_input.c`)

*PCI / DMA (`kg_hw.c`)*

- **Discovery:** the ACPI MCFG table gives the ECAM regions; each bus is mapped (1 MiB, uncached) and the
  tree is walked by following bridge secondary-bus registers, seeded from the MCFG start bus and the OS's
  root buses. No MCFG ⇒ the DMA audit falls back to the OS view (tested on QEMU's `pc` machine).
- **Cross-check:** hardware view vs. PCI core → `hidden from OS`, `missing in hardware`,
  `identity mismatch` (`ALERT_PCI_DISCREPANCY`). Debounced over two scans; powered-off devices (D3cold, or
  behind a bridge in D3cold — e.g. a hybrid-graphics dGPU) are not reported as missing.
- **DMA audit:** an endpoint with `Command.BME` set that is not authorised is an
  `ALERT_UNAUTHORIZED_DMA`. Authorised = present at load (hardware **and** OS view) or in `dma_allow=`.
  Severity is critical when the device is external-facing/untrusted *and* has no IOMMU translation.
  A PCI bus notifier re-scans shortly after a hot-add or driver bind.
- **`enforce=1`:** clears bus mastering through the PCI core, verifies against ECAM, and writes ECAM directly
  (16-bit write — the Status half of the dword is write-1-to-clear) if the OS view disagrees; re-applied every
  scan; announced once (`ALERT_DEVICE_BME_DISABLED`). Bridges are never touched.
- `ALERT_DMA_BLOCKED_IOMMU` is defined for parity and never emitted — see the table above.

*Keyboard path (`kg_input.c`)*

- Registers an `input_handler` matching devices that have `KEY_A` and `KEY_ENTER`. Its handle is
  registered but **never opened**: the module receives no keystrokes and does not keep hardware powered.
- **Identity:** handlers other than the stock ones (`kbd, evdev, sysrq, leds, rfkill, mousedev, joydev`),
  the load-time baseline, or `kbd_allow=` raise `ALERT_UNAUTHORIZED_KBD_FILTER` — **critical if the handle is
  open** (it is receiving keys), a warning otherwise.
- **Integrity** (`ALERT_DISPATCH_HOOK`, shared with Module 3): each of a handler's seven callbacks must
  resolve to a kernel/module symbol, live in the same module as the handler, and must not begin with a
  detour into a different module.
- **`enforce=1`:** the offender's handle is unlinked from `dev->h_list` (and an exclusive grab is released).
  Re-evaluated every scan. Not re-attached on unload.

### Module 3 — kernel integrity (`kg_integrity.c`)

1. **CPU control state, on every CPU.** IDT gates (all 256, against a baseline; handlers must lie in kernel
   text), `MSR_LSTAR/CSTAR/STAR/SYSCALL_MASK/SYSENTER_EIP`, `CR0.WP`, `CR4.{SMEP,SMAP,UMIP,FSGSBASE}`, and —
   only where eIBRS makes it a constant — `SPEC_CTRL.IBRS`. FRED systems skip the IDT check.
2. **Input-path hooks** — see Module 2.
3. **`.text` of the kernel image and of every module (including this one).**
   The kernel image bounds come from the page tables (`_stext/_etext` are not exported): the contiguous
   read-only + executable run that contains a known function. A baseline **copy** is kept and compared
   every `integrity_interval_ms`; a difference is sampled twice (20 ms apart, to skip `text_poke`
   transients), then classified:

   | Difference | Verdict |
   | --- | --- |
   | `NOP5 ↔ CALL/JMP rel32`, `CALL ↔ CALL` (new target), `JMP ↔ JMP`, `CALL ↔ JMP`, target inside kernel text / same module / (for `CALL`) any module or the module area | **benign** – counted, not reported (jump labels, ftrace, static calls) |
   | `NOP2 (66 90) ↔ JMP8 (EB xx)`, including several adjacent sites flipping together | **benign** |
   | `JMP` from arbitrary bytes into unknown module-area code | watch (optimised kprobe) |
   | a lone `0xCC` appearing/disappearing | watch (kprobe breakpoint) |
   | `static_call` NULL/RET0 forms (`xor eax,eax`, `ret`) | watch — also what "neutralise this check" looks like |
   | a branch whose target is not known code; **anything else** | **critical** `ALERT_TEXT_PATCH` → fail-safe |

   Each modification is reported once (the new bytes become the baseline).
4. **Module lifecycle.** A module notifier adds/removes baselines and reports every load
   (`ALERT_MODULE_LOADED`, *watch* if unsigned).
5. **Policy-state hash** verification (Module 4's table).

### Module 4 — mitigation engine (`kg_mitigate.c`)

- **Probe** on each CPU (via `cpuhp`, so hot-added CPUs are covered): `ARCH_CAPABILITIES`, `MD_CLEAR`,
  `FLUSH_L1D`, `IBPB`, SMT, CAT. **Strategy** (same decision table as Windows, driven by
  `X86_BUG_{MDS,TAA,MMIO_STALE_DATA,RFDS,L1TF}`): none / VERW / L1D / VERW+L1D / full-spectrum.
  On a CPU that is not affected the strategy is `none` and routine events flush nothing.
- **Flush** follows the CPU's current strategy; full-spectrum adds `LFENCE` and an IBPB barrier (IBPB is
  never issued from the NMI path).
- **SMT:** an anomaly on one thread escalates and flushes its siblings, and they stay escalated while their
  core partner stays critical (tested with a 2-core × 2-thread guest).
- **CAT:** presence and the partition Windows would use (top quarter of the ways for sensitive work) are
  reported; apply it with resctrl:

  ```sh
  sudo mount -t resctrl resctrl /sys/fs/resctrl
  sudo mkdir /sys/fs/resctrl/sensitive
  echo "L3:0=<sensitive mask>" | sudo tee /sys/fs/resctrl/sensitive/schemata
  echo "L3:0=<default mask>"   | sudo tee /sys/fs/resctrl/schemata
  echo <PID> | sudo tee /sys/fs/resctrl/sensitive/tasks
  ```

  (masks are shown by `kgmon status` on CAT-capable CPUs).
- **Sensitive allocations:** `kg_sens_alloc()` / `kg_sens_free()` / `kg_sens_pfn_tagged()` (`EXPORT_SYMBOL_GPL`)
  track tagged buffers and zero them on free. The module uses it for its own key material.
- **Fail-safe:** every CPU switches to full-spectrum and everything is flushed once. It is the top rung of the
  [posture ladder](#graduated-response): it stays until an operator steps it down (`kgmon posture set`) or the
  module is unloaded.
- User-controlled indices (`KG_IOC_GET_CPU_INFO`) go through `array_index_nospec()`.

### Module 5 — secure communication (`kg_comms.c`)

- **Primary:** one page mapped **read-only** into the monitor. Every notification carries HMAC-SHA256 and a
  sequence number. No syscall is needed to read it, so `read()`/`ioctl()` interposition does not affect it.
- **Fallback:** a `KOBJ_CHANGE` uevent (`KERNELGUARD_ALERT`, `_LEVEL`, `_SEQ` — **never** parameters,
  because uevents are world-readable) and the kernel log. Example udev consumer: `scripts/70-kernelguard.rules`.
- Non-critical notifications are rate-limited (10/s sustained, burst 32); critical ones are never dropped.
  Kernel-log lines below *critical* are rate-limited too.

---

## Graduated response

The Windows driver reacts to each alert the same way and has one fail-safe mode that lasts until unload. Here
the reaction is a ladder (`kg_posture.c`), so one suspicious event costs less than a proven kernel patch and an
operator can step back down after an investigation without unloading the module.

| Posture | Meaning | Entered by |
| --- | --- | --- |
| `NORMAL` | baseline strategies, scans at their configured interval | load, decay, operator |
| `ELEVATED` | scans (PCI, keyboard path, integrity) run **4× as often**; an immediate PCI/keyboard scan is queued | a critical cache-miss rate, an unauthorised bus master or keyboard handler, a PCI discrepancy, a suspicious module load |
| `HIGH` | **every CPU held at full-spectrum**, a floor the PMU sampler cannot relax; with `auto_enforce=1` also the active enforcement of `enforce=1`; an immediate integrity pass | IDT / control-register / syscall-MSR tampering |
| `FAIL-SAFE` | as HIGH, plus the fail-safe state of the Windows driver | a critical `.text` patch or input-callback hook, a corrupted policy state |

**Raising is automatic and bounded.** `max_posture` (writable at run time) is the highest rung the module climbs
by itself: `max_posture=0` keeps it alert-only, `1` never leaves ELEVATED, `2` never enters FAIL-SAFE. An operator
can still set any posture. The posture is stored in the hashed policy table, so tampering with it is caught like
any other policy change.

**Lowering is deliberate.** ELEVATED decays to NORMAL after `posture_decay_s` seconds without another trigger
(each trigger restarts the clock). HIGH and FAIL-SAFE never decay: they mean the kernel may be compromised.

```sh
kgmon posture                 # where are we, why, and how often are scans running
kgmon posture set normal      # (root) after investigating; also: elevated, high, failsafe
echo 2 | sudo tee /sys/module/kernelguard/parameters/max_posture
```

Decay and operator changes are announced with `ALERT_POSTURE_CHANGED` (`0x0032`) in the authenticated ring,
so the audit trail shows who relaxed what and when. The alert is *info* for a decay and *warning* for an operator
change. If the policy state itself was found corrupted, stepping down from HIGH or FAIL-SAFE is refused (`EUCLEAN`):
the baseline strategies it would restore cannot be trusted, so unload and reload the module.

**Why a floor:** before the ladder, an IDT-hook alert set every CPU to full-spectrum and the PMU sampler's relax
step put each CPU back to its baseline within a few seconds. A reproduction of that failed before the change; the
`posture` suite now checks that the floor holds (with the PMU sampler active, i.e. under KVM).

**Cost:** ELEVATED and above quadruple the scan rate (never below 100 ms), which for the integrity pass means
streaming the kernel text through the caches more often. Leave `posture_decay_s` at its default unless alerts on
your workload are frequent and benign; then raise `pmu_crit` or lower `max_posture` instead of shortening it.

---

## Prerequisites

| Requirement | Notes |
| --- | --- |
| x86-64 Linux, kernel with module support | Built against 6.8, 6.14, 6.17, 7.0 (see [Testing](#testing)) |
| Kernel headers for the running kernel | Ubuntu/Mint: `sudo apt install linux-headers-$(uname -r)` |
| `gcc`, `make` | the compiler should match the one that built the kernel |
| root | to load; the device node is `0600` and the key ioctl needs `CAP_SYS_ADMIN` |
| Module signing key | if `sig_enforce=Y` (Secure Boot) — see below |
| QEMU/KVM, busybox, cpio (tests only) | `make test` |

Kernel config used: `CONFIG_PERF_EVENTS`, `CONFIG_INPUT`, `CONFIG_PCI`, `CONFIG_ACPI` (for MCFG),
`CONFIG_KALLSYMS`(+`_ALL` for the best symbol resolution), `CONFIG_CRYPTO_HMAC`, `CONFIG_CRYPTO_SHA256`.
All present in the stock Ubuntu/Mint kernels.

---

## Repository layout

The names in parentheses are the Windows counterparts, in [`../windows/`](../windows/) (`src/`, `usermode/`, `scripts/`).

```text
linux/
├── README.md                      this file
├── Makefile                       make / check / test / clean
├── include/kernelguard_uapi.h     ABI shared by kernel and user space (ioctls, structs, alert codes)
├── module/                        kernelguard.ko
│   ├── kg.h                       master header (types, hot-path flush, prototypes)
│   ├── kg_main.c                  module entry/exit, /dev/kernelguard, parameters      (driver_main.c)
│   ├── kg_state.c                 stats, policy hash, kg_report, event router            (shared_state.c)
│   ├── kg_posture.c               graduated response: posture ladder, decay, operator reset  (Linux only)
│   ├── kg_pmu.c                   Module 1                                              (pmu_detection.c)
│   ├── kg_hw.c                    Module 2, PCI/DMA                                     (hw_keylogger_detect.c)
│   ├── kg_input.c                 Module 2 keyboard path + Module 3 input hooks         (…, kernel_integrity.c)
│   ├── kg_integrity.c             Module 3                                              (kernel_integrity.c)
│   ├── kg_mitigate.c              Module 4                                              (cache_mitigation.c, verw_flush.asm)
│   ├── kg_comms.c                 Module 5                                              (secure_comms.c)
│   └── Kbuild, Makefile
├── monitor/                       kgmon                                                  (usermode/)
│   ├── kgmon.c, kg_hmac.c/.h      monitor + self-contained SHA-256/HMAC
│   └── Makefile
├── scripts/
│   ├── kg-deploy.sh               preflight / build / sign / install / persist          (Deploy-KernelGuard.ps1)
│   ├── kg-stop.sh                 emergency stop                                         (stop_driver.bat)
│   ├── kernelguard-monitor.service, 70-kernelguard.rules
└── tests/vm/                      QEMU/KVM test rig, guest tests, helpers and fixtures
```

---

## Build

```sh
make -C linux                       # module + monitor for the running kernel
make -C linux KVER=6.14.0-37-generic   # against another installed header tree
make -C linux check                 # monitor SHA-256/HMAC known-answer tests (no root, loads nothing)
make -C linux clean
```

The top-level `build.py` (`../build.sh`) wraps this with a choice of components and installed kernel and a
prerequisite check (`../build.sh --check`); it also builds the Windows driver on Windows.

`make -C linux/module W=1` enables extra compiler warnings; the tree is warning-free at `W=1` on all four
header trees listed above. `KG_TESTHOOKS=1` adds a write-only `test_inject` parameter used by the VM suite
to push synthetic alerts through the real report/HMAC path — **never build that variant for real use.**

---

## Secure Boot and module signing

If `/sys/module/module/parameters/sig_enforce` reads `Y` (Secure Boot with lockdown — the default on
Ubuntu/Mint), the kernel refuses unsigned modules. `scripts/kg-deploy.sh preflight` reports this.

On Ubuntu/Linux Mint the usual route is a Machine Owner Key:

```sh
sudo update-secureboot-policy --new-key      # creates /var/lib/shim-signed/mok/MOK.{priv,der}
# reboot, choose "Enroll MOK", confirm
sudo scripts/kg-deploy.sh sign               # signs linux/module/kernelguard.ko with that key
```

`sign` accepts `--key K --cert C` for another key pair. A module signed this way loads with
`sig_enforce=Y`; it still taints the kernel as out-of-tree. (The key enrolment steps depend on your distro
and firmware and were not exercised on the development machine.)

Under lockdown `integrity` a *signed* module may still write MSRs and read physical memory, since it is
kernel code you chose to trust; lockdown only restricts user space.

---

## Deploy

```sh
scripts/kg-deploy.sh preflight              # what would stop it loading here?
scripts/kg-deploy.sh build
sudo scripts/kg-deploy.sh sign              # only if sig_enforce=Y
sudo scripts/kg-deploy.sh install --monitor # load now, start kgmon (alerts → syslog + /var/log/kernelguard-alerts.csv)
sudo scripts/kg-deploy.sh install --enforce # detect AND act (read Safety model first)
scripts/kg-deploy.sh status
sudo scripts/kg-deploy.sh uninstall
```

`key=value` arguments are passed to the module: `install enforce=1 kbd_allow=myhandler dma_allow=10de:2520`.

**Persistent (boot-time) load** — the counterpart of `SERVICE_SYSTEM_START`:

```sh
sudo scripts/kg-deploy.sh persist [key=value ...]   # module → /lib/modules/$KVER/extra, options, modules-load.d,
                                                    # kernelguard-monitor.service, udev rule
sudo scripts/kg-deploy.sh unpersist
DESTDIR=/tmp/stage scripts/kg-deploy.sh persist     # stage the files without root, to inspect them
```

Persistence is **per kernel**: after a kernel update rebuild and (if needed) re-sign — DKMS is the usual
way to automate that and is not provided here. Module parameter values must not contain spaces.

---

## The monitor: `kgmon`

```text
kgmon                       follow alerts (backlog first); verifies every HMAC
kgmon --once                print the ring backlog and exit
kgmon --log FILE            append CSV (Time,Level,AlertType,HMAC,Seq,Param1,Param2,Details)
kgmon --syslog              also send to syslog (authpriv)
kgmon --notify[=USER]       desktop notifications through notify-send (as root, USER selects the session)
kgmon --max N | --new-only | --quiet
kgmon status                driver state, per-CPU strategy table, counters
kgmon posture               the response posture, what raised it, the effective scan intervals
kgmon posture set LEVEL     (root) step it: normal | elevated | high | failsafe
kgmon selftest              SHA-256 / HMAC known-answer tests
kgmon run --sensitive -- CMD...
                            exec CMD with L1D flush, IBPB/STIBP, SSBD and core scheduling enabled where
                            the kernel supports them (each control reports enabled / why not)
```

Example output:

```text
2026-09-29 20:14:15.557 [CRITICAL] Kernel .text Patched             HMAC=OK seq=0  Addr: 0xffffffffb1234560  Len: 2  [kernel]
2026-09-29 20:14:15.557 [Warning ] Unauthorized Keyboard Filter     HMAC=OK seq=2  name: "rogue_logger"
```

The monitor refuses to run twice (a lock file), tells lapped-ring entries apart from forgeries, and reports an
unreadable slot as a possible tamper instead of an HMAC failure.

---

## Alert protocol

The notification is **byte-identical to the Windows `SECURE_NOTIFICATION`** (72 bytes, HMAC-SHA256 over the
first 40) and the shared region is the same 1168-byte layout, so one protocol description covers both ports.

```c
struct kg_notification {
    __u32 magic;            // 0xDEADC0DE while valid, 0 while the kernel rewrites the slot
    __u32 sequence;         // monotonic, never reused
    __u32 alert_type;       // KG_ALERT_*
    __u32 alert_level;      // 0 info, 1 watch, 2 critical
    __u64 timestamp;        // CLOCK_REALTIME ns
    __u64 param1, param2;
    __u8  hmac[32];
};
struct kg_shared_region { __u32 write_index, read_index, driver_nonce, reserved;
                          struct kg_notification notifications[16]; };
```

Notification *N* is in slot `N % 16`. Publication order: `magic = 0` → fill → release-store `magic` → release-store
`write_index`. A reader checks `magic` before and after copying; if `write_index − cursor > 16` it was
lapped. (Under a four-writer flood with a live reader the suite saw zero HMAC failures and zero torn slots.)

### Alert codes

Values `0x0001–0x0031` are the Windows values. `0x0023–0x0024` and `0x0032` are Linux additions.

| Code | Value | Module | Param1 / Param2 |
| --- | --- | --- | --- |
| `ALERT_PMU_L1D_ANOMALY` | `0x0001` | M1 | offender tgid / `(cpu<<32) \| overflows-per-second` |
| `ALERT_PMU_L2_ANOMALY` (LLC) | `0x0002` | M1 | same |
| `ALERT_PMU_RDTSC_RATE` | `0x0003` | M1 | reserved, never emitted |
| `ALERT_UNAUTHORIZED_KBD_FILTER` | `0x0010` | M2 | handler name, bytes 0–7 / 8–15 |
| `ALERT_UNAUTHORIZED_DMA` | `0x0011` | M2 | `seg<<24\|bus<<16\|dev<<8\|fn` / `vendor<<16\|device` |
| `ALERT_PCI_DISCREPANCY` | `0x0012` | M2 | BDF as above / `kind<<32 \| vendor<<16 \| device` (1 hidden, 2 missing, 3 mismatch) |
| `ALERT_KBD_FILTER_NEUTRALIZED` | `0x0013` | M2 | handler name |
| `ALERT_DMA_BLOCKED_IOMMU` | `0x0014` | M2 | defined, not emitted on Linux |
| `ALERT_DEVICE_BME_DISABLED` | `0x0015` | M2 | BDF / ids |
| `ALERT_IDT_HOOK` | `0x0020` | M3 | handler address / vector (`0x100` = IDTR moved) |
| `ALERT_DISPATCH_HOOK` | `0x0021` | M3 | callback address / `kind<<32` (1 unknown memory, 2 foreign module, 3 detour to foreign module, 4 detour to unknown code, 5 int3) |
| `ALERT_TEXT_PATCH` | `0x0022` | M3 | address / `flags<<32 \| length` (`1` kernel, `2` unknown target, `4` int3) |
| `ALERT_CTRL_REG_TAMPER` | `0x0023` | M3 | `cpu<<32 \| register` / new value (register = MSR number, `0x10000000` CR0, `0x10000004` CR4) |
| `ALERT_MODULE_LOADED` | `0x0024` | M3 | module name, bytes 0–7 / 8–15 |
| `ALERT_SHARED_STATE_CORRUPT` | `0x0030` | M4 | 0 / 0 |
| `ALERT_FAIL_SAFE_ENTERED` | `0x0031` | M4 | 0 / 0 |
| `ALERT_POSTURE_CHANGED` | `0x0032` | M4 | `old<<32 \| new` posture / `why<<32 \| trigger alert` (why: 2 decay, 3 operator). Only decay and operator changes are announced; an automatic raise is already explained by the alert that caused it |

---

## ioctl and mmap reference

`/dev/kernelguard` (mode `0600`):

| Call | Effect |
| --- | --- |
| `mmap(len ≤ 4096, PROT_READ, MAP_SHARED, fd, 0)` | the ring. `PROT_WRITE` is refused and `mprotect(PROT_WRITE)` is blocked |
| `poll(fd, POLLIN)` | readable when new notifications were published since the last poll |
| `ioctl(KG_IOC_GET_HMAC_KEY, struct kg_hmac_key *)` | the per-boot 32-byte key (`CAP_SYS_ADMIN`) |
| `ioctl(KG_IOC_GET_INFO, struct kg_info *)` | version, flags, counters |
| `ioctl(KG_IOC_GET_CPU_INFO, struct kg_cpu_info *)` | per-CPU features, strategy, CAT plan (`cpu` clamped with `array_index_nospec`) |
| `ioctl(KG_IOC_GET_POSTURE, struct kg_posture_info *)` | posture, ceiling, decay time, last trigger, effective scan intervals, times each posture was entered |
| `ioctl(KG_IOC_SET_POSTURE, struct kg_posture_req *)` | set the posture (`CAP_SYS_ADMIN`); refused with `EUCLEAN` when stepping down from HIGH/FAIL-SAFE after the policy state was found corrupted |

---

## Module parameters

Runtime-writable ones live in `/sys/module/kernelguard/parameters/`.

| Parameter | Default | Writable | Meaning |
| --- | --- | --- | --- |
| `enforce` | `0` | yes | allow active mitigation (BME clear, handler detach) |
| `kbd_allow` | – | no | extra authorised input-handler names, comma separated |
| `dma_allow` | – | no | extra authorised PCI devices: `SSSS:BB:DD.F` or `VVVV:DDDD` |
| `auto_enforce` | `0` | yes | also take the active mitigation of `enforce=1` once the posture reaches HIGH |
| `max_posture` | `3` | yes | highest posture the module raises by itself: 0 NORMAL (alerts only), 1 ELEVATED, 2 HIGH, 3 FAIL-SAFE |
| `posture_decay_s` | `600` | yes | quiet seconds before ELEVATED falls back to NORMAL (`0` = never; HIGH and FAIL-SAFE never decay) |
| `hw_interval_ms` | `5000` | yes | PCI and keyboard-path re-scan interval (÷4 while ELEVATED or above) |
| `integrity_interval_ms` | `30000` | yes | Module 3 verification interval (÷4 while ELEVATED or above) |
| `pmu`, `hw`, `input`, `integrity` | `1` | no | enable each monitor |
| `pmu_period_l1d` / `pmu_period_llc` | `100000` / `20000` | no | events per counter overflow (min 1000) |
| `pmu_window_ms` | `1000` | yes | sampling window (min 100) |
| `pmu_warn` / `pmu_crit` | `500` / `2000` | yes | overflows/second per CPU for *watch* / *critical* |
| `text_check` | `1` | no | compare kernel/module `.text` |
| `text_modules` | `1` | no | include every module's text, not just the kernel image and this module |
| `text_max_mb` | `128` | no | cap on baseline copies held in memory |

---

## Tuning and false positives

- **PMU.** A miss-rate detector cannot tell Flush+Reload from a memory-bound workload by counts alone;
  streaming code also produces millions of misses per second. Treat alerts as *"look at this process"*
  (the offender is named) and raise `pmu_warn`/`pmu_crit` (or the sample periods) if a legitimate workload
  trips them. Watch-level alerts do not mitigate; only critical ones do, and only on the affected core.
- **Memory.** The kernel image is ~23 MiB of baseline; each loaded module adds its `.text`. A machine with
  the NVIDIA proprietary driver and VirtualBox has ~250 modules and one module alone is ~100 MiB
  (text+data), so expect tens of MiB. `text_modules=0` limits the baseline to the kernel image; `text_max_mb`
  bounds the total.
- **`.text` alerts** are critical and enter fail-safe (set `max_posture=2` to stop the module going that far by itself). The classifier was checked against live ftrace
  (function tracer, 344 filtered functions), tracepoint jump labels, and the driver's own perf counters
  (912 patch sites accepted, 0 alerts). It has **not** been exercised against BPF/kprobe-heavy tooling,
  livepatch, or proprietary modules on real hardware; if you see a critical `TEXT_PATCH` that you can
  explain, `text_modules=0` is the first knob.
- **Fail-safe** here means full-spectrum flushing at the reactive points and on every PMU overflow — not a
  per-context-switch tax as on Windows, because no context-switch hook is installed.

---

## Testing

Nothing is loaded on the host. `tests/vm/run-vm.sh` builds a `KG_TESTHOOKS` copy of the module, boots a real
distro kernel in QEMU/KVM with a busybox initramfs, loads it there and runs a guest-side script:

```sh
make -C linux test                                   # all suites, kernel from /boot if readable
KG_KVER=6.14.0-29-generic KG_KERNEL=/boot/vmlinuz-6.14.0-29-generic linux/tests/vm/run-vm.sh basic pmu
```

Distro images are often root-only; `apt-get download linux-image-$(uname -r)` and `dpkg-deb -x` give a
readable copy (set `KG_KERNEL`). Tools: `qemu-system-x86_64`, `busybox`, `cpio`, `gcc`.

**Result:** all 12 suites (276 checks) pass on a **7.0.0-31-generic** guest (re-run after the graduated-response
change; the previous 11 suites also passed on 6.14.0-29), and the module builds warning-free (`W=1`) against every
installed header tree (two 6.8, two 6.14, 6.17, two 7.0). `checkpatch.pl` reports no errors in the changed files.

| Suite | Covers |
| --- | --- |
| `basic` | load/unload, `0600` node, ioctls, HMAC ring verified by the independent user-space implementation, sequence continuity, ring wrap-around, rate limiting, fail-safe policy and state hash, uevent channel |
| `integrity` | live ftrace/tracepoint patching does **not** alert; module text, kernel text (flagged `[kernel]`), `MSR_CSTAR`, `CR0.WP`, IDT gate tampering does; module-load reports |
| `pmu` | idle control, detection, correct offender named, escalation and decay, no self-alarm, no false `.text` alert from perf's own static keys, CPU hotplug |
| `smt` | a loaded thread escalates and flushes its sibling; the other core is untouched (2-core × 2-thread guest) |
| `input` | rogue handler detected (critical when open); `enforce=1` stops it receiving keys while `evdev` still receives 100 %; unloading the detached owner does not crash; load-time baseline; `kbd_allow=`; hijacked callback pointer; entry detour |
| `hw` | ECAM through a bridge; hidden-device discrepancy; **real hot-plug** via the QEMU monitor; unauthorised bus master; `enforce` clears and keeps clearing it; `dma_allow=` |
| `hwlegacy` | a platform with no MCFG (i440fx): falls back to the OS view |
| `monitor` | CSV format, syslog, `--max`, single-instance lock, `run --sensitive` (controls verified *in the exec'd child*) |
| `deploy` | `kg-deploy.sh`/`kg-stop.sh` under busybox `ash` with a real `insmod` |
| `lifecycle` | 16 load/unload cycles with a flat-memory slope check, cpuhp states released, hostile parameters, unload while PMU NMIs + tracing + keyboard events + an alert flood are running |
| `posture` | automatic raises and the 4× scan rate; decay and its restart on a new trigger; HIGH holds every CPU at full-spectrum past several PMU windows; operator step-down restores the baseline and keeps the state hash valid; the `max_posture` cap (also at run time); a corrupted state cannot be reset away; `auto_enforce` detaches a rogue handler only once the posture reaches HIGH; every announcement authenticated |
| `stress` | 4 concurrent alert writers vs. a live reader: zero HMAC failures, zero torn slots |

Fixtures (`tests/vm/testmods/`): a rogue input handler and a tamper module (patches module/kernel text through
a temporary writable alias, changes `MSR_CSTAR`, clears `CR0.WP` on one CPU, raises an IDT gate's DPL). They
exist only in the guest.

**Not covered — be aware:** real hardware (including D3cold devices, hybrid CPUs, AMD, a real IOMMU with
Thunderbolt), Secure Boot loading, distro kernels other than 7.0.0-31 and 6.14.0-29 at runtime (6.8 and 6.17
are compile-checked only), and long-running behaviour. Power-off handling of D3cold devices is by inspection.

---

## Security design notes

- **The HMAC** authenticates notifications against anything that can write the ring but cannot read the key.
  A kernel-mode attacker can read the key and forge; this is the same guarantee as the Windows design. The key
  now comes from the CSPRNG (a TPM-sealed key remains a possible improvement) and is wiped on unload.
- **The ring is read-only to user space**, the key ioctl needs `CAP_SYS_ADMIN`, and the node is `0600`.
- **Constant time:** digest and HMAC comparisons use `crypto_memneq()` (kernel) / a volatile XOR loop (monitor).
  The bulk text comparison is not constant-time — the baseline is not a secret.
- **Spectre v1:** the one user-controlled index in the kernel code (`KG_IOC_GET_CPU_INFO`) and the ring slot
  index go through `array_index_nospec()`.
- **Zero-trust reads:** MSRs and CRs are read directly on the CPU they describe; ECAM is read from hardware,
  not from the PCI core's cache. This module still runs *in* the kernel it monitors — see limitations.
- **No keystroke exposure:** the keyboard-path handle is never opened, so the module cannot see keys.
- **Reads of kernel memory** use `copy_from_kernel_nofault`; text is read through its normal mapping.
- **No dependence on unexported symbols or `kallsyms_lookup_name` tricks:** everything used is `EXPORT_SYMBOL`
  or `EXPORT_SYMBOL_GPL`.

---

## Known limitations

| Area | Status |
| --- | --- |
| **A kernel-mode attacker wins** | Any code running in ring 0 can disable, blind or forge this module. It raises the cost and catches the common cases; it is not a boundary |
| **Hooks that ride the kernel's own mechanisms** | ftrace / kprobes / livepatch / BPF hooks registered through their normal APIs, and *data* hooks (syscall/VFS/LSM tables, `keyboard_notifier` chain, hooks on `input_event` or in a port driver), are not detected |
| **`.text` scope** | executable kernel text and module text only; `.rodata`/`__ro_after_init` are not covered |
| **Inline hardware keyloggers** | transparent USB/PS/2 devices that never enumerate are invisible to software; only a *new* keyboard or an unexpected bus master is seen |
| **RDTSC profiling** | not implemented (Windows ships it disabled). Use `prctl(PR_SET_TSC, PR_TSC_SIGSEGV)` per task |
| **PMU detection** | a heuristic with false positives on memory-bound workloads (tunable, offender is named) |
| **VT-d / AMD-Vi** | audited, not edited |
| **CAT** | reported and planned, applied through resctrl by the operator; not exercised (the development CPU has no L3 CAT) |
| **AMD** | code paths use generic perf events and `X86_BUG_*`; compiled for both, exercised only on Intel-host KVM guests |
| **Hybrid CPUs** | generic events resolve per CPU; not exercised |
| **Hypervisor guests** | the Windows README's VM keyboard-loss problem does not arise in detect-only mode; with `enforce=1` a hypervisor's virtual input handler that is not stock would be detached — use `kbd_allow=` |
| **Persistence** | per-kernel; no DKMS packaging |
| **Detached handlers** | `enforce=1` does not re-attach on unload; reload the owning driver or replug the device |
| **Kernels** | x86-64 only, ≥ 6.4 (`struct module_memory`); compile-checked on 6.8, 6.14, 6.17, 7.0 |

---

## Recovery

```sh
sudo sh linux/scripts/kg-stop.sh        # enforce off → stop monitor → rmmod
# or by hand, needing no keyboard beyond a shell (SSH works):
echo 0 | sudo tee /sys/module/kernelguard/parameters/enforce
sudo rmmod kernelguard
```

If input stopped working while `enforce=1` was active, an input handler was detached: reload the driver that
provides it (`sudo modprobe -r NAME && sudo modprobe NAME`) or replug the device. If a module was loaded
through `persist` and misbehaves at boot, boot with `module_blacklist=kernelguard` on the kernel command line.

---

## Licence

The kernel module is **GPL-2.0** (`MODULE_LICENSE("GPL")`): it uses `EXPORT_SYMBOL_GPL` interfaces
(`perf_event_create_kernel_counter`, `lookup_address`, `iommu_get_domain_for_dev`, `sprint_symbol`, …), which the
kernel only links to GPL-compatible modules. The user-space monitor, scripts and tests are also marked
GPL-2.0 (SPDX headers in every file); the Windows sources in `../windows/` carry no licence header.
