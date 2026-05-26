﻿# KernelGuard

A Windows 11 x64 Ring-0 kernel-mode driver (WDM) that detects and actively mitigates side-channel attacks, compromised kernels, and hardware keyloggers.

The driver operates under a **zero-trust kernel assumption**: it cannot rely on kernel APIs for critical integrity operations because the kernel itself may be partially compromised. All integrity comparisons are constant-time; all security-boundary flushes execute directly via MSR writes and a MASM routine (`PerformVerwFlush`), bypassing any hooked wrappers.

---

> **WARNING — READ BEFORE LOADING THE DRIVER**
>
> This is a Ring 0 (kernel-mode) driver. Incorrect behavior, unexpected hardware or software configurations, and false-positive detections can cause **complete keyboard loss**, **system hangs**, or **Blue Screen of Death (BSOD)**. Always test in a disposable VM snapshot. Keep a recovery plan ready before loading the driver on any machine you depend on. See [Warnings & known risks](#warnings--known-risks) for details.

---

## Table of Contents

- [Warnings & known risks](#warnings--known-risks)
- [Architecture overview](#architecture-overview)
- [Module details](#module-details)
- [Real-world attack scenarios](#real-world-attack-scenarios)
- [Prerequisites](#prerequisites)
- [Repository layout](#repository-layout)
- [Build](#build)
- [Deploy](#deploy)
- [Uninstall](#uninstall)
- [Alert protocol](#alert-protocol)
- [IOCTL reference](#ioctl-reference)
- [MSR reference](#msr-reference)
- [Performance characteristics](#performance-characteristics)
- [Security design notes](#security-design-notes)
- [Known limitations](#known-limitations)

---

## Warnings & known risks

### Keyboard input loss (confirmed — VMs and some bare-metal configurations)

Module 2 detects unauthorized keyboard filter drivers by comparing hardware-reported devices against the OS driver stack. In a virtual machine (VMware, VirtualBox, Hyper-V, QEMU/KVM) the hypervisor inserts its own virtual keyboard filter drivers into the stack. The driver cannot distinguish these from a rootkit filter and will flag them as `ALERT_UNAUTHORIZED_KBD_FILTER`, patching or detaching the filter via `NeutralizePassThroughDispatch` / `IoDetachDevice`. The result is **complete keyboard input loss** for the VM guest while the driver is running.

**Recovery (mouse must still work):**
1. Right-click `stop_driver.bat` (provided at the repo root) → **Run as administrator**. This runs `sc stop KernelGuard && sc delete KernelGuard` without requiring any keyboard input.
2. Alternatively: right-click the Start button → *Terminal (Admin)* → `sc stop KernelGuard` typed via the on-screen keyboard (Settings → Accessibility → Keyboard → On-Screen Keyboard).
3. In VirtualBox/VMware: revert to a snapshot taken before loading the driver.

**Workaround:** A hypervisor-detection check via `CPUID` leaf `0x1` (bit 31 of ECX = hypervisor present) is planned but not yet implemented. Until it is, avoid loading the driver in a VM for any purpose other than controlled testing with a snapshot ready.

---

### False-positive keyboard filter detection on non-standard hardware

On systems with Bluetooth keyboards, third-party keyboard remapping software (e.g., AutoHotkey kernel driver, Karabiner, manufacturer companion software), accessibility drivers, or KVM switches, Module 2's whitelist may not include the legitimate filter driver. The driver will neutralize it, potentially silencing keyboard input on that device. Check the driver stack of `\Device\KeyboardClass0` with `!devstack` in WinDbg before loading on a non-standard machine.

---

### RDTSC restriction may crash applications (CR4.TSD=1)

Module 1 sets `CR4.TSD = 1` on all logical CPUs, causing any Ring-3 `RDTSC` or `RDTSCP` instruction to raise `#GP` instead of returning the counter. The driver's `RdtscGpHandler` counts and emulates the instruction, but the emulation path involves a kernel-mode handler at `HIGH_LEVEL` IRQL. Applications that call `RDTSC` at very high frequency (some games, multimedia encoders, hardware benchmarks, Wine/Proton DirectX translation layers) may experience crashes, incorrect timing, or severe performance degradation. `QueryPerformanceCounter` and `GetSystemTimeAsFileTime` are unaffected.

---

### Fail-safe mode causes maximum mitigation overhead

When Module 3 detects a `.text` section SHA-256 mismatch (`ALERT_TEXT_PATCH`), the driver enters fail-safe mode and applies full-spectrum mitigations (`VERW` + L1D flush + `LFENCE` + IBRS) on every context switch. On affected CPUs this raises per-context-switch overhead to ~400 ns and can reduce throughput by 20–40% system-wide. Fail-safe mode is intentional and irreversible until the driver is stopped — it is the correct response to a detected kernel patch.

False-positive `.text` mismatches can occur when:
- Windows Update or a hotfix patches a kernel module after the baseline is captured at driver load time.
- A legitimate security product (EDR, AV) uses kernel callbacks that modify `.text` at runtime.
- The driver loads before all kernel modules are fully initialized.

If fail-safe mode triggers unexpectedly, check `KernelGuardMonitor.exe` logs for `ALERT_TEXT_PATCH` and the `Param1`/`Param2` fields identifying which module hash changed.

---

### SMT/HyperThreading restriction degrades throughput

When Module 4's SMT isolation is active (triggered by a detected attack or high anomaly level), sibling logical-core scheduling is restricted for threads that touch sensitive/tagged memory. On workloads that rely on HyperThreading (compilation, rendering, database queries), this can reduce throughput by 5–15% even when no attack is in progress. The restriction persists until the anomaly counter decays below the threshold.

---

### BSOD risk from unexpected hardware configurations

The driver directly reads and writes MSRs, walks PCIe ECAM memory, and modifies VT-d context tables. On hardware where:
- An MSR address is unimplemented (raises `#GP` at `HIGH_LEVEL` IRQL → non-maskable BSOD),
- The ECAM or VT-d MMIO base is wrong or unmapped,
- CAT (`MSR_IA32_PQR_ASSOC`) is unsupported but `IA32_ARCH_CAPABILITIES` reports otherwise,

…the result can be an immediate system crash with no recovery possible other than a hard reset. Always verify CPU model compatibility and enable kernel debugging (`bcdedit /debug on`) before loading on unfamiliar hardware.

---

---

## Architecture overview

The driver is split into **five synergistic modules** plus shared infrastructure. All modules share a central integrity-verified state structure (`DRIVER_SHARED_STATE`) protected by a spin lock at `DISPATCH_LEVEL`.

```
┌─────────────────────────────────────────────────────────────┐
│                     Ring 3 (User Mode)                      │
│  KernelGuardMonitor.exe                                     │
│    ├── polls shared memory ring every 150 ms                │
│    ├── validates each notification's HMAC-SHA256            │
│    └── shows Windows balloon alerts for level ≥ 1           │
└─────────────────┬───────────────────────────────────────────┘
                  │  DeviceIoControl  /  HMAC shared memory
┌─────────────────▼───────────────────────────────────────────┐
│                      Ring 0 (Kernel)                        │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │  M1 PMU  │  │  M2 HW   │  │  M3      │  │  M4      │   │
│  │ Detection│  │ Keylogger│  │ Kernel   │  │ Cache    │   │
│  │          │  │ Detect   │  │ Integrity│  │Mitigation│   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────▲─────┘   │
│       │             │              │              │         │
│       └─────────────┴──────────────┴──────────────┘         │
│                  cross-module events                        │
│                  (DispatchCrossModuleEvent)                 │
│                          │                                  │
│                  ┌───────▼──────┐                           │
│                  │  M5 Secure   │                           │
│                  │   Comms      │                           │
│                  └──────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

### Cross-module event flow

| Trigger | Response |
|---------|----------|
| M1 detects high cache-miss rate | M4 increases flush frequency |
| M2 detects DMA violation | M4 locks IOMMU + flushes buffers |
| M3 detects IDT hook | M4 full-spectrum flush + core isolation |
| M3 detects `.text` hash mismatch | M5 sends critical alert + fail-safe mode |
| M4 detects shared-state corruption | Apply maximum mitigations |

---

## Module details

### Module 1 — Side-Channel Attack Detection (PMU)
`src/pmu_detection.c`

- Configures `IA32_PERFEVTSEL0/1` for L1D and L2 cache-miss counting via IPI to every logical CPU.
- Pre-loads PMC counters near overflow so a PMI fires after `L1D_MISS_THRESHOLD` / `L2_MISS_THRESHOLD` events.
- PMI ISR (`PmiIsr`) runs at `HIGH_LEVEL` (IRQL 26). Zero paged-memory access, zero kernel API calls — reads `IA32_PERF_GLOBAL_STATUS`, increments anomaly counters, issues an immediate L1D flush when anomaly level is critical.
- RDTSC profiling: sets `CR4.TSD=1` so that `RDTSC` from Ring 3 raises `#GP`, which `RdtscGpHandler` intercepts and counts per-process. Excessive rates trigger `ALERT_PMU_RDTSC_RATE`.

**Alert codes emitted:** `ALERT_PMU_L1D_ANOMALY`, `ALERT_PMU_L2_ANOMALY`, `ALERT_PMU_RDTSC_RATE`

### Module 2 — Hardware Keylogger & Peripheral Detection + Mitigation
`src/hw_keylogger_detect.c`

**Detection:**
- Walks the PCIe bus tree directly via ECAM (Enhanced Configuration Access Mechanism), bypassing the OS device stack entirely.
- Compares hardware-discovered keyboard devices against the OS driver stack to detect unauthorized filter drivers.
- Walks VT-d root/context tables directly from physical memory to find DMA mappings granted to unauthorized PCIe devices.

**Mitigation — software keyboard filter drivers:**

| Tier | Mechanism | Condition |
|------|-----------|-----------|
| **1 — Dispatch patch** | `NeutralizePassThroughDispatch` (NONPAGED) overwrites `MajorFunction[IRP_MJ_READ]` and `[IRP_MJ_INTERNAL_DEVICE_CONTROL]`. The stub routes every IRP directly to the lower device, bypassing the filter entirely. Keyboard continues to function; filter never sees keystroke data. | Always applied |
| **2 — IoDetachDevice** | Removes the unauthorized device from the IRP delivery path altogether. | Only when the unauthorized device is the topmost in the stack (nothing above it) |
| **Self-healing** | A 5-second system thread re-inspects every `\Device\KeyboardClass0..9` stack and re-applies both tiers if the rootkit restored its handler. | Continuous |

On driver unload, `HwKeyloggerUninitialize` stops the monitoring thread and restores all original dispatch handlers.

**Mitigation — DMA hardware keyloggers:**

| Tier | Mechanism | Condition |
|------|-----------|-----------|
| **1 — VT-d invalidation** | Clears the context entry's `Present` bit for the unauthorized BDF, then flushes the IOMMU context cache (`CCMD_REG` global invalidation) and the IOTLB (via the offset from `ECAP.IRO`). The device loses all DMA translations immediately. | VT-d MMIO base available |
| **2 — PCIe BME disable** | Reads the PCIe Command register via ECAM, clears bit 2 (`Bus Master Enable`), and writes back. The device can no longer initiate DMA transactions. | VT-d unavailable or Tier 1 failed |

**Alert codes emitted:** `ALERT_UNAUTHORIZED_KBD_FILTER`, `ALERT_UNAUTHORIZED_DMA`, `ALERT_PCI_DISCREPANCY`, `ALERT_KBD_FILTER_NEUTRALIZED`, `ALERT_DMA_BLOCKED_IOMMU`, `ALERT_DEVICE_BME_DISABLED`

> Note: ECAM base address lookup (`PciGetEcamBaseFromAcpi`) is a stub returning `STATUS_NOT_IMPLEMENTED`. Populate `g_EcamBase` by parsing the ACPI MCFG table for your platform. The VT-d and BME mitigations require `g_VtdMmioBase` (from the ACPI DMAR table) and `g_EcamBase` respectively.

### Module 3 — Kernel Integrity & Hook Detection
`src/kernel_integrity.c`

Three independent sub-systems, all running at `PASSIVE_LEVEL` on a background worker thread (30-second interval):

1. **IDT integrity** — reads `IDTR` via `SIDT`, reconstructs 64-bit gate handler addresses, and verifies they fall within known ntoskrnl / HAL image ranges.
2. **Dispatch hook detection** — checks the first 8 bytes of each keyboard driver's `IRP_MJ_READ` dispatch routine against known hook prologues (`JMP rel32`, `PUSH+RET`, `JMP [RIP+disp32]`, `MOV RAX imm64`).
3. **`.text` section integrity** — BCrypt SHA-256 hashes the `.text` section of each loaded kernel module and compares against a baseline captured at driver load time. Comparison is constant-time to prevent timing leakage.

**Alert codes emitted:** `ALERT_IDT_HOOK`, `ALERT_DISPATCH_HOOK`, `ALERT_TEXT_PATCH`

### Module 4 — Crypto-Agnostic Memory & Cache Mitigation (Core Engine)
`src/cache_mitigation.c`

The central mitigation engine. Protects any sensitive data based on memory tagging — it does not attempt to identify cryptographic code.

- **CPU capability probing** — reads `IA32_ARCH_CAPABILITIES` (0x10A) at init to select the cheapest safe mitigation strategy per logical CPU: `MDS_NO` / `L1TF_NO` bits skip unnecessary flushes.
- **Security boundary flushing** — `ExecuteSecurityBoundaryFlush()` is `FORCEINLINE` (body in the header), safe at any IRQL, dispatches per strategy:
  - `MitigateVerwOnly` — `MFENCE` + `VERW` (MD_CLEAR microcode clears all micro-architectural buffers)
  - `MitigateL1dFlushOnly` — `WRMSR(IA32_FLUSH_CMD, 1)` (~100–200 cycles)
  - `MitigateVerwPlusL1d` — both
  - `MitigateFullSpectrum` — `VERW` + L1D flush + `LFENCE`
- **Speculation controls** — `LFENCE`/`MFENCE` barriers on sensitive entry/exit paths; `IBRS`/`STIBP` via `IA32_SPEC_CTRL` (0x48).
- **Sensitive page tagging** — custom allocation API marks pages (keystroke buffers, key material, crypto I/O) via internal bitmap.
- **KPTI-style isolation** — tagged pages excluded from user-mode page tables when not strictly required.
- **Intel CAT** (Cache Allocation Technology) — optional L3 partitioning via `MSR_IA32_PQR_ASSOC` (0xC8F) and `MSR_IA32_L3_CBMBASE` (0xC90).
- **SMT/HT mitigation** — when a logical core runs a thread with tagged memory, sibling-core scheduling is restricted; L1D flush on domain transitions via DPC.

**Alert codes emitted:** `ALERT_SHARED_STATE_CORRUPT`, `ALERT_FAIL_SAFE_ENTERED`

### Module 5 — Secure Ring 0 → Ring 3 Communication
`src/secure_comms.c`

Two independent channels, designed to survive a partially hooked device stack:

| Channel | Mechanism | Notes |
|---------|-----------|-------|
| **Primary** | HMAC-authenticated shared memory section mapped into both kernel and user space | Resistant to `DeviceIoControl` hooking; each notification carries HMAC-SHA256 + sequence number |
| **Fallback** | MSR-based covert signaling (`MSR_COVERT_SIGNAL` 0x150) | For critical alerts when the primary channel cannot be trusted |

HMAC key is derived at boot from `RDTSC` XOR'd with system time. A production deployment should unseal the key via TPM 2.0 `TPM2_Unseal` against the current PCR state.

---

## Real-world attack scenarios

Each module is designed around a concrete threat model. This section maps every module to the specific, documented attacks it addresses — why the detection signal is reliable, and why the mitigation is the correct response.

---

### M1 — Side-channel timing attacks detected by PMU

#### Flush+Reload (cache-timing covert channel)
**Attack:** An attacker process shares a read-only memory-mapped page with a victim process (e.g., a shared system DLL such as `ntdll.dll` or `bcrypt.dll`). The attacker flushes a specific cache line with `CLFLUSH`, waits for the victim to execute a code path that touches that line, then measures reload time with `RDTSC`. A fast reload (~4 ns) means the victim accessed that line; a slow reload (~200 ns) means it did not. By monitoring different cache lines the attacker can reconstruct what the victim did — which branch it took, which lookup table index it used, what AES round key bytes it accessed.

**Real examples:** The foundational Flush+Reload attack (Yarom & Falkner, 2014, USENIX Security) was demonstrated against GnuPG's RSA implementation running on the same physical machine. Cross-VM variants work on cloud hypervisors where co-resident VMs share library pages. CVE-2014-0076 (OpenSSL EC key recovery), CVE-2018-0737 (RSA key gen timing).

**Detection signal:** `CLFLUSH` before each probe causes an L1D cache miss that the victim's access converts to an L1D hit on the attacker's next reload. On a system under active Flush+Reload, `IA32_PMC0` (L1D miss counter, `MEM_LOAD_RETIRED.L1_MISS`) overflows at a rate far above baseline. `ALERT_PMU_L1D_ANOMALY` fires, and M4 escalates the flush frequency.

---

#### Prime+Probe (LLC set-conflict timing)
**Attack:** No shared memory is required. The attacker fills every cache set in a target LLC slice with attacker-controlled data (Prime phase), waits for the victim to run, then reads all its data back and measures which sets are now slow (Probe phase). Slow sets indicate the victim evicted attacker data — revealing which LLC sets the victim's data maps to. By repeating across all LLC sets the attacker builds a full memory-access profile. Used in cross-VM cloud attacks where shared pages are unavailable.

**Real examples:** Last-Level Cache Side-Channel Attacks are Practical (Liu et al., 2015, IEEE S&P). CloudRadar, CacheBleed (CVE-2016-0702, OpenSSL RSA on Sandy Bridge via Intel CAT set conflicts). Demonstrated against AES-NI on shared-nothing VMs.

**Detection signal:** Prime+Probe generates sustained high L2/LLC miss rates and abnormal memory-bus pressure. `IA32_PMC1` (`L2_RQSTS.MISS`) overflow triggers `ALERT_PMU_L2_ANOMALY`. M4 activates Intel CAT to partition the L3 and prevent the attacker from accessing the same LLC ways as sensitive workloads.

---

#### RDTSC-based ASLR / KASLR defeat
**Attack:** A Ring-3 process calls `RDTSC` in a tight loop before and after a syscall or memory access. The sub-nanosecond resolution of `RDTSC` allows the process to measure system-call latency, page-fault timing, and instruction cache behavior, which can be used to:
1. Defeat KASLR by timing the latency of speculative loads that hit or miss the iTLB for kernel addresses.
2. Break software-implemented constant-time crypto (e.g., mbedTLS, WolfSSL) by measuring per-byte timing differences too small for `GetSystemTimeAsFileTime` but visible to `RDTSC`.
3. Build a high-resolution covert channel between two processes in a sandbox that blocks all other IPC.

**Real examples:** AnC (ASLR on Android/Chrome via JavaScript `performance.now`/RDTSC equivalent, 2017). CVE-2021-26313 (AMD speculative execution RDTSC side-channel). Practically every Spectre PoC relies on `RDTSC` as its timing oracle.

**Detection signal:** Legitimate processes call `RDTSC` rarely; timing-attack code issues tens of thousands per second. `CR4.TSD=1` causes `RDTSC` from Ring 3 to raise `#GP`, which `RdtscGpHandler` intercepts and counts per PID. When the count exceeds `RDTSC_RATE_THRESHOLD`, `ALERT_PMU_RDTSC_RATE` fires against the offending process.

---

#### Spectre v1 — Bounds Check Bypass (CVE-2017-5753)
**Attack:** The attacker trains the CPU's branch predictor to predict "in-bounds" for a bounds check it controls. On the next iteration with an out-of-bounds index, the CPU speculatively executes the load using the attacker-chosen index before the misprediction is detected. The speculative load brings a secret byte into the L1D cache. The attacker then uses Flush+Reload to extract the cached byte. The entire kernel address space is readable from Ring 3 on vulnerable CPUs.

**Real examples:** The original Spectre v1 PoC (Kocher et al., 2018) read kernel memory via the eBPF JIT verifier. CVE-2020-12351 (BlueZ Bluetooth Spectre gadget). CVE-2022-23816, CVE-2022-29900 (Retbleed, AMD branch prediction).

**Detection signal:** Any working Spectre v1 exploit requires a timing oracle — either `RDTSC` (caught by M1's TSD enforcement) or Flush+Reload (caught by the L1D miss rate PMI). The `SafeArrayIndex()` masking in M4 also eliminates speculative gadgets in this driver's own IOCTL paths.

---

### M2 — Hardware keyloggers and DMA attacks

#### USB/PS2 in-line hardware keylogger
**Attack:** A physical device inserted between the keyboard cable and the host USB port (KeyGrabber USB, KeyLlama, Keydemon). The device presents a legitimate HID keyboard device object to the OS while transparently relaying all keystrokes to the real keyboard. It stores captured keystrokes in internal flash memory, accessible by connecting to a specific USB VID/PID or by a special keystroke sequence. Completely invisible to software; survives OS re-installation.

**Real examples:** KeyGrabber line (keelog.com) — commercially available, widely used in corporate espionage. Found in several publicly documented insider-threat cases. Similar devices deployed in the Target POS breach physical-access phase.

**Detection signal:** The ECAM walk discovers the hardware keylogger as an additional PCIe/USB device that was not present during the clean-boot inventory, or whose VID/PID does not match any authorized keyboard. `ALERT_PCI_DISCREPANCY` fires. If the device is DMA-capable, M2 clears its VT-d context entry immediately.

---

#### DMA attack via Thunderbolt / rogue PCIe card (PCILeech)
**Attack:** A device with PCIe DMA capability (Thunderbolt adapter, ExpressCard, rogue PCIe card) directly reads or writes host physical memory, bypassing the CPU and OS entirely. The attacker can read credential stores, extract BitLocker/FileVault keys from RAM, inject shellcode into the kernel, or read keystroke buffers. All of this happens at PCIe bus speed with no software interaction on the host.

**Real examples:** PCILeech (GitHub: ufrisk/pcileech) — documented DMA attack framework, reads/writes arbitrary physical memory via Thunderbolt or USB 3380 cards. Inception (citp.princeton.edu) — DMA attack against FireWire, extracted FileVault and BitLocker keys. Demonstrated against Windows 10 with BitLocker enabled when the machine was running (not sleeping). CVE-2019-9897 (Thunderbolt DMA before IOMMU enabled).

**Detection signal:** The VT-d root/context table walk finds the rogue device's BDF with a valid context entry granting it a second-level page-table domain (DMA access). `ALERT_UNAUTHORIZED_DMA` fires immediately. M2 clears the `Present` bit in the context entry and flushes the IOTLB — the DMA hardware immediately loses all valid translations and any in-flight DMA transfer faults at the IOMMU.

---

#### Keyboard filter rootkit (software-based)
**Attack:** A kernel-mode rootkit installs a device filter driver that attaches above `\Device\KeyboardClass0` using `IoAttachDeviceToDeviceStack`. Its `IRP_MJ_READ` completion routine copies keystroke data from each completed read IRP into a private ring buffer, which is later exfiltrated. The filter is invisible to user-mode tools (`sc query`, `tasklist`) because it operates entirely in kernel mode with no user-mode component that can be trivially killed.

**Real examples:** Olympic Destroyer (Pyeongchang 2018 Olympics attack, attributed to Sandworm/APT28) — installed a keyboard filter driver as part of its credential harvesting stage. Agent Tesla RAT — widely deployed keyboard filter for credential theft. Azazel rootkit — open-source rootkit with IRP_MJ_READ hook on `kbdclass`. TDL4 (Alureon) — installed a boot-level filter driver on the keyboard stack to capture pre-boot passphrases.

**Detection signal:** `PciDetectDiscrepancies` walks every keyboard device stack and compares each driver against the whitelist. Any driver not in the list triggers `ALERT_UNAUTHORIZED_KBD_FILTER`. M2 immediately overwrites its `MajorFunction[IRP_MJ_READ]` with `NeutralizePassThroughDispatch`, and if it is topmost, calls `IoDetachDevice`. The monitoring thread re-applies the patch within 5 seconds if the rootkit restores its handler.

---

#### Evil Maid attack (physical access, cold boot variant)
**Attack:** An attacker with brief physical access (hotel room, unattended laptop) boots a custom OS from USB, installs a kernel-mode implant that hooks the keyboard driver, then reboots back to the original OS. On next unlock, the implant captures the full-disk-encryption passphrase. Alternatively: inserts a malicious PCIe card into an available M.2 or ExpressCard slot that DMA-reads RAM after Windows resumes from sleep (cold-boot attack variant — DRAM retains data for seconds to minutes after power-off at low temperatures).

**Real examples:** Joanna Rutkowska's Evil Maid Attack (2009, against TrueCrypt). Lest We Remember cold-boot attack (Princeton, 2008) — successfully extracted BitLocker, FileVault, TrueCrypt keys from sleeping machines. FinFisher/FinSpy commercial spyware documented deploying keyboard implants via Evil Maid on Windows machines.

**Detection signal:** The keyboard filter left by the Evil Maid is caught by `PciDetectDiscrepancies` on the next legitimate boot (M2, `ALERT_UNAUTHORIZED_KBD_FILTER`). The rogue PCIe card is caught by ECAM device enumeration discrepancy (M2, `ALERT_PCI_DISCREPANCY`) and blocked by VT-d invalidation or BME disable (`ALERT_DMA_BLOCKED_IOMMU` / `ALERT_DEVICE_BME_DISABLED`).

---

### M3 — Kernel integrity attacks

#### IDT hook (keyboard interrupt hijack)
**Attack:** A rootkit replaces the IDT gate for vector `0x31` (IRQ1, the PS/2 keyboard hardware interrupt) with its own handler VA. When a key is pressed, the CPU vectors to the rootkit's handler, which logs the scan code and then chains to the original handler. This technique predates filter drivers and works even when device stacks are locked down; it operates at `HIGH_LEVEL` IRQL, making it invisible to all PASSIVE_LEVEL monitoring tools.

**Real examples:** FU rootkit (original Windows IDT hooker, 2004) — replaced interrupt handlers to hide processes. Hacker Defender — comprehensive rootkit using IDT hooks for keystroke logging. NSA ANT catalog GINSU (PCI-based implant using IDT hooks for persistence). Any Ring-0 code injection that installs before this driver runs can attempt an IDT hook.

**Detection signal:** `IdtVerifyKeyboardHandler` reads `IDTR` via `SIDT`, reconstructs the 64-bit handler VA from the IDT gate descriptor fields, and checks whether it falls within the known ntoskrnl or HAL image ranges (obtained via `AuxKlibQueryModuleInformation`). A VA outside these ranges triggers `ALERT_IDT_HOOK`. M4 immediately performs a full-spectrum flush and escalates to maximum mitigation.

---

#### Inline kernel hook / dispatch trampoline (IRP_MJ_READ)
**Attack:** A rootkit patches the first 5–14 bytes of the `kbdclass!KeyboardClassRead` dispatch routine with a JMP trampoline (or MOV RAX / PUSH RAX / RET sequence for position-independent hooking) that redirects execution to the rootkit's handler. The handler receives the completed IRP containing keystroke scan codes, copies the data, and jumps to the original routine. Unlike IDT hooks, this technique survives IDT integrity checks and works across all keyboard types (PS/2, USB HID via kbdhid, Bluetooth).

**Real examples:** DOUBLEPULSAR (NSA, leaked by Shadow Brokers 2017) — hooked `srv.sys` dispatch tables using exactly the PUSH+RET pattern M3 detects. Turla/Snake APT rootkit — inline hooks on `ntdll!NtReadFile` and keyboard class driver. Necurs rootkit — hooks `kbdclass!KeyboardClassRead` for credential harvesting. Zeus banking trojan kernel component uses the same JMP rel32 hook.

**Detection signal:** `ScanKeyboardDrivers` reads the first 8 bytes of each keyboard driver's `MajorFunction[IRP_MJ_READ]` and compares against six known hook prologues (JMP rel32, JMP[RIP+disp32], MOV RAX imm64 / PUSH RAX / RET, etc.) using bitmask matching. Any match triggers `ALERT_DISPATCH_HOOK`. M4 performs a full-spectrum flush and escalates mitigations.

---

#### Kernel `.text` section patch (persistent implant)
**Attack:** A nation-state implant or advanced rootkit modifies the loaded kernel image in memory — patching a system call handler, scheduler function, or security check. Unlike a trampoline hook, the patch is applied surgically (e.g., replacing a `CMP` instruction with `XOR EAX,EAX / NOP` to disable an integrity check), making it invisible to hook scanners that only look for JMP prologues. These patches survive across function calls and are extremely difficult to detect without a clean reference copy.

**Real examples:** Equation Group NOPEN implant — documented to patch `ntoskrnl!PsLookupProcessByProcessId` to hide its process from enumeration. APT41 (Winnti) — patches kernel memory to suppress Windows Defender callbacks. Derusbi/TEMP.Hermit rootkit — direct kernel memory patching for privilege escalation bypass. Flame/Sputnik malware (nation-state, 2012) — in-memory kernel patches for crypto algorithm substitution.

**Detection signal:** `BuildIntegrityBaseline` hashes the `.text` section of every loaded kernel module at driver load time (clean reference). `VerifyModuleIntegrity` re-hashes every 30 seconds and compares using `ConstantTimeMemEq`. Any byte difference (a single NOP substitution, a flipped bit in a CMP operand) produces a SHA-256 mismatch and triggers `ALERT_TEXT_PATCH`. M5 sends a critical alert via the HMAC channel and MSR fallback; the driver enters fail-safe mode.

---

### M4 — Microarchitectural data leakage

#### MDS — RIDL / Fallout / ZombieLoad (CVE-2018-12126/12127/12130)
**Attack:** Microarchitectural Data Sampling exploits the fact that the CPU's line-fill buffers, store buffers, and load ports retain stale data from previous micro-operations that executed in a different security domain (different process, different VM, or Ring-0). A carefully crafted Ring-3 process can sample this stale data by triggering a fault or assist on a load, then using a Flush+Reload gadget to extract what was in the buffers. On a server running both a cloud tenant VM and a management VM, RIDL can leak hypervisor secrets, crypto keys, or keystrokes that Ring-0 processed moments earlier.

**Real examples:** RIDL (VUsec, 2019) — demonstrated leaking `/etc/shadow` from another VM on the same physical core. ZombieLoad (TU Graz, 2019) — leaked AES keys from SGX enclaves and cross-VM secrets. Intel TSX Asynchronous Abort (CVE-2019-11135) — variant that works through TSX abort paths. All require the attacker and victim to share a physical CPU core (common with SMT/HyperThreading enabled).

**Mitigation:** `PerformVerwFlush()` executes `MFENCE` followed by `VERW` with a Ring-3 data segment selector. Intel's MD_CLEAR microcode update causes `VERW` to clear all line-fill buffers, store buffers, and load ports. This is executed by `ExecuteSecurityBoundaryFlush` on every security boundary crossing (context switch involving a sensitive thread, on PMI fire, on every IDT/hook detection event). The MASM implementation is the only place in the codebase where `VERW` appears.

---

#### L1TF / Foreshadow (CVE-2018-3615, CVE-2018-3620, CVE-2018-3646)
**Attack:** L1 Terminal Fault exploits speculative execution across a page-table entry with the `Present` bit cleared. The CPU speculatively loads the L1D cache line at the physical address encoded in the PTE's PFN field before the page fault is raised, leaking its contents through a timing side-channel. An attacker can craft a PTE that points to an SGX enclave page, a hypervisor page, or any other memory marked not-present, and extract its contents without ever having a valid mapping.

**Real examples:** Foreshadow-SGX (CVE-2018-3615) — leaks SGX enclave secrets, including attestation keys. Foreshadow-OS (CVE-2018-3620) — leaks kernel memory from Ring-3. Foreshadow-VMM (CVE-2018-3646) — leaks guest/hypervisor memory across VM boundaries. Any KVM or Hyper-V deployment on affected Intel CPUs is vulnerable without patching.

**Mitigation:** `IA32_FLUSH_CMD` write (`WRMSR(0x10B, 1)`) flushes the entire L1D cache. M4 executes this on every Ring 0→Ring 3 transition for the `MitigateL1dFlushOnly` and `MitigateVerwPlusL1d` strategies (selected by `ProbeCpuCapabilities` based on the `L1TF_NO` flag in `IA32_ARCH_CAPABILITIES`). Processors that report `L1TF_NO=1` skip this flush, avoiding unnecessary overhead on hardware that is not vulnerable.

---

#### Spectre v2 — Branch Target Injection (CVE-2017-5715)
**Attack:** The attacker trains the CPU's indirect branch predictor (BTB — Branch Target Buffer) in the attacker's own security domain to point to an attacker-chosen "gadget" in the victim's address space. When the victim next executes an indirect branch (e.g., a virtual function call or a switch-case dispatch), the CPU speculatively jumps to the attacker's chosen gadget before the correct target is resolved. If the gadget loads a secret-dependent memory location, Flush+Reload extracts the secret.

**Real examples:** Spectre v2 (Kocher et al., 2018) — demonstrated reading arbitrary kernel memory from an eBPF JIT program. CVE-2022-29900 (Retbleed, AMD) — `RET` instructions used as branch targets leak kernel memory. CVE-2022-23816/29901 (Intel Retbleed via `RET`-based gadgets). Used in practical PoCs against the Linux kernel, Windows kernel, and hypervisors.

**Mitigation:** IBRS (`IA32_SPEC_CTRL.IBRS=1`) prevents cross-privilege indirect branch prediction. `EnableSpeculationControls` (M4) sets this on every logical CPU via IPI at boot. `/Qspectre` at compile time inserts `LFENCE` after every load that feeds a branch condition in this driver's own code, eliminating speculative gadgets. IBPB (`IA32_PRED_CMD`) flushes the branch predictor state on context switches between security domains.

---

#### Cross-HT covert channel (SMT side-channel)
**Attack:** Two sibling Hyper-Threads share the L1D cache, L1I cache, and execution ports. Thread A (attacker, low-privilege) can observe Thread B's (victim, high-privilege) memory-access patterns by: monitoring contention on shared execution units (port contention attack, PortSmash CVE-2018-5407), observing L1D cache set occupancy, or using the shared store buffer to extract stale data (MDS variants). On a machine where a password manager and a browser run on sibling HTs, the browser can extract the password manager's AES key via port contention.

**Real examples:** PortSmash (CVE-2018-5407) — demonstrated extracting ECDSA private key from OpenSSL 1.1.0h running on an adjacent HT sibling. TLBleed (VUsec, 2018) — TLB-based covert channel across HT siblings. HyperBleed / SPECK — SMT-based cross-domain attacks on cloud workloads.

**Mitigation:** `SmtBuildTopology` maps logical CPU ↔ sibling CPU relationships. When `ExecuteSecurityBoundaryFlush` runs on a core with a sensitive thread, it queues a `SmtSiblingFlushDpc` on the sibling CPU to flush its L1D as well, ensuring the sibling cannot read stale sensitive data left in shared microarchitectural state.

---

### M5 — Compromised communication channel

#### DeviceIoControl interception by rootkit
**Attack:** A rootkit that has installed itself above this driver in the device stack (or has patched `IRP_MJ_DEVICE_CONTROL` in our dispatch table) can silently drop or forge IOCTL responses. If it drops `IOCTL_KG_GET_HMAC_KEY`, the monitor never validates HMAC and is unable to distinguish legitimate from forged alerts. If it forges `IOCTL_KG_MAP_SHARED_MEM` to return a mapping of the rootkit's own memory, the monitor reads attacker-controlled data.

**Real examples:** Zeus/SpyEye banking trojans intercepted IOCTL traffic to security software hooks. Carberp rootkit patched AV driver dispatch tables to suppress threat notifications. Turla rootkit neutralized EDR agents by forging IOCTL responses.

**Mitigation:** The primary channel is a non-paged shared memory section mapped directly into both the kernel and the user-mode process via `MmMapLockedPagesSpecifyCache`. The monitor validates every notification's HMAC-SHA256 using the key retrieved at startup. A rootkit that modifies any field in a `SECURE_NOTIFICATION` (including suppressing it by zeroing the `Magic` field) will produce an HMAC mismatch. The sequence number prevents replay: the monitor detects any gap or reuse.

---

#### Notification suppression / replay
**Attack:** Rather than forging alerts, a sophisticated rootkit may simply stop writing to the shared memory ring (if it has patched `SecureCommNotify`) or replay an old "system clean" notification in a loop. Either leaves the monitor displaying a false-green state while the attack proceeds.

**Real examples:** Stuxnet-class SCADA attacks suppressed monitoring software readings while keeping the control system display showing normal operation — the same concept applied to endpoint security. FinFisher's kernel component is documented to intercept and modify responses from its detection counterpart.

**Mitigation:** The monotonically increasing `SequenceNumber` in `SECURE_NOTIFICATION` means the monitor detects any sequence gap (suppressed notifications) or re-used number (replay). The MSR fallback (`SecureCommMsrSignal`) writes a critical alert code directly to `MSR_COVERT_SIGNAL` (0x150). A companion Ring-0 helper reads this MSR directly, bypassing all device-stack and shared-memory paths that a rootkit could intercept.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Windows 11 x64 (test VM) | `bcdedit /set testsigning on` + reboot required |
| Visual Studio 2022 / 2025 | Desktop development with C++ workload |
| Windows Driver Kit 10.0.26100.0 | [Download WDK](https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk) |
| MSBuild (ships with VS) | Located at `C:\Program Files\Microsoft Visual Studio\<ver>\Community\MSBuild\Current\Bin\MSBuild.exe` |
| Memory Integrity (HVCI) **off** | Windows Security → Device Security → Core isolation → Memory integrity → OFF → reboot |
| Secure Boot state | Test-signed drivers require test-signing mode; EV cert required for production |

---

## Repository layout

```
KernelGuard/
│
├── src/
│   ├── KernelGuard.h               Master header: types, MSR constants, prototypes
│   ├── driver_main.c                 DriverEntry / DriverUnload / device dispatch
│   ├── shared_state.c                Global state, LogAlert, DispatchCrossModuleEvent
│   ├── pmu_detection.c               Module 1: PMU config, PmiIsr, RDTSC profiling
│   ├── hw_keylogger_detect.c         Module 2: PCIe ECAM walk, IOMMU/VT-d check
│   ├── kernel_integrity.c            Module 3: IDT check, dispatch hooks, .text hash
│   ├── cache_mitigation.c            Module 4: VERW/L1D flush, CAT, SMT, sens-page API
│   ├── secure_comms.c                Module 5: HMAC shared memory, MSR covert channel
│   ├── asm/
│   │   └── verw_flush.asm            MASM: PerformVerwFlush() — MFENCE + VERW 0x2B
│   └── KernelGuard.vcxproj         MSBuild driver project (WDM, DynamicLibrary+.sys)
│
├── usermode/
│   ├── kg_shared.h                  IOCTL codes + shared structures (kernel + user)
│   ├── main.c                        WinMain, tray icon, message pump
│   ├── driver_comm.c / .h            Device open, IOCTL, HMAC verify, polling thread
│   ├── log_window.c / .h             Modeless alert log dialog (ListView, Save Log)
│   ├── resource.h                    Resource IDs
│   ├── app.rc                        Menu, dialog, string table
│   └── KernelGuardMonitor.vcxproj  MSBuild monitor project (Win32 GUI)
│
├── KernelGuard.inf               Driver INF (install / uninstall / service registration)
├── Deploy-KernelGuard.ps1        PowerShell deploy script (build, sign, register, start)
├── 
├── 
├── 
├── 
└── KernelGuard_Driver_Architecture_v1.1.pdf  Authoritative architecture spec
```

### Build outputs

```
x64\Debug\KernelGuard.sys              Kernel driver (debug)
x64\Debug\KernelGuard.pdb
x64\Debug\KernelGuardMonitor.exe      User-mode monitor (debug)
x64\Release\KernelGuard.sys            Kernel driver (release)
x64\Release\KernelGuardMonitor.exe    User-mode monitor (release)
```

---

## Build

### Quick build (recommended)

Use the deploy script's `build` action — it sets up paths automatically:

```powershell
# From an elevated prompt (not required just to build, but consistent)
.\Deploy-KernelGuard.ps1 -Action build
.\Deploy-KernelGuard.ps1 -Action build -Configuration Release
```

### Manual MSBuild

From any PowerShell prompt (no VS environment setup required):

```powershell
$msbuild = "C:\Program Files\Microsoft Visual Studio\18\Community\MSBuild\Current\Bin\MSBuild.exe"
$root    = "C:\Users\<you>\...\SideChannelKernelPreventor"

# Driver
& $msbuild "$root\src\KernelGuard.vcxproj" `
    /p:Configuration=Debug /p:Platform=x64 `
    /p:SolutionDir="$root\" /v:minimal /nologo

# Monitor
& $msbuild "$root\usermode\KernelGuardMonitor.vcxproj" `
    /p:Configuration=Debug /p:Platform=x64 `
    /p:SolutionDir="$root\" /v:minimal /nologo
```

### CMake / Ninja (alternative)

```bat
:: From an x64 Native Tools Command Prompt for VS 2022/2025:
cmake --preset x64-debug
cmake --build --preset x64-debug
```

### Compiler flags

The driver project enforces the following key flags (see `src/KernelGuard.vcxproj`):

| Flag | Purpose |
|------|---------|
| `/kernel` | Ring-0 semantic restrictions |
| `/GS-` | No CRT buffer cookie (we link `BufferOverflowFastFailK.lib` instead) |
| `/Qspectre` | Retpoline — **do not remove** |
| `/EHs-c-` | No C++ exceptions |
| `BasicRuntimeChecks=Default` | Disables `/RTC1` — RTC requires CRT, unavailable in kernel mode |
| `IgnoreAllDefaultLibraries=true` | Prevents user-mode CRT from leaking into the link |
| `/SUBSYSTEM:NATIVE /DRIVER:WDM` | Linker produces a valid `.sys` image |
| `EntryPoint=GsDriverEntry` | Security-cookie wrapper that calls `DriverEntry` |

---

## Deploy

`Deploy-KernelGuard.ps1` requires an **elevated** PowerShell session and test-signing mode enabled.

```powershell
# Full pipeline: build → sign → register → start → launch monitor
.\Deploy-KernelGuard.ps1

# Release build
.\Deploy-KernelGuard.ps1 -Configuration Release

# Skip build (use already-built .sys)
.\Deploy-KernelGuard.ps1 -SkipBuild

# Skip build and sign (binary already signed externally)
.\Deploy-KernelGuard.ps1 -SkipBuild -SkipSign

# Build only, do not install
.\Deploy-KernelGuard.ps1 -Action build

# Check current service and monitor status
.\Deploy-KernelGuard.ps1 -Action status
```

### What the install action does

1. **Pre-flight** — verifies test signing is on (`bcdedit`) and HVCI is off (registry check).
2. **Build** (unless `-SkipBuild`) — MSBuild driver + monitor.
3. **Sign** (unless `-SkipSign`) — creates or reuses a `CN=KernelGuard Test Signing` self-signed certificate in `Cert:\CurrentUser\My`, installs it into `LocalMachine\Root` and `LocalMachine\TrustedPublisher`, then calls `signtool sign /fd sha256`.
4. **Stop old instance** — terminates the monitor process and stops/removes any existing service.
5. **Deploy binary** — copies the signed `.sys` to `%SystemRoot%\system32\drivers\`, verifies the installed copy's signature.
6. **Register service** — writes service registry entries directly under `HKLM\...\Services\KernelGuard` (avoids `sc.exe` pending-deletion races).
7. **Load driver** — `sc start KernelGuard`.
8. **Launch monitor** — starts `KernelGuardMonitor.exe`.

> **Note:** `KernelGuard` is a WDM kernel driver, not a minifilter. Loading is done via `sc start`, not `fltmc load`.

### Manual installation (without the script)

```powershell
# Copy binary
Copy-Item x64\Debug\KernelGuard.sys $env:SystemRoot\system32\drivers\ -Force

# Register and start
sc.exe create KernelGuard type= kernel binPath= "$env:SystemRoot\system32\drivers\KernelGuard.sys"
sc.exe start  KernelGuard

# Launch monitor
.\x64\Debug\KernelGuardMonitor.exe
```

---

## Uninstall

```powershell
.\Deploy-KernelGuard.ps1 -Action uninstall
```

This stops the monitor process, stops and deletes the service, and removes the `.sys` from `system32\drivers`.

---

## Alert protocol

The driver sends notifications through a non-paged **shared memory ring** (`SHARED_MEM_REGION`) exposed to the monitor via `IOCTL_KG_MAP_SHARED_MEM`. Every slot is authenticated with HMAC-SHA256.

```c
typedef struct _SECURE_NOTIFICATION {
    ULONG   Magic;           // 0xDEADC0DE
    ULONG   SequenceNumber;  // Monotonically increasing; replay detection
    ULONG   AlertType;       // One of the ALERT_* codes below
    ULONG   AlertLevel;      // 0=info, 1=watch, 2=critical
    ULONG64 Timestamp;       // KeQueryPerformanceCounter value
    ULONG64 Param1;          // Alert-specific parameter
    ULONG64 Param2;          // Alert-specific parameter
    BYTE    Hmac[32];        // HMAC-SHA256 over all fields above
} SECURE_NOTIFICATION;
```

### Alert codes

| Code | Value | Module | Meaning |
|------|-------|--------|---------|
| `ALERT_PMU_L1D_ANOMALY` | `0x0001` | M1 | L1D cache-miss rate exceeds threshold (possible Flush+Reload) |
| `ALERT_PMU_L2_ANOMALY` | `0x0002` | M1 | L2 cache-miss rate exceeds threshold |
| `ALERT_PMU_RDTSC_RATE` | `0x0003` | M1 | Excessive RDTSC calls from Ring 3 (timing attack) |
| `ALERT_UNAUTHORIZED_KBD_FILTER` | `0x0010` | M2 | Keyboard filter driver not in hardware-reported device list |
| `ALERT_UNAUTHORIZED_DMA` | `0x0011` | M2 | DMA transfer from unauthorized PCIe device |
| `ALERT_PCI_DISCREPANCY` | `0x0012` | M2 | ECAM device list differs from OS-reported devices |
| `ALERT_KBD_FILTER_NEUTRALIZED` | `0x0013` | M2 | Unauthorized filter's dispatch table patched (or re-patched after self-restore) |
| `ALERT_DMA_BLOCKED_IOMMU` | `0x0014` | M2 | Unauthorized DMA blocked via VT-d context entry invalidation |
| `ALERT_DEVICE_BME_DISABLED` | `0x0015` | M2 | PCIe Bus Master Enable cleared (VT-d unavailable or failed) |
| `ALERT_IDT_HOOK` | `0x0020` | M3 | IDT handler points outside ntoskrnl/HAL range |
| `ALERT_DISPATCH_HOOK` | `0x0021` | M3 | Keyboard driver `IRP_MJ_READ` prologue matches hook pattern |
| `ALERT_TEXT_PATCH` | `0x0022` | M3 | Kernel `.text` SHA-256 hash mismatch against baseline |
| `ALERT_SHARED_STATE_CORRUPT` | `0x0030` | M4 | `DRIVER_SHARED_STATE` integrity hash mismatch |
| `ALERT_FAIL_SAFE_ENTERED` | `0x0031` | M4 | Driver entered fail-safe mode (max mitigations applied) |

---

## IOCTL reference

The monitor opens `\\.\KernelGuard` with `FILE_READ_ACCESS` and calls two IOCTLs at startup:

| IOCTL | Code | Direction | Returns |
|-------|------|-----------|---------|
| `IOCTL_KG_MAP_SHARED_MEM` | `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)` | Out | Pointer to `SHARED_MEM_REGION` mapped into the calling process |
| `IOCTL_KG_GET_HMAC_KEY` | `CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_ACCESS)` | Out | 32-byte HMAC-SHA256 key for notification authentication |

---

## MSR reference

| MSR | Address | Module | Purpose |
|-----|---------|--------|---------|
| `IA32_PERFEVTSEL0–3` | 0x186–0x189 | M1 | PMU event selection |
| `IA32_PMC0–3` | 0x0C1–0x0C4 | M1 | Performance counters |
| `IA32_PERF_GLOBAL_CTRL` | 0x38F | M1 | Enable/disable counters globally |
| `IA32_PERF_GLOBAL_STATUS` | 0x38E | M1 | PMI source flags (read in PmiIsr) |
| `IA32_ARCH_CAPABILITIES` | 0x10A | M4 | CPU vulnerability flags (MDS_NO, L1TF_NO, …) |
| `IA32_FLUSH_CMD` | 0x10B | M4 | L1D cache flush trigger |
| `IA32_SPEC_CTRL` | 0x48 | M4 | IBRS / STIBP control |
| `IA32_PRED_CMD` | 0x49 | M4 | IBPB (Indirect Branch Prediction Barrier) |
| `MSR_IA32_PQR_ASSOC` | 0xC8F | M4 | CAT CLOS assignment |
| `MSR_IA32_L3_CBMBASE` | 0xC90+ | M4 | CAT cache bit masks per CLOS |
| `MSR_COVERT_SIGNAL` | 0x150 | M5 | Fallback alert signal (alias of IA32_MCG_CAP) |

---

## Performance characteristics

| Scenario | Overhead |
|----------|----------|
| No active attack, all mitigations idle | < 0.1% |
| MDS mitigation only (VERW per context switch) | ~50 ns per context switch |
| MDS + L1TF (VERW + L1D flush) | ~250 ns per context switch |
| SMT isolation enabled | 5–15% throughput reduction for sensitive workloads |
| Full-spectrum mode (attack detected) | ~400 ns per context switch |

---

## Security design notes

### Zero-trust kernel assumption
The driver avoids calling kernel APIs that could be hooked by a compromised kernel for any security-critical operation. MSR reads/writes use `__readmsr`/`__writemsr` intrinsics directly; the VERW flush uses the MASM `PerformVerwFlush()` routine.

### IRQL discipline
- `PmiIsr` runs at `HIGH_LEVEL` (IRQL 26): zero paged memory, zero kernel API calls, only MSR reads and atomic counter increments.
- All spin-lock–protected shared state is accessed at `DISPATCH_LEVEL`.
- BCrypt, AuxKlib, and object manager APIs are called exclusively from `PASSIVE_LEVEL` sections (`#pragma alloc_text(PAGE, ...)`).

### Constant-time operations
All integrity comparisons (SHA-256 hash checks in M3, HMAC verification in M5) use the `ConstantTimeMemEq()` helper defined in the header. No early-exit loops exist on security-critical comparison paths.

### Spectre v1 gadget prevention
Every user-controlled index used to access an array goes through `SafeArrayIndex()` (constant-time bounds masking) before the load. All user-pointer accesses in IOCTL handlers use `LFENCE` before dereferencing.

### FORCEINLINE placement
`ExecuteSecurityBoundaryFlush()` and other `FORCEINLINE` functions that are called from multiple translation units have their **bodies in the header** (`KernelGuard.h`), below the declarations of all symbols they reference. Placing the body in a `.c` file would allow the Release optimizer to inline within that TU and discard the external symbol, causing linker errors in callers.

---

## Known limitations

| Area | Status |
|------|--------|
| **VM / hypervisor keyboard loss** | Hypervisor virtual keyboard filter drivers are indistinguishable from rootkit filters; M2 neutralizes them, causing complete keyboard loss in the guest. No hypervisor-detection guard (`CPUID` leaf 0x1 bit 31) is implemented yet. **Do not load without a VM snapshot.** See [Warnings & known risks](#warnings--known-risks). |
| **False-positive kbd filter detection** | Third-party keyboard remapping drivers, Bluetooth stacks, KVM switches, and accessibility drivers may not be in the M2 whitelist and will be neutralized. Verify `\Device\KeyboardClass0` stack before loading on non-standard hardware. |
| **CR4.TSD application crashes** | `RDTSC` from Ring 3 raises `#GP` while the driver is loaded. Games, encoders, and Wine/Proton layers that call `RDTSC` at high frequency may crash or degrade severely. |
| ECAM base lookup | `PciGetEcamBaseFromAcpi` is a stub. Parse the ACPI MCFG table to populate `g_EcamBase`; without it, PCIe scan and BME-disable mitigation are skipped. |
| VT-d base | `g_VtdMmioBase` must be populated from the ACPI DMAR table. Without it, DMA mitigation falls back to PCIe BME disable (which also requires ECAM). |
| HMAC key derivation | Currently uses `RDTSC ⊕ system-time`. Replace with `TPM2_Unseal` for production. |
| Baseline persistence | SHA-256 baselines are captured in memory at boot; they are lost on driver unload. A production system should store them in NVRAM or TPM NV indices. |
| False-positive `.text` mismatch | Windows Update or EDR products that patch kernel modules after driver load will trigger `ALERT_TEXT_PATCH` and enter fail-safe mode (maximum overhead). |
| Multi-socket / NUMA | PMU and CAT configuration runs per logical CPU via IPI; cross-socket CAT topology is not verified. |
| AMD support | MSR addresses and CPUID leaf handling target Intel SDM. AMD equivalents (`MSR_AMD_VIRT_SPEC_CTRL` 0xC0011F00) are defined but not fully exercised. |
| Test signing only | The deploy script creates a self-signed test certificate. A production deployment requires a Microsoft-issued EV code-signing certificate and WHQL submission. |
