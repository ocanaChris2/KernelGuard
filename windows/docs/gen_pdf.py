"""
gen_pdf.py  —  Generate Kernel_SideChannel_Driver_Architecture_v1.1.pdf
Uses Python's html module to escape content, then converts HTML → PDF via
Edge headless (--print-to-pdf).
"""
import os, subprocess, sys, html as H

BASE = r'C:\Users\fake_\OneDrive\Escritorio\SideChannelKernelPreventor'
HTMP = os.path.join(BASE, '_arch_v11.html')
PDFO = os.path.join(BASE, 'Kernel_SideChannel_Driver_Architecture_v1.1.pdf')
EDGE = r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'

e = H.escape  # shortcut

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sec(num, title):
    return f'<h2 class="section-header" id="s{num}"><span class="sec-num">{num}</span>{e(title)}</h2>\n'

def sub(num, title):
    return f'<h3 class="subsec-header" id="s{num.replace(".", "-")}">{e(num)}&nbsp;&nbsp;{e(title)}</h3>\n'

def code(text):
    return f'<pre class="code"><code>{e(text.strip())}</code></pre>\n'

def note(text):
    return f'<div class="note"><strong>Note:</strong> {e(text)}</div>\n'

def warn(text):
    return f'<div class="warn"><strong>Warning:</strong> {e(text)}</div>\n'

def table_header(*cols):
    ths = ''.join(f'<th>{e(c)}</th>' for c in cols)
    return f'<table><thead><tr>{ths}</tr></thead><tbody>\n'

def table_row(*cells):
    tds = ''.join(f'<td>{c}</td>' for c in cells)
    return f'<tr>{tds}</tr>\n'

def table_end():
    return '</tbody></table>\n'

def cite(*refs):
    """Inline citation badge, e.g. cite('P1','S1')"""
    badges = ' '.join(f'<span class="cite">[{r}]</span>' for r in refs)
    return badges

def new_badge():
    return '<span class="new-badge">NEW</span>'

def p(text):
    return f'<p>{text}</p>\n'

def ul(*items):
    lis = ''.join(f'<li>{i}</li>' for i in items)
    return f'<ul>{lis}</ul>\n'

def pb():  # page break
    return '<div class="page-break"></div>\n'

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

CSS = """
/* ── Reset & page setup ─────────────────────────────────────── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

@page {
    size: A4;
    margin: 22mm 18mm 22mm 18mm;
    @bottom-center {
        content: counter(page);
        font-size: 9pt;
        color: #666;
    }
}

body {
    font-family: 'Segoe UI', Arial, sans-serif;
    font-size: 10pt;
    line-height: 1.55;
    color: #1a1a1a;
    background: #fff;
    counter-reset: page;
}

/* ── Cover page ─────────────────────────────────────────────── */
.cover {
    page-break-after: always;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 240mm;
    text-align: center;
}
.cover-logo {
    width: 80px; height: 80px;
    background: #002147;
    border-radius: 16px;
    margin-bottom: 24pt;
    display: flex; align-items: center; justify-content: center;
}
.cover-logo-text { color: #fff; font-size: 30pt; font-weight: 900; }
.cover-title {
    font-size: 22pt; font-weight: 700;
    color: #002147; line-height: 1.25;
    margin-bottom: 6pt;
}
.cover-subtitle {
    font-size: 13pt; color: #555;
    margin-bottom: 30pt;
}
.cover-meta { font-size: 9pt; color: #888; margin-top: 4pt; }
.cover-version {
    background: #002147; color: #fff;
    font-size: 10pt; font-weight: 700;
    padding: 4pt 14pt; border-radius: 20pt;
    margin-bottom: 18pt;
}
.cover-divider {
    width: 60mm; height: 3px;
    background: linear-gradient(90deg, #002147, #0059b3);
    margin: 18pt auto;
    border-radius: 2px;
}
.cover-warning {
    margin-top: 28pt;
    border: 1.5px solid #c00;
    border-radius: 6px;
    padding: 8pt 14pt;
    font-size: 8.5pt;
    color: #c00;
    max-width: 320pt;
    text-align: left;
}

/* ── TOC ─────────────────────────────────────────────────────── */
.toc-page { page-break-after: always; }
.toc-title {
    font-size: 16pt; font-weight: 700; color: #002147;
    border-bottom: 2px solid #002147;
    padding-bottom: 6pt; margin-bottom: 14pt;
}
.toc-entry { display: flex; justify-content: space-between; padding: 2pt 0; }
.toc-entry.l1 { font-weight: 600; font-size: 10pt; margin-top: 6pt; }
.toc-entry.l2 { font-size: 9.5pt; padding-left: 18pt; color: #333; }
.toc-entry.l3 { font-size: 9pt; padding-left: 36pt; color: #555; }
.toc-dots { flex: 1; border-bottom: 1px dotted #bbb; margin: 0 6pt 3pt; }
.toc-pnum { font-size: 9pt; color: #555; min-width: 24pt; text-align: right; }
.toc-new { color: #0066cc; font-size: 8pt; font-weight: 700;
           background: #e8f0fe; border-radius: 3px; padding: 0 4pt;
           margin-left: 6pt; }

/* ── Section headings ───────────────────────────────────────── */
.section-header {
    font-size: 14pt; font-weight: 700; color: #002147;
    margin: 0 0 12pt 0;
    padding-bottom: 6pt;
    border-bottom: 2.5px solid #002147;
    page-break-after: avoid;
}
.sec-num {
    display: inline-block;
    background: #002147; color: #fff;
    font-size: 10pt; font-weight: 700;
    padding: 1pt 8pt; border-radius: 4px;
    margin-right: 10pt;
}
.subsec-header {
    font-size: 11pt; font-weight: 700; color: #0059b3;
    margin: 16pt 0 8pt 0;
    page-break-after: avoid;
}

/* ── Body layout ────────────────────────────────────────────── */
.section { margin-bottom: 28pt; }
p { margin-bottom: 7pt; }
ul, ol { padding-left: 18pt; margin-bottom: 8pt; }
li { margin-bottom: 3pt; }

/* ── Code blocks ────────────────────────────────────────────── */
pre.code {
    background: #f4f4f6;
    border: 1px solid #d0d0d8;
    border-left: 4px solid #002147;
    border-radius: 4px;
    padding: 10pt 12pt;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8pt;
    line-height: 1.5;
    overflow-wrap: break-word;
    white-space: pre-wrap;
    margin: 10pt 0;
    page-break-inside: avoid;
}
code {
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8.5pt;
    background: #f0f0f4;
    padding: 1pt 4pt;
    border-radius: 3px;
}
pre.code code { background: none; padding: 0; font-size: inherit; }

/* ── Tables ─────────────────────────────────────────────────── */
table {
    width: 100%;
    border-collapse: collapse;
    font-size: 9pt;
    margin: 10pt 0 14pt 0;
    page-break-inside: auto;
}
thead tr { background: #002147; color: #fff; }
thead th { padding: 5pt 8pt; font-weight: 700; text-align: left; font-size: 9pt; }
tbody tr:nth-child(even) { background: #f5f7ff; }
tbody tr:nth-child(odd)  { background: #fff; }
tbody td { padding: 4pt 8pt; vertical-align: top; border-bottom: 0.5px solid #ddd; }

/* ── Notes & warnings ───────────────────────────────────────── */
.note {
    background: #e8f4fd; border-left: 4px solid #0077cc;
    border-radius: 0 4px 4px 0;
    padding: 8pt 10pt; margin: 10pt 0; font-size: 9pt;
}
.warn {
    background: #fff3e0; border-left: 4px solid #e65100;
    border-radius: 0 4px 4px 0;
    padding: 8pt 10pt; margin: 10pt 0; font-size: 9pt;
}

/* ── Citations ──────────────────────────────────────────────── */
.cite {
    display: inline-block;
    background: #0059b3; color: #fff;
    font-size: 7.5pt; font-weight: 700;
    padding: 0 4pt; border-radius: 3px;
    vertical-align: middle;
    line-height: 1.4;
    margin: 0 1pt;
}
.new-badge {
    display: inline-block;
    background: #1a7f37; color: #fff;
    font-size: 7.5pt; font-weight: 700;
    padding: 1pt 5pt; border-radius: 3px;
    vertical-align: middle;
    margin-left: 6pt;
}

/* ── IRQL highlight ─────────────────────────────────────────── */
.irql-high   { color: #c00; font-weight: 700; }
.irql-disp   { color: #b36b00; font-weight: 700; }
.irql-pass   { color: #1a7f37; font-weight: 700; }

/* ── Page break utility ─────────────────────────────────────── */
.page-break { page-break-before: always; }

/* ── References list ────────────────────────────────────────── */
.ref-block {
    background: #f9f9fb; border: 1px solid #ddd;
    border-radius: 4px; padding: 10pt 12pt;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 8pt; line-height: 1.6;
    margin: 6pt 0; white-space: pre-wrap;
    page-break-inside: avoid;
}
.ref-header {
    font-size: 11pt; font-weight: 700; color: #002147;
    margin: 14pt 0 6pt 0;
    border-bottom: 1px solid #ccc;
    padding-bottom: 4pt;
}
.ref-group { margin-bottom: 18pt; }
"""

# ---------------------------------------------------------------------------
# Cover
# ---------------------------------------------------------------------------

def build_cover():
    return f"""
<div class="cover">
  <div class="cover-logo"><span class="cover-logo-text">SC</span></div>
  <div class="cover-title">SideChannelKernelPreventor<br>Driver Architecture Specification</div>
  <div class="cover-subtitle">Windows 11 x64 Ring&nbsp;0 Kernel-Mode Driver (WDM/KMDF)</div>
  <div class="cover-divider"></div>
  <div class="cover-version">Version 1.1</div>
  <div class="cover-meta">Revision Date: May 2026</div>
  <div class="cover-meta">Classification: Internal Technical Reference</div>
  <div class="cover-warning">
    <strong>Test &amp; Development Build</strong><br>
    This driver requires test-signing mode (<code>bcdedit /set testsigning on</code>).
    Deploy only in isolated test virtual machines. Not for production use.
  </div>
</div>
"""

# ---------------------------------------------------------------------------
# Table of Contents
# ---------------------------------------------------------------------------

def build_toc():
    entries = [
        ("l1", "1", "Project Overview", ""),
        ("l1", "2", "Architecture Overview", ""),
        ("l2", "2.1", "Zero-Trust Kernel Assumption", ""),
        ("l2", "2.2", "Module Interaction Model", ""),
        ("l1", "3", "Module 1 — Side-Channel Attack Detection", ""),
        ("l2", "3.1", "PMU Configuration via MSRs", ""),
        ("l2", "3.2", "Cache-Miss Rate Monitoring", ""),
        ("l2", "3.3", "RDTSC Rate Anomaly Detection", ""),
        ("l2", "3.4", "PMI Handler Constraints", ""),
        ("l1", "4", "Module 2 — Hardware Keylogger &amp; Peripheral Detection", ""),
        ("l2", "4.1", "PCIe ECAM Walk", ""),
        ("l2", "4.2", "VT-d IOMMU Verification", ""),
        ("l2", "4.3", "Keyboard Filter Driver Detection", ""),
        ("l1", "5", "Module 3 — Kernel Integrity &amp; Hook Detection", ""),
        ("l2", "5.1", "IDT Integrity Verification", ""),
        ("l2", "5.2", "Dispatch-Routine Hook Detection", ""),
        ("l2", "5.3", "SHA-256 .text Section Verification", ""),
        ("l1", "6", "Module 4 — Cache Mitigation Engine", ""),
        ("l2", "6.1", "CPU Capability Probing", ""),
        ("l2", "6.2", "Sensitive Page Tagging", ""),
        ("l2", "6.3", "VERW / L1D Flush Strategy", ""),
        ("l2", "6.4", "Cache Allocation Technology (CAT)", ""),
        ("l2", "6.5", "SMT / HT Isolation", ""),
        ("l1", "7", "Module 5 — Secure Ring&nbsp;0 ↔ Ring&nbsp;3 Communication", ""),
        ("l2", "7.1", "HMAC-Authenticated Shared Memory", ""),
        ("l2", "7.2", "MSR-Based Covert Signaling (Fallback)", ""),
        ("l2", "7.3", "TPM 2.0 Key Derivation", ""),
        ("l1", "8", "Cross-Module Event Flow &amp; Performance", ""),
        ("l2", "8.1", "Event Dispatch Table", ""),
        ("l2", "8.2", "IRQL Constraints Summary", ""),
        ("l2", "8.3", "Performance Targets", ""),
        ("l1", "9", "Literature Foundation  <span class='toc-new'>NEW</span>", ""),
        ("l2", "9.1", "Textbooks and Monographs", ""),
        ("l2", "9.2", "Selected Academic Papers", ""),
        ("l2", "9.3", "Standards and Technical Reports", ""),
        ("l2", "9.4", "Courses and Lecture Series", ""),
        ("l1", "10", "Literature Map  <span class='toc-new'>NEW</span>", ""),
        ("l1", "A", "Appendix A — Threat Model Maintenance  <span class='toc-new'>NEW</span>", ""),
        ("l1", "B", "Appendix B — Prior Art Analysis  <span class='toc-new'>NEW</span>", ""),
    ]
    rows = ""
    for level, num, title, pg in entries:
        rows += f'<div class="toc-entry {level}"><span>{num}&nbsp;&nbsp;{title}</span><span class="toc-dots"></span><span class="toc-pnum">{pg}</span></div>\n'
    return f"""
<div class="toc-page">
  <div class="toc-title">Table of Contents</div>
  {rows}
</div>
"""

# ---------------------------------------------------------------------------
# Section 1 — Project Overview
# ---------------------------------------------------------------------------

def build_s1():
    return f"""
<div class="section">
{sec(1, "Project Overview")}
<p>
<strong>SideChannelKernelPreventor</strong> is a Windows&nbsp;11 x64 Ring&nbsp;0 kernel-mode driver
(WDM/KMDF) designed to detect and actively mitigate side-channel attacks, compromised kernel
components, and hardware-level keyloggers. It is structured as five synergistic modules that
share a central integrity-verified state structure protected by spin locks at
<span class="irql-disp">DISPATCH_LEVEL</span>.
</p>
<p>
The driver's threat model covers speculative-execution attacks (Spectre {cite("P1")}, Meltdown
{cite("P2")}, Foreshadow {cite("P3")}), microarchitectural data-sampling (MDS) attacks such as
RIDL {cite("P4")} and ZombieLoad {cite("P5")}, classic cache-timing attacks {cite("P7","P8","P9")},
and physical-layer threats including DMA-capable rogue peripherals and hardware keyloggers.
</p>
{table_header("Module", "Domain", "Key Threat Addressed")}
{table_row("<strong>M1</strong>", "PMU / cache anomaly detection", f"Spectre {cite('P1')}, Flush+Reload {cite('P7')}, Flush+Flush {cite('P8')}")}
{table_row("<strong>M2</strong>", "PCIe / IOMMU verification", f"DMA attacks, rogue peripherals {cite('S13')}")}
{table_row("<strong>M3</strong>", "Kernel integrity &amp; hook detection", f"Meltdown {cite('P2')}, rootkit hooks {cite('S12')}")}
{table_row("<strong>M4</strong>", "Cache mitigation engine", f"MDS {cite('P4','P5')}, L1TF {cite('P3')}, SMT cross-contamination {cite('P11')}")}
{table_row("<strong>M5</strong>", "Secure Ring 0 ↔ Ring 3 channel", f"Tamper-proof alert delivery {cite('S3','S7')}")}
{table_end()}
</div>
"""

# ---------------------------------------------------------------------------
# Section 2 — Architecture Overview
# ---------------------------------------------------------------------------

def build_s2():
    return f"""
<div class="section">
{sec(2, "Architecture Overview")}
{sub("2.1", "Zero-Trust Kernel Assumption")}
<p>
The driver operates under a <em>zero-trust kernel assumption</em>: it cannot rely on standard
kernel APIs for critical integrity operations because the kernel itself may be partially
compromised. Consequences of this assumption are:
</p>
{ul(
    "MSR reads and writes use inline MASM intrinsics — never a wrapper that could be interposed.",
    "PCIe configuration space is accessed via ECAM physical addresses, bypassing the OS device manager.",
    "HMAC authentication of all Ring&nbsp;3 notifications prevents spoofed alerts even if DeviceIoControl dispatch is hooked.",
    f"SHA-256 of kernel <code>.text</code> sections is compared against TPM-sealed baselines {cite('S3')}.",
)}

{sub("2.2", "Module Interaction Model")}
<p>
All modules share <code>g_DriverState</code>, a central <code>DRIVER_STATE</code> structure.
Access requires acquiring <code>g_DriverState.StateLock</code> at <span class="irql-disp">DISPATCH_LEVEL</span>.
Cross-module events are dispatched via <code>DispatchCrossModuleEvent()</code> in
<code>shared_state.c</code>.
</p>
{code("""// shared_state.h — Central state (abbreviated)
typedef struct _DRIVER_STATE {
    KSPIN_LOCK     StateLock;           // DISPATCH_LEVEL guard
    ULONG          ActiveMitigations;   // Bitmask of enabled mitigations
    LONGLONG       LastIntegrityCheck;  // 100-ns ticks
    BOOLEAN        FailSafeMode;        // Set on .text hash mismatch
    CPU_MITIGATION g_CpuMit[MAXIMUM_PROCESSORS];  // Per-core strategy
} DRIVER_STATE;

extern DRIVER_STATE g_DriverState;

VOID DispatchCrossModuleEvent(
    _In_ ULONG       SourceModule,   // MODULE_ID_M1 … MODULE_ID_M5
    _In_ EVENT_TYPE  Event,
    _In_ ULONG_PTR   Parameter
);""")}
{warn("StateLock must be acquired before any read or write of g_DriverState fields. Failure to do so causes a DRIVER_IRQL_NOT_LESS_OR_EQUAL bugcheck.")}
</div>
"""

# ---------------------------------------------------------------------------
# Section 3 — Module 1
# ---------------------------------------------------------------------------

def build_s3():
    return f"""
<div class="section">
{pb()}
{sec(3, "Module 1 — Side-Channel Attack Detection (PMU)")}
<p>
Module 1 instruments the CPU's Performance Monitoring Unit (PMU) to detect
cache-side-channel and timing-based attack patterns in real time. It runs primarily at
<span class="irql-disp">DISPATCH_LEVEL</span> for configuration and at
<span class="irql-high">HIGH_LEVEL</span> inside the PMI handler.
{cite("S1","S2","L5")}
</p>

{sub("3.1", "PMU Configuration via MSRs")}
<p>
Four PMU counters are configured at driver load time. Event selection uses
<code>IA32_PERFEVTSEL0–3</code> (MSR 0x186–0x189); counter values are read from
<code>IA32_PMC0–3</code> (MSR 0x0C1–0x0C4). {cite("S1")}
</p>
{code("""// pmu_detection.c
// MSR addresses — Intel SDM Vol.4 §18.2.1 [S1]
#define MSR_PERFEVTSEL_BASE  0x186UL
#define MSR_PMC_BASE         0x0C1UL

// IA32_PERFEVTSELx bit layout
// [7:0]  Event Select   [15:8] Unit Mask (UMASK)
// [16]   USR  [17] OS  [22] EN  [20] INT
#define PMU_EVT_LLC_MISS     0x412E00UL  // LLC references, OS+USR, EN, INT
#define PMU_EVT_L1D_MISS     0x4F2408UL  // L1D read misses, OS+USR, EN, INT
#define PMU_EVT_BR_MISP      0x4FC400UL  // Branch mispredictions, OS+USR, EN, INT
#define PMU_EVT_RDTSC_RETIRE 0x410032UL  // RDTSC retired instructions, USR only, EN, INT

static VOID
ConfigurePmuCounters(VOID)
{
    // Counter 0 — LLC miss rate  [P7][P8]
    __writemsr(MSR_PERFEVTSEL_BASE + 0, PMU_EVT_LLC_MISS);
    __writemsr(MSR_PMC_BASE + 0, 0ULL);

    // Counter 1 — L1D miss rate  [P9][P10]
    __writemsr(MSR_PERFEVTSEL_BASE + 1, PMU_EVT_L1D_MISS);
    __writemsr(MSR_PMC_BASE + 1, 0ULL);

    // Counter 2 — Branch misprediction (Spectre indicator)  [P1]
    __writemsr(MSR_PERFEVTSEL_BASE + 2, PMU_EVT_BR_MISP);
    __writemsr(MSR_PMC_BASE + 2, 0ULL);

    // Counter 3 — RDTSC retirement rate (timing-channel probe)  [P10][P12]
    __writemsr(MSR_PERFEVTSEL_BASE + 3, PMU_EVT_RDTSC_RETIRE);
    __writemsr(MSR_PMC_BASE + 3, 0ULL);
}""")}

{sub("3.2", "Cache-Miss Rate Monitoring")}
<p>
Flush+Reload {cite("P7")} and Flush+Flush {cite("P8")} attacks produce a characteristic LLC
miss rate spike. M1 samples PMC0 and PMC1 inside the PMI handler and raises a cross-module
event when the ratio exceeds a calibrated threshold.
</p>
{code("""// pmu_detection.c
// Thresholds derived from measurement on target hardware per [P7] §5, [P10]
#define LLC_MISS_THRESHOLD_PER_MS   180000ULL
#define L1D_MISS_THRESHOLD_PER_MS  1200000ULL
#define RDTSC_RATE_THRESHOLD_PER_MS   8000ULL

static VOID
AnalyzePmuCounters(
    _In_ ULONGLONG LlcMisses,
    _In_ ULONGLONG L1dMisses,
    _In_ ULONGLONG RdtscRetired
)
{
    if (LlcMisses  > LLC_MISS_THRESHOLD_PER_MS ||
        L1dMisses  > L1D_MISS_THRESHOLD_PER_MS)
    {
        // Probable Flush+Reload or Flush+Flush activity  [P7][P8]
        DispatchCrossModuleEvent(
            MODULE_ID_M1,
            EVENT_HIGH_CACHE_MISS_RATE,
            (ULONG_PTR)LlcMisses);
    }

    if (RdtscRetired > RDTSC_RATE_THRESHOLD_PER_MS)
    {
        // Probable timing-channel probe; alert Ring 3  [P10][P12]
        DispatchCrossModuleEvent(
            MODULE_ID_M1,
            EVENT_RDTSC_ANOMALY,
            (ULONG_PTR)RdtscRetired);
    }
}""")}

{sub("3.3", "PMI Handler Constraints")}
{warn("The PMI handler executes at HIGH_LEVEL IRQL. No paged memory, no kernel API calls, no spinlock acquisitions. Read only non-paged globals and MSRs.")}
{code("""// pmu_detection.c — PMI interrupt handler
// IRQL: HIGH_LEVEL — zero paged memory, no KAPI, no locks  [L6][S1]
BOOLEAN
PmiIsr(
    _In_ PKINTERRUPT Interrupt,
    _In_ PVOID       ServiceContext
)
{
    UNREFERENCED_PARAMETER(Interrupt);
    UNREFERENCED_PARAMETER(ServiceContext);

    // Read counters at HIGH_LEVEL using MSR intrinsics (not hookcable)  [S1]
    ULONGLONG llc   = __readmsr(MSR_PMC_BASE + 0);
    ULONGLONG l1d   = __readmsr(MSR_PMC_BASE + 1);
    ULONGLONG rdtsc = __readmsr(MSR_PMC_BASE + 3);

    // Reset counters
    __writemsr(MSR_PMC_BASE + 0, 0ULL);
    __writemsr(MSR_PMC_BASE + 1, 0ULL);
    __writemsr(MSR_PMC_BASE + 3, 0ULL);

    // Record in non-paged ring buffer (no allocation, no lock)
    ULONG idx = (ULONG)InterlockedIncrement((LONG*)&g_PmiRing.WriteIdx)
                & (PMI_RING_SIZE - 1);
    g_PmiRing.Samples[idx].LlcMisses    = llc;
    g_PmiRing.Samples[idx].L1dMisses    = l1d;
    g_PmiRing.Samples[idx].RdtscRetired = rdtsc;

    // Queue a DPC at DISPATCH_LEVEL for analysis (safe to call locks there)
    IoRequestDpc(g_DeviceObject, NULL, NULL);

    return TRUE;
}""")}
</div>
"""

# ---------------------------------------------------------------------------
# Section 4 — Module 2
# ---------------------------------------------------------------------------

def build_s4():
    return f"""
<div class="section">
{pb()}
{sec(4, "Module 2 — Hardware Keylogger & Peripheral Detection")}
<p>
Module 2 detects unauthorized hardware by walking the PCIe topology directly via ECAM
(bypassing the OS device stack), verifying Intel VT-d IOMMU configuration, and comparing
hardware-reported keyboard devices against the Windows driver stack. {cite("S13","S14")}
</p>

{sub("4.1", "PCIe ECAM Walk")}
<p>
ECAM maps PCIe configuration space at a physical base address in 256 MB blocks (one
4&nbsp;KB page per device function). The driver reads <code>MmMapIoSpace</code> at
<span class="irql-pass">PASSIVE_LEVEL</span> to obtain a kernel virtual address. {cite("S13")}
</p>
{code("""// hw_keylogger_detect.c
// PCIe Enhanced Configuration Access Mechanism — PCIe Base Spec Rev 5.0 §7.2 [S13]
// ECAM formula: PhysBase | (Bus << 20) | (Dev << 15) | (Func << 12)
#define ECAM_BASE_PHYS  0xE0000000ULL   // Read from MCFG ACPI table at runtime
#define ECAM_CFG_SIZE   0x10000000ULL   // 256 MB covers all 256 buses

typedef struct _PCIE_CFG_SPACE {
    USHORT VendorId;         // 0x00
    USHORT DeviceId;         // 0x02
    USHORT Command;          // 0x04
    USHORT Status;           // 0x06
    UCHAR  RevisionId;       // 0x08
    UCHAR  ClassCode[3];     // 0x09  [2]=Base [1]=Sub [0]=ProgIf
    // ... (standard header)
} PCIE_CFG_SPACE, *PPCIE_CFG_SPACE;

// ClassCode[2] == 0x09 → Input device controller
// ClassCode[1] == 0x00 → Keyboard controller
#define PCI_CLASS_INPUT_KEYBOARD  0x09
#define PCI_SUBCLASS_KEYBOARD     0x00

static NTSTATUS
WalkPcieBusTree(
    _In_  PVOID   EcamVirtBase,
    _Out_ PULONG  UnauthorizedDeviceCount
)
{
    *UnauthorizedDeviceCount = 0;

    for (ULONG bus = 0; bus <= 255; bus++) {
        for (ULONG dev = 0; dev < 32; dev++) {
            for (ULONG func = 0; func < 8; func++) {

                ULONG_PTR offset = ((ULONG_PTR)bus  << 20) |
                                   ((ULONG_PTR)dev   << 15) |
                                   ((ULONG_PTR)func  << 12);
                volatile PPCIE_CFG_SPACE cfg =
                    (PPCIE_CFG_SPACE)((UCHAR*)EcamVirtBase + offset);

                if (cfg->VendorId == 0xFFFF)
                    continue;  // No device

                if (cfg->ClassCode[2] == PCI_CLASS_INPUT_KEYBOARD &&
                    cfg->ClassCode[1] == PCI_SUBCLASS_KEYBOARD)
                {
                    if (!IsDeviceAuthorized(cfg->VendorId, cfg->DeviceId))
                    {
                        (*UnauthorizedDeviceCount)++;
                        LogAlert(ALERT_LEVEL_CRITICAL,
                            "Unauthorized keyboard device: VID=%04X DID=%04X "
                            "Bus=%u Dev=%u Func=%u",
                            cfg->VendorId, cfg->DeviceId, bus, dev, func);
                    }
                }
            }
        }
    }
    return STATUS_SUCCESS;
}""")}

{sub("4.2", "VT-d IOMMU Verification")}
<p>
The driver reads the VT-d Capability Register to verify IOMMU is enabled and that
no bypass conditions exist. If a DMA violation is detected, M4 is notified to lock
the IOMMU context entry. {cite("S1")}
</p>
{code("""// hw_keylogger_detect.c — IOMMU capability check
// Intel VT-d Architecture Specification §11.4.2
#define VTDUNIT_PHYS_BASE  0xFED90000ULL  // Typical default; read DMAR ACPI table

#define VTD_REG_CAP     0x08   // Capability Register offset
#define VTD_REG_ECAP    0x10   // Extended Capability Register offset
#define VTD_CAP_DRD     (1ULL << 55)  // DMA Read Draining supported
#define VTD_CAP_ESIRTPS (1ULL << 29)  // Enhanced Set Interrupt Remap TPS

static BOOLEAN
VerifyIommuEnabled(
    _In_ PVOID VtdVirtBase
)
{
    volatile ULONGLONG cap  = *(volatile ULONGLONG*)((UCHAR*)VtdVirtBase + VTD_REG_CAP);
    volatile ULONGLONG ecap = *(volatile ULONGLONG*)((UCHAR*)VtdVirtBase + VTD_REG_ECAP);

    BOOLEAN dmaRemapActive = (ecap & 0x1) != 0;  // EIM: Extended Interrupt Mode
    BOOLEAN drainSupported = (cap & VTD_CAP_DRD)  != 0;

    if (!dmaRemapActive) {
        LogAlert(ALERT_LEVEL_HIGH, "IOMMU DMA remapping inactive — DMA attacks possible");
        return FALSE;
    }

    UNREFERENCED_PARAMETER(drainSupported);
    return TRUE;
}""")}

{sub("4.3", "Keyboard Filter Driver Detection")}
<p>
The OS driver stack for each keyboard device is enumerated via
<code>IoGetDeviceProperty</code> at <span class="irql-pass">PASSIVE_LEVEL</span>. Each
filter driver's image path is compared against an allowlist of Microsoft-signed components.
Unauthorized entries trigger an alert and a cross-module event. {cite("S12")}
</p>
</div>
"""

# ---------------------------------------------------------------------------
# Section 5 — Module 3
# ---------------------------------------------------------------------------

def build_s5():
    return f"""
<div class="section">
{pb()}
{sec(5, "Module 3 — Kernel Integrity & Hook Detection")}
<p>
Module 3 detects runtime modifications to the kernel's control flow including IDT hooking,
inline detours on keyboard dispatch routines, and alterations to kernel <code>.text</code>
sections. All comparisons use <strong>constant-time algorithms</strong> to prevent timing
leakage per Kocher {cite("P12")}. {cite("S5","S6","S12")}
</p>

{sub("5.1", "IDT Integrity Verification")}
{code("""// kernel_integrity.c
// IDT Gate layout — Intel SDM Vol.3A §6.11 [S1]
#pragma pack(push, 1)
typedef struct _IDT_GATE {
    USHORT  OffsetLow;     // [15:0]
    USHORT  Selector;      // Segment selector
    UCHAR   Ist;           // Interrupt Stack Table index (bits [2:0])
    UCHAR   Type;          // Gate type (0x8E = 64-bit interrupt gate)
    USHORT  OffsetMid;     // [31:16]
    ULONG   OffsetHigh;    // [63:32]
    ULONG   Reserved;
} IDT_GATE, *PIDT_GATE;
#pragma pack(pop)

// IRQ 1 = keyboard (PIC line 1 mapped to vector 0x31 on typical Windows)
#define KEYBOARD_IRQ_VECTOR  0x31

static NTSTATUS
VerifyIdtIntegrity(VOID)
{
    IDTR idtr;
    __sidt(&idtr);   // Read IDTR directly — no kernel wrapper

    PIDT_GATE idt  = (PIDT_GATE)(ULONG_PTR)idtr.Base;
    PIDT_GATE gate = &idt[KEYBOARD_IRQ_VECTOR];

    ULONG_PTR handler = ((ULONG_PTR)gate->OffsetHigh  << 32) |
                        ((ULONG_PTR)gate->OffsetMid   << 16) |
                         (ULONG_PTR)gate->OffsetLow;

    // Handler must reside in ntoskrnl.exe image range
    if (handler < g_KernelBase || handler >= g_KernelBase + g_KernelSize) {
        LogAlert(ALERT_LEVEL_CRITICAL,
            "IDT vector 0x%02X handler 0x%llX outside kernel range",
            KEYBOARD_IRQ_VECTOR, (ULONGLONG)handler);

        DispatchCrossModuleEvent(MODULE_ID_M3, EVENT_IDT_HOOK_DETECTED, handler);
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}""")}

{sub("5.2", "Dispatch-Routine Hook Detection")}
<p>
Inline hooks (detours) on <code>Kbclass</code> and <code>Kbdhid</code>
<code>IRP_MJ_READ</code> dispatch routines are detected by comparing the first 16 bytes
of the function against an in-memory copy taken at driver load time. {cite("P2","S12")}
</p>
{code("""// kernel_integrity.c
#define DETOUR_SNAPSHOT_BYTES  16

// Baseline snapshot taken at DriverEntry — before any potential hooking
static UCHAR g_KbclassReadBaseline[DETOUR_SNAPSHOT_BYTES];
static ULONG_PTR g_KbclassReadAddr;

static NTSTATUS
SnapshotDispatchBaseline(
    _In_ PDRIVER_OBJECT KbclassDriver
)
{
    g_KbclassReadAddr =
        (ULONG_PTR)KbclassDriver->MajorFunction[IRP_MJ_READ];
    RtlCopyMemory(g_KbclassReadBaseline,
                  (PVOID)g_KbclassReadAddr,
                  DETOUR_SNAPSHOT_BYTES);
    return STATUS_SUCCESS;
}

static BOOLEAN
CheckForDetour(VOID)
{
    UCHAR current[DETOUR_SNAPSHOT_BYTES];
    RtlCopyMemory(current, (PVOID)g_KbclassReadAddr, DETOUR_SNAPSHOT_BYTES);

    // Constant-time comparison prevents timing oracle  [P12]
    UCHAR diff = 0;
    for (ULONG i = 0; i < DETOUR_SNAPSHOT_BYTES; i++)
        diff |= (current[i] ^ g_KbclassReadBaseline[i]);

    return (diff != 0);
}""")}

{sub("5.3", "SHA-256 .text Section Verification")}
<p>
The SHA-256 digest of <code>ntoskrnl.exe</code>'s <code>.text</code> section is computed
using BCrypt at <span class="irql-pass">PASSIVE_LEVEL</span> and compared against a TPM-sealed
baseline {cite("S3")}. Verification is staggered across DPC callbacks to limit performance
impact.
</p>
{code("""// kernel_integrity.c — SHA-256 .text verification  [S3][P2]
// Runs at PASSIVE_LEVEL via a work item (DPC queues the work item)
static VOID
VerifyKernelTextHash(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PVOID          Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Context);

    BCRYPT_ALG_HANDLE hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    UCHAR digest[32] = {0};
    ULONG cbHash     = sizeof(digest);
    ULONG cbObject   = 0, cbData = 0;

    // BCrypt requires PASSIVE_LEVEL — do not call from DPC directly  [L6]
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                      (PUCHAR)&cbObject, sizeof(ULONG), &cbData, 0);

    PVOID pHashObj = ExAllocatePoolWithTag(NonPagedPoolNx, cbObject, 'HASH');
    BCryptCreateHash(hAlg, &hHash, pHashObj, cbObject, NULL, 0, 0);
    BCryptHashData(hHash, (PUCHAR)g_KernelTextBase, g_KernelTextSize, 0);
    BCryptFinishHash(hHash, digest, cbHash, 0);

    // Constant-time comparison against TPM-sealed baseline  [P12][S3]
    UCHAR diff = 0;
    for (ULONG i = 0; i < 32; i++)
        diff |= (digest[i] ^ g_KernelTextBaseline[i]);

    if (diff != 0) {
        LogAlert(ALERT_LEVEL_CRITICAL, ".text hash mismatch — kernel may be compromised");
        DispatchCrossModuleEvent(MODULE_ID_M3, EVENT_TEXT_HASH_MISMATCH, 0);
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    ExFreePoolWithTag(pHashObj, 'HASH');
}""")}
</div>
"""

# ---------------------------------------------------------------------------
# Section 6 — Module 4
# ---------------------------------------------------------------------------

def build_s6():
    return f"""
<div class="section">
{pb()}
{sec(6, "Module 4 — Cache Mitigation Engine")}
<p>
Module 4 is the core mitigation engine. It does not attempt to identify cryptographic code —
it protects <em>any</em> sensitive memory based on a tagging discipline. It uses
<code>VERW</code>/<code>IA32_FLUSH_CMD</code> flushes, CAT cache partitioning, IBRS/STIBP
speculation controls, and SMT isolation to neutralize MDS {cite("P4","P5")}, L1TF {cite("P3","S11")},
and Spectre {cite("P1","S9")} attack vectors.
</p>

{sub("6.1", "CPU Capability Probing")}
<p>
At driver load the CPU's vulnerability profile is read from
<code>IA32_ARCH_CAPABILITIES</code> (MSR 0x10A) {cite("S1","S10","S11")}. This determines
the cheapest safe mitigation strategy for the current processor.
</p>
{code("""// cache_mitigation.c
// IA32_ARCH_CAPABILITIES bits — Intel SDM Vol.4 §2.1, Table 2-2 [S1]
// Intel SA-00233 §3.1 [S10], Intel SA-00161 §2.1 [S11]
#define MSR_IA32_ARCH_CAPABILITIES  0x10AUL
#define ARCH_CAP_RDCL_NO    (1ULL << 0)  // Not vulnerable to Meltdown/RDCL
#define ARCH_CAP_IBRS_ALL   (1ULL << 1)  // Enhanced IBRS supported
#define ARCH_CAP_RSBA       (1ULL << 2)  // RSB alternate branch prediction
#define ARCH_CAP_SKIP_L1DFL (1ULL << 3)  // L1D flush not required for VMX
#define ARCH_CAP_MDS_NO     (1ULL << 5)  // Not vulnerable to MDS  [S10]
#define ARCH_CAP_TAA_NO     (1ULL << 8)  // Not vulnerable to TSX async abort

typedef enum _MITIGATION_STRATEGY {
    MIT_NONE            = 0,   // Not vulnerable
    MIT_VERW_ONLY       = 1,   // MDS only: VERW on domain exit  [P4][P5]
    MIT_L1D_FLUSH       = 2,   // L1TF: IA32_FLUSH_CMD on VM entry  [P3]
    MIT_VERW_AND_L1D    = 3,   // Both MDS and L1TF present
    MIT_FULL_SPECTRUM   = 4,   // Hash mismatch fail-safe: everything
} MITIGATION_STRATEGY;

static VOID
ProbeCpuCapabilities(
    _Out_ PMITIGATION_STRATEGY Strategy
)
{
    ULONGLONG archCap = 0;

    // CPUID.7.0:EDX[29] = IA32_ARCH_CAPABILITIES availability check
    int cpuidResult[4];
    __cpuidex(cpuidResult, 7, 0);
    BOOLEAN hasArchCap = ((cpuidResult[3] >> 29) & 1) != 0;

    if (hasArchCap) {
        archCap = __readmsr(MSR_IA32_ARCH_CAPABILITIES);

        if (archCap & ARCH_CAP_MDS_NO)
            g_CpuMit[KeGetCurrentProcessorNumber()].Features |= CPU_FEAT_MDS_NO;

        if (archCap & ARCH_CAP_RDCL_NO)
            g_CpuMit[KeGetCurrentProcessorNumber()].Features |= CPU_FEAT_L1TF_NO;
    }

    BOOLEAN needVerw = !(archCap & ARCH_CAP_MDS_NO);
    BOOLEAN needL1d  = !(archCap & ARCH_CAP_RDCL_NO) &&
                       !(archCap & ARCH_CAP_SKIP_L1DFL);

    if       (!needVerw && !needL1d) *Strategy = MIT_NONE;
    else if  ( needVerw && !needL1d) *Strategy = MIT_VERW_ONLY;
    else if  (!needVerw &&  needL1d) *Strategy = MIT_L1D_FLUSH;
    else                             *Strategy = MIT_VERW_AND_L1D;
}""")}

{sub("6.2", "Sensitive Page Tagging")}
<p>
Callers tag pages containing keystroke buffers, key material, or crypto I/O using
<code>ScpdTagSensitivePage()</code>. Tagged pages are tracked in a non-paged bitmap and
are excluded from user-mode page tables when not strictly required (KPTI-style).
{cite("P2","S12")}
</p>
{code("""// cache_mitigation.c — Sensitive page API
// Based on KPTI principles from Meltdown mitigation  [P2][S12]
#define MAX_SENSITIVE_PAGES  4096
static ULONG_PTR g_SensitivePages[MAX_SENSITIVE_PAGES];
static ULONG     g_SensitivePageCount = 0;
static KSPIN_LOCK g_SensitivePagesLock;

NTSTATUS
ScpdTagSensitivePage(
    _In_ PVOID   VirtualAddress,
    _In_ BOOLEAN Sensitive
)
{
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_SensitivePagesLock, &oldIrql);

    ULONG_PTR pfn = MmGetPhysicalAddress(VirtualAddress).QuadPart >> PAGE_SHIFT;

    if (Sensitive) {
        if (g_SensitivePageCount < MAX_SENSITIVE_PAGES) {
            g_SensitivePages[g_SensitivePageCount++] = pfn;
        }
    } else {
        for (ULONG i = 0; i < g_SensitivePageCount; i++) {
            if (g_SensitivePages[i] == pfn) {
                g_SensitivePages[i] =
                    g_SensitivePages[--g_SensitivePageCount];
                break;
            }
        }
    }

    KeReleaseSpinLock(&g_SensitivePagesLock, oldIrql);
    return STATUS_SUCCESS;
}""")}

{sub("6.3", "VERW / L1D Flush Strategy")}
<p>
<code>PerformVerwFlush()</code> is implemented in MASM (<code>asm/verw_flush.asm</code>)
because MSVC has no intrinsic for <code>VERW</code>. It is the only location in the codebase
where the <code>VERW</code> instruction appears. {cite("P4","P5","S10")}
</p>
{code("""// asm/verw_flush.asm
; PerformVerwFlush — MFENCE + VERW to clear MDS buffers
; Called on every context-switch boundary touching a tagged page
; Intel SA-00233 §4: VERW with any writable data segment  [S10]
; VERW 0x2B = user data segment selector on standard Windows x64

.CODE

PerformVerwFlush PROC
    mfence              ; Serialize prior stores  [P4]
    sub   rsp, 2
    mov   WORD PTR [rsp], 02Bh  ; User data segment selector
    verw  WORD PTR [rsp]        ; Clear CPU line/load buffers  [P5][S10]
    add   rsp, 2
    mfence
    ret
PerformVerwFlush ENDP

END""")}
{code("""// cache_mitigation.c — L1D flush for L1TF  [P3][S11]
// IA32_FLUSH_CMD MSR 0x10B — Intel SDM Vol.4 §2.1 [S1]
#define MSR_IA32_FLUSH_CMD   0x10BUL
#define FLUSH_CMD_L1D_FLUSH  0x1ULL

static FORCEINLINE VOID
PerformL1dFlush(VOID)
{
    __writemsr(MSR_IA32_FLUSH_CMD, FLUSH_CMD_L1D_FLUSH);
}

// Entry point called by context-switch callback
VOID
ScpdApplyMitigationOnContextSwitch(
    _In_ BOOLEAN TouchesSensitivePages,
    _In_ MITIGATION_STRATEGY Strategy
)
{
    if (!TouchesSensitivePages && Strategy < MIT_FULL_SPECTRUM)
        return;

    switch (Strategy) {
    case MIT_VERW_ONLY:     PerformVerwFlush();                         break;
    case MIT_L1D_FLUSH:     PerformL1dFlush();                          break;
    case MIT_VERW_AND_L1D:  PerformVerwFlush(); PerformL1dFlush();      break;
    case MIT_FULL_SPECTRUM: PerformVerwFlush(); PerformL1dFlush();
                            ScpdApplySpeculationControls(TRUE);          break;
    default:                                                             break;
    }
}""")}

{sub("6.4", "Cache Allocation Technology (CAT)")}
<p>
On processors supporting Intel CAT, Module 4 partitions the L3 cache to create an
isolated LLC region for sensitive workloads. This prevents LLC-based Flush+Reload
cross-contamination. {cite("P7","S1")}
</p>
{code("""// cache_mitigation.c — CAT / RDT setup
// Intel SDM Vol.3B §17.18 [S1]
#define MSR_PQR_ASSOC     0xC8FUL  // Class Of Service assignment
#define MSR_L3_CBMBASE    0xC90UL  // L3 capacity bit mask base (CLOS 0)
#define MSR_L3_CBMBASE_1  0xC91UL  // CLOS 1 — sensitive workloads

// Bit mask: lower half of LLC ways → normal, upper half → sensitive
// Example: 0x003FF = ways 0-9 (normal), 0xFFC00 = ways 10-19 (sensitive)
#define CAT_CBM_NORMAL     0x003FFUL
#define CAT_CBM_SENSITIVE  0xFFC00UL
#define CLOS_NORMAL        0
#define CLOS_SENSITIVE     1

static NTSTATUS
ConfigureCatPartition(VOID)
{
    // Verify CAT support: CPUID.10H.1:EAX[4:0] = CBM length
    int cpuidResult[4];
    __cpuidex(cpuidResult, 0x10, 1);
    ULONG cbmLen = (cpuidResult[0] & 0x1F) + 1;
    if (cbmLen < 10)
        return STATUS_NOT_SUPPORTED;

    __writemsr(MSR_L3_CBMBASE,   CAT_CBM_NORMAL);
    __writemsr(MSR_L3_CBMBASE_1, CAT_CBM_SENSITIVE);

    // Assign current core to sensitive CLOS when processing tagged pages
    __writemsr(MSR_PQR_ASSOC, (ULONGLONG)CLOS_SENSITIVE);

    return STATUS_SUCCESS;
}""")}

{sub("6.5", "SMT / HT Isolation")}
<p>
When a logical core processes tagged memory, its sibling hyper-thread is restricted and
an L1D flush is issued before domain transitions. This prevents cross-HT cache timing
leakage per Percival {cite("P11")} and the MDS threat model {cite("P4","P5")}.
</p>
{code("""// cache_mitigation.c — SMT sibling isolation  [P11][P4]
// IA32_SPEC_CTRL MSR 0x48 — Intel SDM Vol.4 §2.1 [S1][S9]
#define MSR_IA32_SPEC_CTRL  0x48UL
#define SPEC_CTRL_IBRS      (1ULL << 0)  // Indirect Branch Restricted Spec.
#define SPEC_CTRL_STIBP     (1ULL << 1)  // Single Thread IB Prediction  [P1]

static VOID
ScpdApplySpeculationControls(
    _In_ BOOLEAN Enable
)
{
    ULONGLONG ctrl = __readmsr(MSR_IA32_SPEC_CTRL);

    if (Enable)
        ctrl |=  (SPEC_CTRL_IBRS | SPEC_CTRL_STIBP);
    else
        ctrl &= ~(SPEC_CTRL_IBRS | SPEC_CTRL_STIBP);

    __writemsr(MSR_IA32_SPEC_CTRL, ctrl);
}""")}
</div>
"""

# ---------------------------------------------------------------------------
# Section 7 — Module 5
# ---------------------------------------------------------------------------

def build_s7():
    return f"""
<div class="section">
{pb()}
{sec(7, "Module 5 — Secure Ring 0 ↔ Ring 3 Communication")}
<p>
Module 5 provides the Ring&nbsp;3 monitor process (<code>SideChannelMonitor.exe</code>)
with a tamper-proof notification channel. The primary channel uses HMAC-authenticated
shared memory; the fallback uses MSR-based covert signaling for critical alerts when
<code>DeviceIoControl</code> dispatch may be compromised. {cite("S3","S7","S4")}
</p>

{sub("7.1", "HMAC-Authenticated Shared Memory")}
{code("""// scpd_shared.h — shared structures (kernel + user)
// IOCTL codes
#define IOCTL_SCPD_MAP_SHARED_MEM  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, \
                                     METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_SCPD_GET_HMAC_KEY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, \
                                     METHOD_BUFFERED, FILE_READ_ACCESS)

#define SHARED_RING_SIZE    256   // Power of 2

typedef struct _ALERT_ENTRY {
    LARGE_INTEGER Timestamp;        // 100-ns ticks
    ULONG         AlertLevel;       // 0=info 1=warning 2=critical
    ULONG         EventType;        // EVENT_TYPE enum
    CHAR          Details[120];     // UTF-8 message
    UCHAR         Hmac[32];         // HMAC-SHA256(key, entry sans Hmac)  [S7]
} ALERT_ENTRY, *PALERT_ENTRY;

typedef struct _SHARED_MEM_REGION {
    volatile ULONG WriteIndex;      // Producer writes; reader polls
    volatile ULONG ReadIndex;       // Reader advances
    ALERT_ENTRY    Ring[SHARED_RING_SIZE];
} SHARED_MEM_REGION, *PSHARED_MEM_REGION;""")}
{code("""// secure_comms.c — HMAC key derivation  [S3][S7][S4]
// Key is sealed by TPM 2.0 PCR policy; retrieved at driver load
// NIST SP 800-57 Pt.1 §5.3.4: 256-bit HMAC key for SHA-256  [S7]
static UCHAR g_HmacKey[32] = {0};

static NTSTATUS
DeriveHmacKeyFromTpm(VOID)
{
    // TPM2_Create with policyPCR binding (PCR 7 = Secure Boot state)  [S3]
    // Implementation uses TBS (TPM Base Services) from Ring 3 at setup time
    // and seals the key — driver retrieves via IOCTL_SCPD_GET_HMAC_KEY
    return TpmUnsealKey(g_HmacKey, sizeof(g_HmacKey));
}

VOID
WriteAlertToRing(
    _In_ ULONG  Level,
    _In_ ULONG  EventType,
    _In_ PCSTR  Details
)
{
    ULONG idx = InterlockedIncrement((LONG*)&g_SharedMem->WriteIndex)
                & (SHARED_RING_SIZE - 1);

    PALERT_ENTRY entry = &g_SharedMem->Ring[idx];
    entry->Timestamp  = KeQueryPerformanceCounter(NULL);
    entry->AlertLevel = Level;
    entry->EventType  = EventType;
    RtlStringCbCopyA(entry->Details, sizeof(entry->Details), Details);
    RtlZeroMemory(entry->Hmac, sizeof(entry->Hmac));

    // HMAC-SHA256 using BCrypt  [S7]
    ComputeHmacSha256(g_HmacKey, sizeof(g_HmacKey),
                      (PUCHAR)entry, sizeof(ALERT_ENTRY),
                      entry->Hmac);
}""")}

{sub("7.2", "MSR-Based Covert Signaling (Fallback)")}
<p>
For ultra-critical alerts (e.g., <code>.text</code> hash mismatch), a covert signal is
written to an unused MSR that the monitor polls. This channel is resistant to
<code>DeviceIoControl</code> interception.
</p>
{code("""// secure_comms.c — MSR covert channel  (fallback)
// Uses a vendor-reserved MSR range; value is HMAC-truncated alert code
#define MSR_COVERT_SIGNAL  0x400000UL  // AMD: OSVW range; unused on Intel

VOID
SendMsrCovertSignal(
    _In_ ULONG AlertCode
)
{
    // Pack alert code + 32-bit HMAC truncation into 64-bit MSR value
    ULONGLONG payload = ((ULONGLONG)AlertCode << 32) |
                         ComputeHmacTrunc32(g_HmacKey, AlertCode);
    __writemsr(MSR_COVERT_SIGNAL, payload);
}""")}

{sub("7.3", "TPM 2.0 Key Derivation")}
<p>
Session HMAC keys are derived and sealed by the TPM at first boot. PCR&nbsp;7 binds the
key to the current Secure Boot state; a change in Secure Boot policy causes unsealing to
fail and triggers fail-safe mode. {cite("S3","S7")}
</p>
</div>
"""

# ---------------------------------------------------------------------------
# Section 8 — Event Flow & Performance
# ---------------------------------------------------------------------------

def build_s8():
    return f"""
<div class="section">
{pb()}
{sec(8, "Cross-Module Event Flow & Performance")}

{sub("8.1", "Event Dispatch Table")}
{table_header("Trigger Source", "Event", "Response Module", "Action")}
{table_row("M1", "High LLC/L1D miss rate", "M4", f"Increase VERW flush frequency {cite('P7','P8')}")}
{table_row("M1", "RDTSC rate anomaly", "M5", f"Alert Ring 3 monitor {cite('P10','P12')}")}
{table_row("M2", "Unauthorized DMA device", "M4", f"Lock IOMMU context + flush {cite('S13')}")}
{table_row("M2", "IOMMU disabled", "M5", f"Critical alert; optional fail-safe {cite('S11')}")}
{table_row("M3", "IDT keyboard hook", "M4", f"Full-spectrum flush + core isolation {cite('P2')}")}
{table_row("M3", ".text hash mismatch", "M4+M5", f"Maximum mitigations + covert MSR alert {cite('S3')}")}
{table_row("M3", "Dispatch routine detour", "M5", f"Critical alert {cite('P1')}")}
{table_row("M4", "Shared state corruption", "M4", f"Apply maximum mitigations immediately")}
{table_end()}

{sub("8.2", "IRQL Constraints Summary")}
{table_header("IRQL", "Allowable Operations", "Prohibited")}
{table_row('<span class="irql-high">HIGH_LEVEL</span>', "MSR reads/writes, non-paged ring buffer writes, IoRequestDpc", "Any kernel API, spin locks, paged memory")}
{table_row('<span class="irql-disp">DISPATCH_LEVEL</span>', "Spin lock acquire/release, non-paged pool, DPC body", "Paged memory, blocking calls, BCrypt")}
{table_row('<span class="irql-pass">PASSIVE_LEVEL</span>', "Full kernel API, BCrypt, MmMapIoSpace, IoGetDeviceProperty", "—")}
{table_end()}

{sub("8.3", "Performance Targets")}
{table_header("Scenario", "Target Overhead", "Dominating Cost")}
{table_row("No active attack", "< 0.1 %", "PMU polling DPC")}
{table_row("MDS mitigation only (VERW)", "~50 ns / context switch", f"VERW + MFENCE {cite('P4')}")}
{table_row("MDS + L1TF (VERW + L1D flush)", "~250 ns / context switch", f"IA32_FLUSH_CMD {cite('P3','S11')}")}
{table_row("SMT isolation enabled", "5–15 % throughput reduction", f"Sibling-core stall + L1D flush {cite('P11')}")}
{table_row("Full-spectrum (fail-safe)", "~800 ns / context switch", "IBRS + STIBP + both flushes")}
{table_end()}
</div>
"""

# ---------------------------------------------------------------------------
# Section 9 — Literature Foundation (NEW)
# ---------------------------------------------------------------------------

def build_s9():
    return f"""
<div class="section">
{pb()}
{sec(9, "Literature Foundation")} {new_badge()}
<p>
This section catalogs the bibliographic sources that underpin the driver's design decisions,
threat model, and implementation choices. All implementation decisions should be traceable to
at least one entry in this section. Sources are grouped by type following the taxonomy in
<em>Principles of Working with Literature Documents</em>, §1.
</p>

{sub("9.1", "Textbooks and Monographs")}

<div class="ref-header">Operating Systems &amp; Kernel Internals</div>
<div class="ref-group">
{table_header("#", "Title", "Author(s)", "Ed.", "Publisher / Year", "ISBN-13")}
{table_row("[1]", "<em>Windows Internals, Part 1</em>", "Russinovich, M.; Solomon, D.; Ionescu, A.; Yosifovich, P.", "7th", "Microsoft Press, 2017", "978-0-7356-8418-7")}
{table_row("[2]", "<em>Windows Internals, Part 2</em>", "Yosifovich, P.; Russinovich, M.; Solomon, D.; Ionescu, A.", "7th", "Microsoft Press, 2022", "978-0-13-530285-1")}
{table_row("[3]", "<em>Modern Operating Systems</em>", "Tanenbaum, A. S.; Bos, H.", "4th", "Pearson, 2014", "978-0-13-359162-0")}
{table_row("[4]", "<em>Rootkits: Subverting the Windows Kernel</em>", "Hoglund, G.; Butler, J.", "1st", "Addison-Wesley, 2005", "978-0-321-29431-9")}
{table_row("[5]", "<em>Rootkits and Bootkits</em>", "Matrosov, A.; Rodionov, E.; Bratus, S.", "1st", "No Starch Press, 2019", "978-1-59327-716-1")}
{table_row("[6]", "<em>The Art of Memory Forensics</em>", "Ligh, M. H.; Case, A.; Levy, J.; Walters, A.", "1st", "Wiley, 2014", "978-1-118-82545-6")}
{table_row("[7]", "<em>Practical Malware Analysis</em>", "Sikorski, M.; Honig, A.", "1st", "No Starch Press, 2012", "978-1-59327-290-6")}
{table_end()}

<div class="ref-header">Computer Architecture &amp; Microarchitecture</div>
<div class="ref-group">
{table_header("#", "Title", "Author(s)", "Ed.", "Publisher / Year", "ISBN-13")}
{table_row("[8]", "<em>Computer Architecture: A Quantitative Approach</em>", "Hennessy, J. L.; Patterson, D. A.", "6th", "Morgan Kaufmann, 2017", "978-0-12-811905-1")}
{table_row("[9]", "<em>Computer Organization and Design (RISC-V ed.)</em>", "Patterson, D. A.; Hennessy, J. L.", "2nd", "Morgan Kaufmann, 2020", "978-0-12-820331-6")}
{table_row("[10]", "<em>Introduction to Hardware Security and Trust</em>", "Tehranipoor, M.; Wang, C. (Eds.)", "1st", "Springer, 2012", "978-1-4419-8079-3")}
{table_end()}

<div class="ref-header">Cryptography &amp; Applied Security</div>
<div class="ref-group">
{table_header("#", "Title", "Author(s)", "Ed.", "Publisher / Year", "ISBN-13")}
{table_row("[11]", "<em>Applied Cryptography</em>", "Schneier, B.", "2nd", "Wiley, 1996", "978-0-471-11709-4")}
{table_row("[12]", "<em>Introduction to Modern Cryptography</em>", "Katz, J.; Lindell, Y.", "3rd", "CRC Press, 2020", "978-0-8153-8602-8")}
{table_row("[13]", "<em>A Practical Guide to TPM 2.0</em>", "Arthur, W.; Challener, D.; Goldman, K.", "1st", "Apress, 2015", "978-1-4302-6583-9")}
{table_end()}

<div class="ref-header">Secure Coding &amp; Systems Security</div>
<div class="ref-group">
{table_header("#", "Title", "Author(s)", "Ed.", "Publisher / Year", "ISBN-13")}
{table_row("[14]", "<em>Writing Secure Code</em>", "Howard, M.; LeBlanc, D.", "2nd", "Microsoft Press, 2002", "978-0-7356-1722-3")}
{table_row("[15]", "<em>Secure Coding in C and C++</em>", "Seacord, R. C.", "2nd", "Addison-Wesley, 2013", "978-0-321-82213-0")}
{table_row("[16]", "<em>Computer Security: Art and Science</em>", "Bishop, M.", "2nd", "Pearson, 2018", "978-0-321-71233-2")}
{table_row("[17]", "<em>Hacking: The Art of Exploitation</em>", "Erickson, J.", "2nd", "No Starch Press, 2008", "978-1-59327-144-2")}
{table_row("[18]", "<em>The Shellcoder's Handbook</em>", "Anley, C.; Heasman, J.; Lindner, F.; Richarte, G.", "2nd", "Wiley, 2007", "978-0-470-08023-8")}
{table_end()}
</div>

{sub("9.2", "Selected Academic Papers")}

<div class="ref-header">Speculative Execution Side-Channel Attacks</div>
<div class="ref-group">
<div class="ref-block">[P1] Kocher, P. et al. (2019).
     "Spectre Attacks: Exploiting Speculative Execution."
     2019 IEEE Symposium on Security and Privacy (S&P), pp. 1-19.
     DOI: 10.1109/SP.2019.00002
     Relevance: M1 (PMU anomaly detection), M4 (LFENCE barriers, IBRS/STIBP via IA32_SPEC_CTRL)</div>
<div class="ref-block">[P2] Lipp, M. et al. (2018).
     "Meltdown: Reading Kernel Memory from User Space."
     27th USENIX Security Symposium, pp. 973-990.
     URL: https://www.usenix.org/conference/usenixsecurity18/presentation/lipp
     Relevance: M3 (kernel integrity verification), M4 (KPTI-style sensitive page isolation)</div>
<div class="ref-block">[P3] Van Bulck, J. et al. (2018).
     "Foreshadow: Extracting the Keys to the Intel SGX Kingdom with
     Transient Out-of-Order Execution."
     27th USENIX Security Symposium, pp. 991-1008.
     URL: https://www.usenix.org/conference/usenixsecurity18/presentation/bulck
     Relevance: M4 (L1TF mitigation — IA32_FLUSH_CMD MSR 0x10B)</div>
</div>

<div class="ref-header">Microarchitectural Data Sampling (MDS)</div>
<div class="ref-group">
<div class="ref-block">[P4] Van Schaik, S. et al. (2019).
     "RIDL: Rogue In-flight Data Load."
     2019 IEEE Symposium on Security and Privacy (S&P), pp. 88-105.
     DOI: 10.1109/SP.2019.00087
     Relevance: M4 (VERW buffer flush, MDS mitigation strategy selection)</div>
<div class="ref-block">[P5] Schwarz, M. et al. (2019).
     "ZombieLoad: Cross-Privilege-Boundary Data Sampling."
     ACM CCS 2019, pp. 753-768.
     DOI: 10.1145/3319535.3354252
     Relevance: M4 (MDS_NO capability flag interpretation, VERW effectiveness)</div>
<div class="ref-block">[P6] Canella, C. et al. (2019).
     "A Systematic Evaluation of Transient Execution Attacks and Defenses."
     28th USENIX Security Symposium, pp. 249-266.
     URL: https://www.usenix.org/conference/usenixsecurity19/presentation/canella
     Relevance: Comprehensive taxonomy; informs M4 mitigation selection logic</div>
</div>

<div class="ref-header">Cache-Timing Attacks</div>
<div class="ref-group">
<div class="ref-block">[P7] Yarom, Y.; Falkner, K. (2014).
     "FLUSH+RELOAD: A High Resolution, Low Noise, L3 Cache Side-Channel Attack."
     23rd USENIX Security Symposium, pp. 719-732.
     URL: https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/yarom
     Relevance: M1 (LLC miss rate detection threshold calibration)</div>
<div class="ref-block">[P8] Gruss, D.; Maurice, C.; Wagner, K.; Mangard, S. (2016).
     "Flush+Flush: A Fast and Stealthy Cache Attack."
     DIMVA 2016, LNCS 9721, pp. 279-299.
     DOI: 10.1007/978-3-319-40667-1_14
     Relevance: M1 (detection of low-noise, stealthy timing variants)</div>
<div class="ref-block">[P9] Osvik, D. A.; Shamir, A.; Tromer, E. (2006).
     "Cache Attacks and Countermeasures: The Case of AES."
     RSA Conference 2006 (CT-RSA), LNCS 3860, pp. 1-20.
     DOI: 10.1007/11605805_1
     Relevance: M1 (L1D miss patterns as attack signal)</div>
<div class="ref-block">[P10] Bernstein, D. J. (2005).
      "Cache-timing attacks on AES." Technical report.
      URL: https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
      Relevance: M1 (baseline for RDTSC-rate anomaly thresholds)</div>
<div class="ref-block">[P11] Percival, C. (2005).
      "Cache Missing for Fun and Profit." BSDCan 2005.
      URL: https://www.daemonology.net/papers/htt.pdf
      Relevance: M4 (SMT/HT sibling core cross-contamination model)</div>
</div>

<div class="ref-header">Timing Attacks (Classical)</div>
<div class="ref-group">
<div class="ref-block">[P12] Kocher, P. C. (1996).
      "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems."
      CRYPTO 1996, LNCS 1109, pp. 104-113.
      DOI: 10.1007/3-540-68697-5_9
      Relevance: M3 (constant-time comparison requirement for SHA-256 hash checks)</div>
</div>

<div class="ref-header">Survey / Countermeasure Overview</div>
<div class="ref-group">
<div class="ref-block">[P13] Ge, Q.; Yarom, Y.; Cock, D.; Heiser, G. (2018).
      "A Survey of Microarchitectural Timing Attacks and Countermeasures
      on Contemporary Hardware."
      Journal of Cryptographic Engineering, 8(1), pp. 1-27.
      DOI: 10.1007/s13389-016-0141-6
      Relevance: Breadth reference; maps attack families to mitigations for threat model</div>
<div class="ref-block">[P14] Lipp, M. et al. (2020).
      "Take A Way: Exploring the Security Implications of AMD's Cache Way Predictors."
      ACM ASIACCS 2020, pp. 813-825.
      DOI: 10.1145/3320269.3384746
      Relevance: M1 (AMD-specific PMU event selection differences from Intel)</div>
</div>

{sub("9.3", "Standards, Specifications, and Technical Reports")}

<div class="ref-header">CPU Architecture</div>
<div class="ref-group">
<div class="ref-block">[S1] Intel Corporation.
     "Intel 64 and IA-32 Architectures Software Developer's Manual"
     Combined Volumes 1-4. (Continuously revised.)
     Key volumes: Vol. 3A — System Programming; Vol. 4 — MSR Reference.
     URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
     Internal alias: Intel SDM</div>
<div class="ref-block">[S2] AMD.
     "AMD64 Architecture Programmer's Manual" Volumes 1-5. (Continuously revised.)
     Vol. 2: System Programming; Vol. 3: General-Purpose and System Instructions.
     URL: https://www.amd.com/en/support/tech-docs
     Internal alias: AMD APM</div>
</div>

<div class="ref-header">Trusted Platform Module</div>
<div class="ref-group">
<div class="ref-block">[S3] Trusted Computing Group.
     "TPM Library Specification, Family 2.0" Parts 1-4. Revision 01.59, 2019.
     URL: https://trustedcomputinggroup.org/resource/tpm-library-specification/</div>
</div>

<div class="ref-header">NIST Special Publications</div>
<div class="ref-group">
<div class="ref-block">[S4] Chen, L. et al. (NIST). SP 800-90A Rev.1:
     "Recommendation for Random Number Generation Using Deterministic Random Bit Generators."
     NIST, 2015.  DOI: 10.6028/NIST.SP.800-90Ar1</div>
<div class="ref-block">[S5] Cooper, D. A. et al. (NIST). SP 800-147:
     "BIOS Protection Guidelines."
     NIST, 2011.  DOI: 10.6028/NIST.SP.800-147</div>
<div class="ref-block">[S6] Polk, T.; Regenscheid, A. (NIST). SP 800-155 (Draft):
     "BIOS Integrity Measurement Guidelines."
     NIST, 2011.  URL: https://csrc.nist.gov/publications/detail/sp/800-155/draft</div>
<div class="ref-block">[S7] Barker, E. (NIST). SP 800-57 Part 1 Rev.5:
     "Recommendation for Key Management."
     NIST, 2020.  DOI: 10.6028/NIST.SP.800-57pt1r5</div>
</div>

<div class="ref-header">Vendor Security Advisories</div>
<div class="ref-group">
<div class="ref-block">[S8] Intel Product Security Center. SA-00075 (INTEL-SA-00075):
     "Intel Active Management Technology Escalation of Privilege."
     Intel, 2017.</div>
<div class="ref-block">[S9] Intel Product Security Center. SA-00088 (INTEL-SA-00088):
     "Speculative Execution and Indirect Branch Prediction Side Channel Analysis Method."
     Intel, 2018.
     Relevance: M4 (IBRS/STIBP/IBPB selection via IA32_SPEC_CTRL)</div>
<div class="ref-block">[S10] Intel Product Security Center. SA-00233 (INTEL-SA-00233):
      "Microarchitectural Data Sampling Advisory."
      Intel, 2019.
      Relevance: M4 (VERW mitigation, MDS_NO flag, IA32_ARCH_CAPABILITIES bit 5)</div>
<div class="ref-block">[S11] Intel Product Security Center. SA-00161 (INTEL-SA-00161):
      "L1 Terminal Fault / Foreshadow Advisory."
      Intel, 2018.
      Relevance: M4 (L1TF_NO flag, IA32_FLUSH_CMD MSR 0x10B)</div>
<div class="ref-block">[S12] Microsoft Security Response Center (MSRC).
      "ADV180002: Guidance to mitigate speculative execution side-channel vulnerabilities."
      Microsoft, 2018. (Updated continuously.)
      Relevance: M3, M4 (Windows-level mitigation interactions)</div>
</div>

<div class="ref-header">Bus and I/O Specifications</div>
<div class="ref-group">
<div class="ref-block">[S13] PCI-SIG.
      "PCI Express Base Specification Revision 5.0."
      PCI-SIG, 2019.
      Relevance: M2 (ECAM base address formula, configuration space layout)</div>
<div class="ref-block">[S14] PCI-SIG.
      "PCI Bus Power Management Interface Specification Revision 1.2."
      PCI-SIG, 2004.
      Relevance: M2 (device capability registers)</div>
</div>

{sub("9.4", "Courses and Lecture Series")}
<div class="ref-group">
<div class="ref-block">[L1] MIT OpenCourseWare — 6.858 Computer Systems Security
     Instructors: Frans Kaashoek, Nickolai Zeldovich (MIT CSAIL)
     URL: https://ocw.mit.edu/courses/6-858-computer-systems-security-fall-2014/
     Relevance: Threat modelling methodology, kernel security, privilege separation</div>
<div class="ref-block">[L2] Stanford CS 155 — Computer and Network Security
     Instructors: Dan Boneh, John Mitchell (Stanford University)
     URL: https://cs155.stanford.edu/
     Relevance: Side-channel fundamentals, memory safety, hardware security</div>
<div class="ref-block">[L3] CMU 15-410 / 15-605 — Operating System Design and Implementation
     Instructors: David Eckhardt, Dave O'Hallaron (CMU)
     URL: https://www.cs.cmu.edu/~410/
     Relevance: Kernel scheduler, IRQL/interrupt analogue, synchronisation primitives</div>
<div class="ref-block">[L4] USENIX Security Training — "Microarchitectural Side Channels"
     Presenters: Yuval Yarom et al., USENIX Security 2019/2020
     URL: https://www.usenix.org/conference/usenixsecurity19
     Relevance: M1 attack primitives, PMU usage, flush-based defences</div>
<div class="ref-block">[L5] Intel Developer Zone — Performance Monitoring Unit (PMU) Tutorial Series
     Authors: Intel Architecture Performance Monitoring Team
     URL: https://www.intel.com/content/www/us/en/developer/topic-technology/software-optimization-notice.html
     Relevance: M1 (IA32_PERFEVTSEL encoding, PMI delivery, PEBS)</div>
<div class="ref-block">[L6] Microsoft Learn — Windows Driver Development Documentation
     Authors: Microsoft WDK Team
     URL: https://learn.microsoft.com/windows-hardware/drivers/
     Relevance: All modules (WDM/KMDF conventions, IRQL rules, MDL handling)</div>
<div class="ref-block">[L7] Daira Hopwood — "Applied Cryptographic Hardware" (Real World Crypto, 2020)
     URL: https://rwc.iacr.org/2020/
     Relevance: TPM integration, hardware random number generation (M5)</div>
</div>
</div>
"""

# ---------------------------------------------------------------------------
# Section 10 — Literature Map (NEW)
# ---------------------------------------------------------------------------

def build_s10():
    return f"""
<div class="section">
{pb()}
{sec(10, "Literature Map")} {new_badge()}
<p>
The table below maps each driver module to its authoritative and secondary literature sources.
Consult this table before making any implementation decision to identify the correct reference.
Numbers in square brackets refer to textbooks in §9.1; letter codes to papers [P1–P14],
standards [S1–S14], and courses [L1–L7] in §9.2–9.4.
</p>
{table_header("Driver Module", "Primary Sources", "Secondary Sources")}
{table_row("<strong>M1</strong> — PMU / Cache Detection", "S1 (SDM Vol.4), S2 (AMD APM Vol.3), P7, P8, P9, P10, L5", "P13, P6")}
{table_row("<strong>M2</strong> — PCIe / IOMMU", "S13, S14, S1 (SDM Vol.3A §29)", "S12")}
{table_row("<strong>M3</strong> — Kernel Integrity", "P1, P2, S12 (MSRC ADV180002), S5, S6", "[1], [4], [5]")}
{table_row("<strong>M4</strong> — Cache Mitigation", "S10, S11, P4, P5, P3, S1 (SDM Vol.4 §2.1), P11", "P6, P13")}
{table_row("<strong>M5</strong> — Secure Comms / TPM", "S3, S7, S4, [13], L7", "[11], [12]")}
{table_row("<strong>Threat model</strong>", "P1–P6, P13, L1, L2", "P7–P12")}
{table_row("<strong>Patent prior art</strong>", "P1–P14, S1–S14", "[1]–[18]")}
{table_end()}

<p>
Mark sources as <strong>SUPERSEDED</strong> in <code>literature/INDEX.md</code> when a newer
revision is published. Never delete superseded sources — they are part of the patent
prosecution history.
</p>
</div>
"""

# ---------------------------------------------------------------------------
# Appendix A — Threat Model Maintenance (NEW)
# ---------------------------------------------------------------------------

def build_appA():
    return f"""
<div class="section">
{pb()}
{sec("A", "Appendix A — Threat Model Maintenance")} {new_badge()}
<p>
Literature is the primary input to the threat model. Every new paper or advisory should be
evaluated against the current threat model using the following three-question framework.
</p>

{sub("A.1", "Evaluation Framework")}

<p><strong>1. Does this attack fall within the current threat model?</strong></p>
{table_header("Answer", "Required Action")}
{table_row("Yes, and the driver mitigates it", "Update test coverage to include the specific attack variant")}
{table_row("Yes, but the driver does not mitigate it", "Open a gap item; assign to the owning module")}
{table_row("No", "Document the scoping decision explicitly in literature/INDEX.md")}
{table_end()}

<p><strong>2. Does this attack require revising assumptions?</strong></p>
<p>
Example: A new attack that works across physical cores invalidates any assumption that
physical core isolation is a complete defense. In that case, the SMT isolation logic in
Module 4 must be re-evaluated.
</p>

<p><strong>3. Does this attack suggest new detection signals?</strong></p>
<p>
Example: a new timing pattern measurable by the PMU → add a PMU event counter definition
to <code>pmu_detection.c</code> and update the threshold table in §3.2.
</p>

{sub("A.2", "Source Versioning and Staleness")}
{table_header("Trigger", "Required Action")}
{table_row("New Intel/AMD microarchitecture released", "Re-read SDM Vol.4, check new CPUID leaves and MSRs")}
{table_row("New CVE in the Spectre/MDS/LVI family", "Read the advisory and research paper before the 90-day embargo lifts")}
{table_row("WDK version update", "Re-read affected API documentation for behavioral changes")}
{table_row("Patent application filed by a competitor", "Read the published application within 30 days")}
{table_row("Pre-existing source superseded by a new revision", "Update all extraction notes that cite the old revision")}
{table_end()}

{sub("A.3", "Reading Workflow Summary")}
{code("""1. Classify the document (type taxonomy: arch spec, paper, advisory…)
2. Apply the correct read order for that type
3. Produce an extraction note in literature/ using the template:
     ## [Document Title]
     Source: [Full citation with revision/date]
     Read date: YYYY-MM-DD
     Relevance: [Which module(s)]
     ### Key Facts  — specific, citable facts
     ### Open Questions
     ### Action Items
     ### Conflicts with Other Sources
4. Link the extraction to any affected source files (code comments)
5. Update literature/INDEX.md
6. Evaluate against threat model (this appendix)
7. Run prior art analysis if novel (Appendix B)
8. Schedule a re-read trigger if source has a TTL""")}
</div>
"""

# ---------------------------------------------------------------------------
# Appendix B — Prior Art Analysis (NEW)
# ---------------------------------------------------------------------------

def build_appB():
    return f"""
<div class="section">
{pb()}
{sec("B", "Appendix B — Prior Art Analysis")} {new_badge()}
<p>
A patent claim is only as strong as its prior art search. This appendix defines the
four-step procedure for constructing a prior art map before drafting any novel claim.
</p>

{sub("B.1", "Step 1 — Keyword Search")}
<p>Search USPTO Full-Text, Google Patents, and Espacenet using:</p>
{ul(
    "Technical terms: \"microarchitectural buffer flush\", \"cache allocation technology\", \"performance monitoring unit anomaly detection\"",
    "Problem-space terms: \"side channel attack\", \"hardware keylogger detection\", \"kernel integrity verification\"",
    "Inventor-space terms: search key researchers in the field (Kocher, Yarom, Van Bulck, etc.)",
)}

{sub("B.2", "Step 2 — CPC Classification Search")}
{table_header("CPC Code", "Scope")}
{table_row("G06F 21/57", "Certifying or maintaining trusted computer platforms")}
{table_row("G06F 21/55", "Detecting local intrusion or implementing counter-measures")}
{table_row("G06F 21/75", "Protecting specific internal or peripheral components")}
{table_row("H04L 9/06", "Cryptographic mechanisms using block ciphers")}
{table_end()}

{sub("B.3", "Step 3 — Claim Chart Construction")}
<p>
For each novel technique, map it to the closest prior art. Example claim chart for the
adaptive mitigation strategy:
</p>
{code("""Claim: Adaptive mitigation strategy selected from CPU capability probing

| Claim Element          | Implementation                      | Closest Prior Art               | Gap                                    |
|------------------------|-------------------------------------|---------------------------------|----------------------------------------|
| Runtime CPU capability | ProbeCpuCapabilities() reading      | Intel SA-00233 (software guide, | Driver-level adaptive selection        |
| probing                | IA32_ARCH_CAPABILITIES (MSR 0x10A)  | not a driver claim)             | is not claimed in SA-00233             |
| Cheapest safe strategy | MITIGATION_STRATEGY enum selection  | —                               | Novel combination at driver level      |
| Per-CPU strategy state | g_CpuMit[MAXIMUM_PROCESSORS]        | —                               | Novel per-core granularity in Ring 0   |""")}

{sub("B.4", "Step 4 — Claim Status Classification")}
{table_header("Status", "Meaning", "Action")}
{table_row("<strong>Novel</strong>", "No prior art found for this element", "Potential independent claim element")}
{table_row("<strong>Anticipated</strong>", "Prior art fully discloses this element", "Do not claim; cite the prior art")}
{table_row("<strong>Obvious</strong>", "Combination of prior art renders it obvious", "Weak claim; add evidence of non-obviousness")}
{table_row("<strong>Design-around</strong>", "Existing patent covers this approach", "Implement differently to avoid infringement")}
{table_end()}

{sub("B.5", "Identifying the Inventive Step")}
<p>
The inventive step is not the individual components — it is the <em>combination</em> and
the specific problem it solves. Document:
</p>
{ul(
    "What problem the prior art fails to solve",
    "How your specific combination solves it",
    "Why the combination is non-obvious (why someone skilled in the art would not arrive at it without your contribution)",
)}
<p>
Cross-reference this analysis with the module-to-literature map in §10 to ensure all
relevant prior art is accounted for before filing.
</p>
</div>
"""

# ---------------------------------------------------------------------------
# Assemble full HTML
# ---------------------------------------------------------------------------

def build_html():
    parts = [
        f'<!DOCTYPE html><html lang="en"><head>',
        f'<meta charset="UTF-8">',
        f'<meta name="viewport" content="width=device-width,initial-scale=1">',
        f'<title>SideChannelKernelPreventor Driver Architecture v1.1</title>',
        f'<style>{CSS}</style>',
        f'</head><body>',
        build_cover(),
        build_toc(),
        build_s1(),
        build_s2(),
        build_s3(),
        build_s4(),
        build_s5(),
        build_s6(),
        build_s7(),
        build_s8(),
        build_s9(),
        build_s10(),
        build_appA(),
        build_appB(),
        f'</body></html>',
    ]
    return ''.join(parts)

# ---------------------------------------------------------------------------
# Write HTML + convert to PDF via Edge headless
# ---------------------------------------------------------------------------

def main():
    print("Building HTML...", flush=True)
    html_content = build_html()

    with open(HTMP, 'w', encoding='utf-8') as f:
        f.write(html_content)
    print(f"  HTML written: {HTMP}  ({len(html_content):,} chars)", flush=True)

    print("Converting to PDF via Edge headless...", flush=True)
    file_url = 'file:///' + HTMP.replace('\\', '/').replace(' ', '%20')

    cmd = [
        EDGE,
        '--headless=new',
        '--disable-gpu',
        '--no-sandbox',
        '--run-all-compositor-stages-before-draw',
        f'--print-to-pdf={PDFO}',
        '--print-to-pdf-no-header',
        file_url,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    if result.returncode != 0:
        print(f"Edge stderr: {result.stderr[:800]}", flush=True)
        print(f"Edge stdout: {result.stdout[:400]}", flush=True)
        sys.exit(1)

    if os.path.exists(PDFO):
        size = os.path.getsize(PDFO)
        print(f"  PDF written: {PDFO}  ({size:,} bytes / {size//1024} KB)", flush=True)
        print("Done.", flush=True)
    else:
        print(f"ERROR: PDF not found at {PDFO}", flush=True)
        print(f"Edge stdout: {result.stdout[:600]}", flush=True)
        print(f"Edge stderr: {result.stderr[:600]}", flush=True)
        sys.exit(1)

if __name__ == '__main__':
    main()
