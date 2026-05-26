# Principles of Working with Literature Documents

A methodology for reading, extracting, mapping, and applying technical literature
in security-systems research and kernel-driver development.

---

## 1. Document Taxonomy

Not all literature is read the same way. Classify every document before opening it.

| Type | Examples | Primary Goal |
|------|----------|--------------|
| **Architecture specification** | Intel SDM, AMD APM, ACPI spec, PCIe spec | Extract precise register offsets, bit layouts, behavioral guarantees |
| **Security research paper** | Spectre, Meltdown, MDS, Flush+Reload | Understand attack primitives, reproduce threat model |
| **Journal paper** | IEEE S&P, ACM TISSEC, Elsevier Computers & Security | Authoritative long-form results; treated as durable prior art |
| **Conference paper** | USENIX Security, CCS, NDSS, IEEE S&P (conf.) | State-of-the-art advances; peer-reviewed but compressed |
| **Workshop / short paper** | WOOT, RAID, DRAMSec | Early-stage or narrow results; verify independently before relying on |
| **Preprint** | arXiv cs.CR, IACR ePrint | Unreviewed; treat as a signal to watch, not as settled fact |
| **Textbook** | Tanenbaum *Modern OS*, Russinovich *Windows Internals* | Deep conceptual grounding; long shelf life |
| **Monograph / thesis** | PhD dissertations, NIST IR reports | Single-topic depth; often the most complete treatment of a narrow area |
| **Patent document** | USPTO, EPO filings | Map prior art boundaries, identify claim gaps |
| **Standards document** | NIST SP 800-x, ISO/IEC, IETF RFC | Extract compliance obligations and recommended parameters |
| **Vendor advisory** | Intel SA-*, AMD-SB-*, MSRC | Extract CVE scope, affected microarchitectures, recommended mitigations |

---

## 2. Reading Strategy by Document Type

### 2.1 Architecture Specifications

**Read order:** Table of Contents → Index → Target section → Referenced sections recursively.

Never read linearly. Specifications are reference material, not narratives.

**What to extract:**

- Register addresses and their exact bit-field layout
- CPUID leaf and sub-leaf that gates a feature
- Behavioral preconditions (e.g., "only valid when CR4.SMEP=1")
- Errata — check the processor-specific errata document for every MSR you write

**Annotation discipline:**

Record the exact **volume**, **chapter**, **section number**, and **revision** for every
extracted fact. Intel SDM is revised frequently; a section number without a revision
is ambiguous.

```
IA32_ARCH_CAPABILITIES [MSR 0x10A]
Source: Intel SDM Vol.4 §2.1, Table 2-2 — Revision 083 (May 2024)
Bit 5 (MDS_NO): 1 = processor not affected by MDS
```

**Cross-check:** For any MSR or CPUID leaf, verify independently against the AMD APM
to understand whether your code needs an AMD-specific path.

---

### 2.2 Security Research Papers

**Read order:** Abstract → Conclusion → Threat model section → Technical attack section → Evaluation → Related work.

Reading related work before the attack section contaminates your understanding with
the authors' framing. Read it last to identify prior art claims.

**What to extract per paper:**

1. **Threat model** — exact attacker capability assumptions (same physical core,
   same logical core, cross-VM, co-located, etc.)
2. **Attack primitive** — the specific microarchitectural behavior being exploited
3. **Observable signal** — what the attacker measures (timing delta, cache state,
   branch predictor state)
4. **Required preconditions** — what must be true in the victim environment
5. **Proposed defenses** — and their stated limitations
6. **Measurement methodology** — how they validated the attack, on which CPUs

**Red flags to watch:**

- Papers that only validate on a single microarchitecture generation are not
  portable claims. Note the exact CPU model (codename, stepping) used.
- Attack latency numbers are environment-specific. Do not use paper latency
  figures as thresholds in production code without re-measuring on your target
  hardware.

---

### 2.3 Patent Documents

**Read order:** Claims (independent claims first) → Abstract → Figures → Detailed description.

The claims are the legal scope. The description is only relevant for claim construction.

**What to extract:**

- **Independent claims** — the broadest protection; each element is a limitation
- **Dependent claims** — narrow the independent claim; show preferred embodiments
- **Priority date** — determines prior art cutoff
- **Cited references** — what the examiner accepted as prior art

**Prior art analysis procedure:**

For each independent claim, decompose it into its elements. Then for each element,
determine whether your implementation is:

| Status | Meaning |
|--------|---------|
| **Novel** | No prior art found — potential claim for your patent |
| **Anticipated** | Prior art fully discloses this element — do not claim |
| **Obvious** | Combination of prior art renders it obvious — weak claim |
| **Design-around** | You must implement differently to avoid infringement |

Document this as a claim chart — one row per element, with citation to your code
and to any prior art.

---

### 2.4 Vendor Security Advisories

**Read immediately on release.** Do not queue.

**What to extract:**

- Affected CPU models (microarchitecture family, stepping range)
- Affected software conditions (OS version, hypervisor type, SMT enabled/disabled)
- Recommended mitigation (microcode update, software workaround, or both)
- Whether the mitigation is a performance regression and its measured cost
- Whether existing code paths already implement the mitigation or require changes

---

## 3. Active Reading and Annotation

Passive reading produces no lasting knowledge. Every reading session must produce
a structured artifact.

### 3.1 The Extraction Template

For every document read, produce an extraction note with this structure:

```markdown
## [Document Title]

**Source:** [Full citation with revision/date]
**Read date:** YYYY-MM-DD
**Relevance:** [Which module(s) of the driver this affects]

### Key Facts
- [Specific, citable fact with page/section reference]
- ...

### Open Questions
- [Something the document does not answer that you need to resolve]

### Action Items
- [ ] [Specific code change, investigation, or follow-up reading]

### Conflicts with Other Sources
- [Any contradiction with another document, and which source takes precedence]
```

Store these extractions in a `literature/` directory, one file per document.

---

### 3.2 Cross-Reference Discipline

When a fact from literature is used in code, the connection must be traceable in
both directions.

**In code:** Add a single-line comment citing the source only when the behavior
would be non-obvious without it — for example, an IRQL constraint, a bit mask
derived from a spec, or a workaround for a specific errata.

```c
// Intel SDM Vol.4 §2.1 Rev.083: MDS_NO (bit 5) means VERW is not required.
if (archCap & ARCH_CAP_MDS_NO)
    mit->Features |= CPU_FEAT_MDS_NO;
```

**In the extraction note:** Record which source file and function consumed this fact.
This allows you to find every code site that depends on a given source when that
source is superseded.

---

## 4. Building a Literature Map

As the body of literature grows, maintain a `literature/INDEX.md` that maps each
document to the driver modules it informs.

```markdown
| Document | Modules | Key Contribution | Supersedes |
|----------|---------|-----------------|------------|
| Intel SDM Vol.4 Rev.083 | M1, M4 | MSR addresses, ARCH_CAPABILITIES bits | Rev.082 |
| Lipp et al., "Meltdown" (USENIX Sec 2018) | M3, M4 | L1TF attack primitive | — |
| Van Schaik et al., "RIDL" (S&P 2019) | M1, M4 | MDS attack family, VERW defense | — |
| Intel SA-00233 | M4 | MDS software mitigation guide | — |
| US10437990B2 | M4 | Prior art: cache partitioning for isolation | — |
```

This index is the authoritative source of what literature the system is built on —
essential for patent prosecution and security audits.

---

## 5. Threat Model Maintenance

Literature is the primary input to the threat model. Every new paper or advisory
should be evaluated against the current threat model:

1. **Does this attack fall within the current threat model?**
   - Yes, and the driver mitigates it → update test coverage to include it
   - Yes, but the driver does not mitigate it → open a gap item
   - No → document the scoping decision explicitly

2. **Does this attack require revising assumptions?**
   - Example: a new attack that works across physical cores invalidates any
     assumption that physical core isolation is a complete defense

3. **Does this attack suggest new detection signals?**
   - Example: a new timing pattern measurable by the PMU → add a PMU event counter

---

## 6. Prior Art Mapping for Patent Claims

A patent claim is only as strong as your prior art search. Before drafting any claim:

### Step 1 — Keyword search

Search USPTO Full-Text, Google Patents, and Espacenet using:

- Technical terms from your implementation (e.g., "microarchitectural buffer flush",
  "cache allocation technology", "performance monitoring unit anomaly detection")
- Problem-space terms (e.g., "side channel attack", "hardware keylogger detection",
  "kernel integrity verification")
- Inventor-space terms (search key researchers in the field)

### Step 2 — Classification search

Identify relevant CPC (Cooperative Patent Classification) codes:

| CPC Code | Scope |
|----------|-------|
| G06F 21/57 | Certifying or maintaining trusted computer platforms |
| G06F 21/55 | Detecting local intrusion or implementing counter-measures |
| G06F 21/75 | Protecting specific internal or peripheral components |
| H04L 9/06 | Cryptographic mechanisms using block ciphers |

### Step 3 — Claim chart construction

Map each of your novel techniques to the closest prior art found:

```markdown
## Claim: Adaptive mitigation strategy selected from CPU capability probing

| Claim Element | Your Implementation | Closest Prior Art | Gap |
|---------------|--------------------|--------------------|-----|
| Runtime CPU capability probing | ProbeCpuCapabilities() reading IA32_ARCH_CAPABILITIES | Intel SA-00233 (software guide, not a driver claim) | Driver-level adaptive selection is not claimed |
| Selecting cheapest safe strategy | MITIGATION_STRATEGY enum selection | — | Novel combination |
| Per-CPU strategy state | g_CpuMit[MAXIMUM_PROCESSORS] | — | Novel per-core granularity |
```

### Step 4 — Identify the inventive step

The inventive step is not the individual components — it is the combination and
the specific problem it solves. Document:

- What problem the prior art fails to solve
- How your specific combination solves it
- Why the combination is non-obvious (i.e., why someone skilled in the art would
  not arrive at it without your contribution)

---

## 7. Source Versioning and Staleness

Literature has a shelf life. Establish rules for when to re-read a source:

| Trigger | Action |
|---------|--------|
| New Intel/AMD microarchitecture released | Re-read SDM Vol.4, check new CPUID leaves and MSRs |
| New CVE in the Spectre/MDS/LVI family | Read the advisory and research paper before the 90-day embargo lifts |
| WDK version update | Re-read affected API documentation for behavioral changes |
| Patent application filed by a competitor | Read the published application within 30 days |
| Pre-existing source superseded by a new revision | Update all extraction notes that cite the old revision |

Mark stale sources explicitly in `literature/INDEX.md` with a `SUPERSEDED` tag.
Never delete superseded sources — they are part of the patent prosecution history.

---

## 8. Reading Workflow Summary

```
1. Classify the document (§1)
2. Apply the correct read order for that type (§2)
3. Produce an extraction note using the template (§3.1)
4. Link the extraction to any affected code (§3.2)
5. Update literature/INDEX.md (§4)
6. Evaluate against threat model (§5)
7. Run prior art analysis if novel (§6)
8. Schedule a re-read trigger if source has a TTL (§7)
```

No document is "read" until steps 1–4 are complete. Steps 5–8 apply only when
the document directly informs the driver or a patent claim.

---

## 9. Recommended Literature, Lectures, and Reference Documents

Bibliographic references relevant to the SideChannelKernelPreventor project, grouped
by type. ISBNs are given where a commercial edition exists. Papers and standards do
not carry ISBNs; use the DOI or URL indicated instead.

---

### 9.1 Textbooks and Monographs

#### Operating Systems & Kernel Internals

| # | Title | Author(s) | Edition | Publisher / Year | ISBN-10 | ISBN-13 |
|---|-------|-----------|---------|-----------------|---------|---------|
| 1 | *Windows Internals, Part 1* | Russinovich, M.; Solomon, D.; Ionescu, A.; Yosifovich, P. | 7th ed. | Microsoft Press, 2017 | 0-7356-8418-3 | 978-0-7356-8418-7 |
| 2 | *Windows Internals, Part 2* | Yosifovich, P.; Russinovich, M.; Solomon, D.; Ionescu, A. | 7th ed. | Microsoft Press, 2022 | 0-13-530285-X | 978-0-13-530285-1 |
| 3 | *Modern Operating Systems* | Tanenbaum, A. S.; Bos, H. | 4th ed. | Pearson, 2014 | 0-13-359162-X | 978-0-13-359162-0 |
| 4 | *Rootkits: Subverting the Windows Kernel* | Hoglund, G.; Butler, J. | 1st ed. | Addison-Wesley, 2005 | 0-321-29431-X | 978-0-321-29431-9 |
| 5 | *Rootkits and Bootkits: Reversing Modern Malware and Next Generation Threats* | Matrosov, A.; Rodionov, E.; Bratus, S. | 1st ed. | No Starch Press, 2019 | 1-59327-716-4 | 978-1-59327-716-1 |
| 6 | *The Art of Memory Forensics: Detecting Malware and Threats in Windows, Linux, and Mac Memory* | Ligh, M. H.; Case, A.; Levy, J.; Walters, A. | 1st ed. | Wiley, 2014 | 1-118-82545-0 | 978-1-118-82545-6 |
| 7 | *Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software* | Sikorski, M.; Honig, A. | 1st ed. | No Starch Press, 2012 | 1-59327-290-1 | 978-1-59327-290-6 |

#### Computer Architecture & Microarchitecture

| # | Title | Author(s) | Edition | Publisher / Year | ISBN-10 | ISBN-13 |
|---|-------|-----------|---------|-----------------|---------|---------|
| 8 | *Computer Architecture: A Quantitative Approach* | Hennessy, J. L.; Patterson, D. A. | 6th ed. | Morgan Kaufmann, 2017 | 0-12-811905-1 | 978-0-12-811905-1 |
| 9 | *Computer Organization and Design: The Hardware/Software Interface* (RISC-V ed.) | Patterson, D. A.; Hennessy, J. L. | 2nd ed. | Morgan Kaufmann, 2020 | 0-12-820331-8 | 978-0-12-820331-6 |
| 10 | *Introduction to Hardware Security and Trust* | Tehranipoor, M.; Wang, C. (Eds.) | 1st ed. | Springer, 2012 | 1-4419-8079-5 | 978-1-4419-8079-3 |

#### Cryptography & Applied Security

| # | Title | Author(s) | Edition | Publisher / Year | ISBN-10 | ISBN-13 |
|---|-------|-----------|---------|-----------------|---------|---------|
| 11 | *Applied Cryptography: Protocols, Algorithms, and Source Code in C* | Schneier, B. | 2nd ed. | Wiley, 1996 | 0-471-11709-9 | 978-0-471-11709-4 |
| 12 | *Introduction to Modern Cryptography* | Katz, J.; Lindell, Y. | 3rd ed. | CRC Press, 2020 | 0-8153-8602-4 | 978-0-8153-8602-8 |
| 13 | *A Practical Guide to TPM 2.0: Using the Trusted Platform Module in the New Age of Security* | Arthur, W.; Challener, D.; Goldman, K. | 1st ed. | Apress, 2015 | 1-4302-6583-X | 978-1-4302-6583-9 |

#### Secure Coding & Systems Security

| # | Title | Author(s) | Edition | Publisher / Year | ISBN-10 | ISBN-13 |
|---|-------|-----------|---------|-----------------|---------|---------|
| 14 | *Writing Secure Code* | Howard, M.; LeBlanc, D. | 2nd ed. | Microsoft Press, 2002 | 0-7356-1722-8 | 978-0-7356-1722-3 |
| 15 | *Secure Coding in C and C++* | Seacord, R. C. | 2nd ed. | Addison-Wesley, 2013 | 0-321-82213-5 | 978-0-321-82213-0 |
| 16 | *Computer Security: Art and Science* | Bishop, M. | 2nd ed. | Pearson, 2018 | 0-321-71233-1 | 978-0-321-71233-2 |
| 17 | *Hacking: The Art of Exploitation* | Erickson, J. | 2nd ed. | No Starch Press, 2008 | 1-59327-144-1 | 978-1-59327-144-2 |
| 18 | *The Shellcoder's Handbook: Discovering and Exploiting Security Holes* | Anley, C.; Heasman, J.; Lindner, F.; Richarte, G. | 2nd ed. | Wiley, 2007 | 0-470-08023-8 | 978-0-470-08023-8 |

---

### 9.2 Selected Academic Papers

Papers are ordered by relevance to the driver's threat model. Use the DOI for
canonical access; arXiv/USENIX links are provided as open-access mirrors where
available.

#### Side-Channel Attacks — Speculative Execution

```
[P1] Kocher, P. et al. (2019).
     "Spectre Attacks: Exploiting Speculative Execution."
     2019 IEEE Symposium on Security and Privacy (S&P), pp. 1–19.
     DOI: 10.1109/SP.2019.00002
     Relevance: M1 (PMU detection), M4 (LFENCE barriers, IBRS/STIBP)

[P2] Lipp, M. et al. (2018).
     "Meltdown: Reading Kernel Memory from User Space."
     27th USENIX Security Symposium, pp. 973–990.
     URL: https://www.usenix.org/conference/usenixsecurity18/presentation/lipp
     Relevance: M3 (kernel integrity), M4 (KPTI-style page isolation)

[P3] Van Bulck, J. et al. (2018).
     "Foreshadow: Extracting the Keys to the Intel SGX Kingdom with
     Transient Out-of-Order Execution."
     27th USENIX Security Symposium, pp. 991–1008.
     URL: https://www.usenix.org/conference/usenixsecurity18/presentation/bulck
     Relevance: M4 (L1TF mitigation, IA32_FLUSH_CMD)
```

#### Side-Channel Attacks — Microarchitectural Data Sampling (MDS)

```
[P4] Van Schaik, S. et al. (2019).
     "RIDL: Rogue In-flight Data Load."
     2019 IEEE Symposium on Security and Privacy (S&P), pp. 88–105.
     DOI: 10.1109/SP.2019.00087
     Relevance: M4 (VERW flush, MDS mitigation strategy)

[P5] Schwarz, M. et al. (2019).
     "ZombieLoad: Cross-Privilege-Boundary Data Sampling."
     ACM CCS 2019, pp. 753–768.
     DOI: 10.1145/3319535.3354252
     Relevance: M4 (MDS_NO capability flag, VERW)

[P6] Canella, C. et al. (2019).
     "A Systematic Evaluation of Transient Execution Attacks and Defenses."
     28th USENIX Security Symposium, pp. 249–266.
     URL: https://www.usenix.org/conference/usenixsecurity19/presentation/canella
     Relevance: Comprehensive taxonomy; informs M4 mitigation selection logic
```

#### Cache-Timing Attacks

```
[P7] Yarom, Y.; Falkner, K. (2014).
     "FLUSH+RELOAD: A High Resolution, Low Noise, L3 Cache Side-Channel Attack."
     23rd USENIX Security Symposium, pp. 719–732.
     URL: https://www.usenix.org/conference/usenixsecurity14/technical-sessions/presentation/yarom
     Relevance: M1 (LLC miss rate detection threshold calibration)

[P8] Gruss, D.; Maurice, C.; Wagner, K.; Mangard, S. (2016).
     "Flush+Flush: A Fast and Stealthy Cache Attack."
     DIMVA 2016, LNCS 9721, pp. 279–299.
     DOI: 10.1007/978-3-319-40667-1_14
     Relevance: M1 (detection of stealthy timing variants)

[P9] Osvik, D. A.; Shamir, A.; Tromer, E. (2006).
     "Cache Attacks and Countermeasures: The Case of AES."
     RSA Conference 2006 (CT-RSA), LNCS 3860, pp. 1–20.
     DOI: 10.1007/11605805_1
     Relevance: M1 (L1D miss patterns used as attack signal)

[P10] Bernstein, D. J. (2005).
      "Cache-timing attacks on AES." Technical report.
      URL: https://cr.yp.to/antiforgery/cachetiming-20050414.pdf
      Relevance: M1 (baseline for RDTSC-rate anomaly thresholds)

[P11] Percival, C. (2005).
      "Cache Missing for Fun and Profit."
      BSDCan 2005.
      URL: https://www.daemonology.net/papers/htt.pdf
      Relevance: M4 (SMT/HT sibling core cross-contamination)
```

#### Timing Attacks (Classical)

```
[P12] Kocher, P. C. (1996).
      "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems."
      CRYPTO 1996, LNCS 1109, pp. 104–113.
      DOI: 10.1007/3-540-68697-5_9
      Relevance: M3 (constant-time comparison requirement for SHA-256 checks)
```

#### Survey / Countermeasure Overview

```
[P13] Ge, Q.; Yarom, Y.; Cock, D.; Heiser, G. (2018).
      "A Survey of Microarchitectural Timing Attacks and Countermeasures
      on Contemporary Hardware."
      Journal of Cryptographic Engineering, 8(1), pp. 1–27.
      DOI: 10.1007/s13389-016-0141-6
      Relevance: Breadth reference; maps attack families to mitigations for §5

[P14] Lipp, M. et al. (2020).
      "Take A Way: Exploring the Security Implications of AMD's Cache Way Predictors."
      ACM ASIACCS 2020, pp. 813–825.
      DOI: 10.1145/3320269.3384746
      Relevance: M1 (AMD-specific PMU event selection differences)
```

---

### 9.3 Standards, Specifications, and Technical Reports

These documents carry no ISBN. Cite by document identifier and revision date.

#### CPU Architecture

```
[S1] Intel Corporation.
     "Intel® 64 and IA-32 Architectures Software Developer's Manual"
     Combined Volumes 1–4. (Continuously revised.)
     Relevant volumes: Vol. 3A (system programming), Vol. 4 (MSR reference).
     URL: https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html
     Internal alias: Intel SDM

[S2] AMD.
     "AMD64 Architecture Programmer's Manual" Volumes 1–5. (Continuously revised.)
     Vol. 2: System Programming; Vol. 3: General-Purpose and System Instructions.
     URL: https://www.amd.com/en/support/tech-docs
     Internal alias: AMD APM
```

#### Trusted Platform Module

```
[S3] Trusted Computing Group.
     "TPM Library Specification, Family 2.0" Parts 1–4. Revision 01.59, 2019.
     URL: https://trustedcomputinggroup.org/resource/tpm-library-specification/
```

#### NIST Special Publications

```
[S4] Chen, L. et al. (NIST). SP 800-90A Rev.1:
     "Recommendation for Random Number Generation Using Deterministic Random Bit Generators."
     NIST, 2015.
     URL: https://doi.org/10.6028/NIST.SP.800-90Ar1

[S5] Cooper, D. A. et al. (NIST). SP 800-147:
     "BIOS Protection Guidelines."
     NIST, 2011.
     URL: https://doi.org/10.6028/NIST.SP.800-147

[S6] Polk, T.; Regenscheid, A. (NIST). SP 800-155 (Draft):
     "BIOS Integrity Measurement Guidelines."
     NIST, 2011.
     URL: https://csrc.nist.gov/publications/detail/sp/800-155/draft

[S7] Barker, E. (NIST). SP 800-57 Part 1 Rev.5:
     "Recommendation for Key Management."
     NIST, 2020.
     URL: https://doi.org/10.6028/NIST.SP.800-57pt1r5
```

#### Vendor Security Advisories (Selected Foundational)

```
[S8] Intel Product Security Center. SA-00075 (INTEL-SA-00075):
     "Intel Active Management Technology, Intel Small Business Technology, and
     Intel Standard Manageability Escalation of Privilege."
     Intel, 2017.

[S9] Intel Product Security Center. SA-00088 (INTEL-SA-00088):
     "Speculative Execution and Indirect Branch Prediction Side Channel
     Analysis Method." Intel, 2018.
     URL: https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00088.html
     Relevance: M4 (IBRS/STIBP/IBPB selection)

[S10] Intel Product Security Center. SA-00233 (INTEL-SA-00233):
      "Microarchitectural Data Sampling Advisory."
      Intel, 2019.
      URL: https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00233.html
      Relevance: M4 (VERW mitigation, MDS_NO flag, IA32_ARCH_CAPABILITIES)

[S11] Intel Product Security Center. SA-00161 (INTEL-SA-00161):
      "L1 Terminal Fault / Foreshadow Advisory."
      Intel, 2018.
      URL: https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00161.html
      Relevance: M4 (L1TF_NO flag, IA32_FLUSH_CMD)

[S12] Microsoft Security Response Center (MSRC).
      "ADV180002: Guidance to mitigate speculative execution side-channel vulnerabilities."
      Microsoft, 2018. (Updated continuously.)
      URL: https://msrc.microsoft.com/update-guide/vulnerability/ADV180002
      Relevance: M3, M4 (Windows-level mitigation interactions)
```

#### Bus and I/O Specifications

```
[S13] PCI-SIG.
      "PCI Express® Base Specification Revision 5.0."
      PCI-SIG, 2019.
      URL: https://pcisig.com/specifications
      Relevance: M2 (ECAM base address, config space layout)

[S14] PCI-SIG.
      "PCI Bus Power Management Interface Specification Revision 1.2."
      PCI-SIG, 2004.
      Relevance: M2 (device capability registers)
```

---

### 9.4 Courses and Lecture Series

Online and academic lecture series whose material directly informs driver
development and side-channel research. No ISBN applies.

```
[L1] MIT OpenCourseWare — 6.858 Computer Systems Security
     Instructors: Frans Kaashoek, Nickolai Zeldovich (MIT CSAIL)
     Format: Lecture slides, notes, lab assignments (open access)
     URL: https://ocw.mit.edu/courses/6-858-computer-systems-security-fall-2014/
     Relevance: Threat modelling methodology, kernel security, privilege separation

[L2] Stanford CS 155 — Computer and Network Security
     Instructors: Dan Boneh, John Mitchell (Stanford University)
     Format: Lecture slides and reading lists (varies by year)
     URL: https://cs155.stanford.edu/
     Relevance: Side-channel fundamentals, memory safety, hardware security

[L3] CMU 15-410 / 15-605 — Operating System Design and Implementation
     Instructors: David Eckhardt, Dave O'Hallaron (CMU)
     Format: Lecture notes, kernel projects
     URL: https://www.cs.cmu.edu/~410/
     Relevance: Kernel scheduler, IRQL/interrupt analogue, synchronisation primitives

[L4] USENIX Security Training — "Microarchitectural Side Channels"
     Presenters: Yuval Yarom et al.
     Format: Tutorial videos and slides from USENIX Security 2019/2020
     URL: https://www.usenix.org/conference/usenixsecurity19
     Relevance: M1 attack primitives, PMU usage, flush-based defences

[L5] Intel Developer Zone — Performance Monitoring Unit (PMU) Tutorial Series
     Authors: Intel Architecture Performance Monitoring Team
     Format: Articles and code samples (open access)
     URL: https://www.intel.com/content/www/us/en/developer/topic-technology/software-optimization-notice.html
     Relevance: M1 (IA32_PERFEVTSEL encoding, PMI delivery, PEBS)

[L6] Microsoft Learn — Windows Driver Development Documentation
     Authors: Microsoft WDK Team
     Format: Online reference + samples (open access)
     URL: https://learn.microsoft.com/windows-hardware/drivers/
     Relevance: All modules (WDM/KMDF conventions, IRQL rules, MDL handling)

[L7] Daira Hopwood — "Applied Cryptographic Hardware" (Real World Crypto, 2020)
     Format: Conference talk slides and recording
     URL: https://rwc.iacr.org/2020/
     Relevance: TPM integration, hardware random number generation (M5)
```

---

### 9.5 Quick-Reference: Document → Driver Module Map

Use this table to determine which section of the literature is authoritative for
a given module before making any implementation decision.

| Driver Module | Primary Sources | Secondary Sources |
|---------------|-----------------|-------------------|
| **M1** — PMU / Cache Detection | S1 (SDM Vol.4), S2 (AMD APM Vol.3), P7, P8, P9, P10, L5 | P13, P6 |
| **M2** — PCIe / IOMMU | S13, S14, S1 (SDM Vol.3A §29) | S12 |
| **M3** — Kernel Integrity | P1, P2, S12 (MSRC ADV180002), S5, S6 | [1], [4], [5] |
| **M4** — Cache Mitigation | S10, S11, P4, P5, P3, S1 (SDM Vol.4 §2.1), P11 | P6, P13 |
| **M5** — Secure Comms / TPM | S3, S7, S4, [13], L7 | [11], [12] |
| **Threat model** | P1–P6, P13, L1, L2 | P7–P12 |
| **Patent prior art** | P1–P14, S1–S14 | [1]–[18] |

Numbers in square brackets refer to the textbook list in §9.1.
