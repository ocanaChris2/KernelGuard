// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_integrity.c - Module 3: kernel integrity and hook detection.
 * Counterpart of windows/src/kernel_integrity.c.
 *
 *  3.1  CPU control state   IDT gates, syscall-entry MSRs, CR0.WP, CR4 pins,
 *                           IBRS - checked on EVERY CPU against a boot-time
 *                           baseline (Windows: IDT of the current CPU only).
 *  3.2  Input-path hooks    kg_input.c (callback-range / prologue checks); the
 *                           symbol helper it needs lives here.
 *  3.3  .text integrity     core kernel image + every loaded module, including
 *                           this one.
 *  3.4  Module lifecycle    module notifier: baselines follow modules as they
 *                           come and go, and a load is itself reported.
 *
 * The problem the Windows design does not have to solve
 * -----------------------------------------------------
 * ntoskrnl's .text is immutable after boot (PatchGuard/HVCI).  Linux kernel text
 * is not: jump labels (every enabled tracepoint or static key), ftrace, static
 * calls, kprobes and BPF trampolines all rewrite live text at runtime.  A plain
 * SHA-256 of .text would therefore fire the first time anyone runs `perf`.
 * So we keep a baseline COPY (not just a hash) of each region and, on a
 * mismatch, look at the actual difference:
 *
 *   - 5-byte site flipping between NOP5 <-> CALL/JMP rel32, CALL <-> CALL with a
 *     new target, and the 2-byte NOP2 <-> JMP8 form are the kernel's own patch
 *     sites.  They are accepted (and counted) if the branch target is
 *     legitimate code.
 *   - a lone 0xCC (int3) is a kprobe: reported at "watch" level.
 *   - anything else - and any branch whose target is not known code - is a
 *     critical TEXT_PATCH and puts the driver in fail-safe mode.
 *
 * What this does NOT catch: hooks that ride on the kernel's own patch sites
 * (ftrace/kprobes/livepatch/BPF registered through the normal APIs), and data
 * pointer hooks (syscall/VFS tables, LSM hooks).  See README "Known limitations".
 *
 * The .text bounds cannot come from _stext/_etext (not exported), so they are
 * found from the page tables: the contiguous read-only + executable run of the
 * kernel mapping that contains a known function.
 */
#include "kg.h"

#include <linux/cpu.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/rcupdate.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <asm/desc.h>
#include <asm/pgtable.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>

static bool p_text = true;
static unsigned int p_text_max_mb = 128;
module_param_named(text_check, p_text, bool, 0444);
MODULE_PARM_DESC(text_check, "Hash-compare kernel and module .text (default 1)");
static bool p_text_modules = true;
module_param_named(text_modules, p_text_modules, bool, 0444);
MODULE_PARM_DESC(text_modules, "Also baseline every loaded module's .text, not just the kernel image (default 1)");
module_param_named(text_max_mb, p_text_max_mb, uint, 0444);
MODULE_PARM_DESC(text_max_mb, "Cap on baseline .text copies held in memory, MiB (default 128)");

/*----------------------------------------------------------------------------
 * Symbol helper (kallsyms lookup usable in any non-NMI context)
 *--------------------------------------------------------------------------*/
bool kg_sym_module(unsigned long addr, char *modname, size_t len, bool *found)
{
	char buf[KSYM_SYMBOL_LEN];
	char *lb, *rb;

	sprint_symbol_no_offset(buf, addr);
	/* Unresolvable addresses come back as a bare "0x...". */
	*found = strncmp(buf, "0x", 2) != 0;
	modname[0] = '\0';
	lb = strchr(buf, '[');
	if (*found && lb) {
		rb = strchr(lb, ']');
		if (rb) {
			*rb = '\0';
			strscpy(modname, lb + 1, len);
			/* build-id suffix, if any: "[mod build_id]" */
			rb = strchr(modname, ' ');
			if (rb)
				*rb = '\0';
		}
	}
	return *found;
}

/*----------------------------------------------------------------------------
 * .text bounds from the page tables
 *--------------------------------------------------------------------------*/
static unsigned long kg_text_start, kg_text_end;

bool kg_addr_in_kernel_text(unsigned long addr)
{
	return kg_text_end && addr >= kg_text_start && addr < kg_text_end;
}

static bool kg_va_is_rx(unsigned long va)
{
	unsigned int level;
	pte_t *pte = lookup_address(va, &level);

	return pte && pte_present(*pte) && pte_exec(*pte) && !pte_write(*pte);
}

static int kg_find_text_bounds(void)
{
	unsigned long anchor = (unsigned long)&_printk & PAGE_MASK;
	unsigned long lo = anchor, hi = anchor + PAGE_SIZE;
	const unsigned long limit = 256UL << 20;

	if (!kg_va_is_rx(anchor))
		return -ENODATA;
	while (anchor - lo < limit && kg_va_is_rx(lo - PAGE_SIZE))
		lo -= PAGE_SIZE;
	while (hi - anchor < limit && kg_va_is_rx(hi))
		hi += PAGE_SIZE;

	if (hi - lo < (1UL << 20) || hi - lo >= limit) {
		pr_warn("implausible kernel text extent %#lx bytes - text integrity disabled\n", hi - lo);
		return -ERANGE;
	}
	kg_text_start = lo;
	kg_text_end = hi;
	pr_info("kernel text: %lu KiB read-only+executable\n", (hi - lo) >> 10);
	return 0;
}

/*----------------------------------------------------------------------------
 * Monitored regions: the core image and each module's text
 *--------------------------------------------------------------------------*/
struct kg_region {
	struct list_head node;
	char name[MODULE_NAME_LEN];
	unsigned long base;
	size_t size;
	u8 *copy;
	bool kernel;
	const struct module *mod;       /* identity only - never dereferenced */
};

static LIST_HEAD(kg_regions);
static DEFINE_MUTEX(kg_region_lock);
static size_t kg_copy_bytes;
static unsigned int kg_nregions;
static bool kg_baseline_done;       /* module loads after this point are reported */
static bool kg_text_enabled;

#define KG_CHUNK    65536UL
#define KG_OVERLAP  8UL             /* patch windows may straddle a chunk boundary */
static u8 *kg_tmp;                  /* KG_CHUNK + KG_OVERLAP bytes, under kg_region_lock */

static bool kg_region_contains(const struct kg_region *r, unsigned long addr)
{
	return addr >= r->base && addr < r->base + r->size;
}

/* kg_region_lock held */
static bool kg_in_tracked_module(unsigned long addr)
{
	struct kg_region *r;

	list_for_each_entry(r, &kg_regions, node)
		if (!r->kernel && kg_region_contains(r, addr))
			return true;
	return false;
}

static bool kg_in_module_area(unsigned long addr)
{
	return addr >= MODULES_VADDR && addr < MODULES_END;
}

/*
 * Bulk copy / compare in 64 KiB pieces.  Each piece runs with preemption off and
 * kg_self_busy set, so the driver's own multi-MiB streaming never looks like a
 * cache attack to Module 1, and no piece keeps the CPU for more than ~10 us.
 */
static void kg_stream_copy(void *dst, const void *src, size_t n)
{
	size_t off;

	for (off = 0; off < n; off += KG_CHUNK) {
		size_t len = min_t(size_t, KG_CHUNK, n - off);

		preempt_disable();
		this_cpu_write(kg_self_busy, true);
		memcpy(dst + off, src + off, len);
		this_cpu_write(kg_self_busy, false);
		preempt_enable();
		cond_resched();
	}
}

static bool kg_stream_equal(const void *a, const void *b, size_t n)
{
	size_t off;

	for (off = 0; off < n; off += KG_CHUNK) {
		size_t len = min_t(size_t, KG_CHUNK, n - off);
		bool same;

		preempt_disable();
		this_cpu_write(kg_self_busy, true);
		same = !memcmp(a + off, b + off, len);
		this_cpu_write(kg_self_busy, false);
		preempt_enable();
		if (!same)
			return false;
		cond_resched();
	}
	return true;
}

/* kg_region_lock held.  Returns 0 or -errno; the copy is only kept if stable. */
static int kg_region_add(const char *name, unsigned long base, size_t size,
			 bool kernel, const struct module *mod)
{
	struct kg_region *r;
	int attempt;

	if (!size)
		return 0;
	if (kg_copy_bytes + size > ((size_t)p_text_max_mb << 20)) {
		pr_warn("text baseline cap (%u MiB) reached - %s not monitored\n", p_text_max_mb, name);
		return -ENOSPC;
	}
	r = kzalloc(sizeof(*r), GFP_KERNEL);
	if (!r)
		return -ENOMEM;
	r->copy = vmalloc(size);
	if (!r->copy) {
		kfree(r);
		return -ENOMEM;
	}
	strscpy(r->name, name, sizeof(r->name));
	r->base = base;
	r->size = size;
	r->kernel = kernel;
	r->mod = mod;

	/* Copy, then confirm it is stable: a concurrent text_poke() must not become the baseline. */
	for (attempt = 0; attempt < 4; attempt++) {
		kg_stream_copy(r->copy, (const void *)base, size);
		if (kg_stream_equal(r->copy, (const void *)base, size))
			break;
		msleep(10);
	}

	list_add_tail(&r->node, &kg_regions);
	kg_copy_bytes += size;
	kg_nregions++;
	return 0;
}

/* kg_region_lock held */
static void kg_region_del(struct kg_region *r)
{
	list_del(&r->node);
	kg_copy_bytes -= r->size;
	kg_nregions--;
	vfree(r->copy);
	kfree(r);
}

bool kg_text_active(void)
{
	return kg_text_enabled;
}

void kg_text_stats(unsigned int *regions, unsigned int *kib)
{
	/* word-sized reads; taking kg_region_lock here would stall behind a verify pass */
	*regions = READ_ONCE(kg_nregions);
	*kib = (unsigned int)(READ_ONCE(kg_copy_bytes) >> 10);
}

/*----------------------------------------------------------------------------
 * Classification of a modified byte run
 *--------------------------------------------------------------------------*/
enum kg_form { F_OTHER, F_NOP5, F_CALL, F_JMP, F_XOR5, F_RET5 };

static enum kg_form kg_form5(const u8 *p)
{
	static const u8 nop_p6[5] = { 0x0f, 0x1f, 0x44, 0x00, 0x00 };
	static const u8 nop_k8[5] = { 0x66, 0x66, 0x90, 0x66, 0x90 };
	static const u8 xor5[5]   = { 0x2e, 0x2e, 0x2e, 0x31, 0xc0 };   /* static_call RET0 */
	static const u8 ret5[5]   = { 0xc3, 0xcc, 0xcc, 0xcc, 0xcc };   /* static_call NULL */

	if (!memcmp(p, nop_p6, 5) || !memcmp(p, nop_k8, 5))
		return F_NOP5;
	if (p[0] == 0xe8)
		return F_CALL;
	if (p[0] == 0xe9)
		return F_JMP;
	if (!memcmp(p, xor5, 5))
		return F_XOR5;
	if (!memcmp(p, ret5, 5))
		return F_RET5;
	return F_OTHER;
}

static unsigned long kg_branch_target(unsigned long site, const u8 *p)
{
	s32 rel;

	memcpy(&rel, p + 1, sizeof(rel));
	return site + 5 + (long)rel;
}

enum kg_verdict { KG_V_BENIGN, KG_V_WATCH, KG_V_CRITICAL };   /* ordered: worst wins */

struct kg_verdict_info {
	enum kg_verdict v;
	u32 flags;              /* KG_TEXTF_* */
	unsigned long site;     /* address the alert points at */
	size_t wlen;
};

struct kg_seg {
	size_t end;             /* first region offset after the matched patch site */
	enum kg_verdict v;
	u32 flags;
	unsigned long site;
};

/* The byte at @pos as it would be after the change (bytes outside the run are unchanged). */
static inline u8 kg_new_at(const struct kg_region *r, size_t rs, size_t re, const u8 *newb, size_t pos)
{
	return (pos >= rs && pos < re) ? newb[pos - rs] : r->copy[pos];
}

/*
 * Does the modification starting at @pos look like one of the kernel's own
 * patch sites?  Two shapes exist on x86-64:
 *
 *   2 bytes  NOP2 (66 90) <-> JMP8 (EB rel8)              short jump labels
 *   5 bytes  NOP5 / CALL rel32 / JMP rel32 transitions    jump labels, ftrace,
 *                                                         static calls
 *
 * The 2-byte form is tried first: a 5-byte window that starts a byte early
 * could otherwise mistake a preceding 0xE8/0xE9 for a CALL/JMP opcode.
 * kg_region_lock held.
 */
static bool kg_match_site(struct kg_region *r, size_t pos, size_t rs, size_t re,
			  const u8 *newb, bool first, struct kg_seg *seg)
{
	int delta;

	memset(seg, 0, sizeof(*seg));
	seg->site = r->base + pos;

	if (pos + 2 <= r->size) {
		u8 o0 = r->copy[pos], o1 = r->copy[pos + 1];
		u8 n0 = kg_new_at(r, rs, re, newb, pos), n1 = kg_new_at(r, rs, re, newb, pos + 1);

		if ((o0 == 0x66 && o1 == 0x90 && n0 == 0xeb) ||
		    (n0 == 0x66 && n1 == 0x90 && o0 == 0xeb)) {
			seg->end = pos + 2;
			seg->v = KG_V_BENIGN;
			return true;
		}
	}

	/* Earlier window starts are only meaningful for a rel32 retarget whose opcode byte is unchanged. */
	for (delta = 0; delta <= (first ? 4 : 0); delta++) {
		u8 o[5], n[5];
		enum kg_form fo, fn;
		size_t s;
		int k;

		if ((size_t)delta > pos)
			break;
		s = pos - delta;
		if (s + 5 > r->size)
			continue;
		for (k = 0; k < 5; k++) {
			o[k] = r->copy[s + k];
			n[k] = kg_new_at(r, rs, re, newb, s + k);
		}
		if (delta && (o[0] != n[0] || (o[0] != 0xe8 && o[0] != 0xe9)))
			continue;

		fo = kg_form5(o);
		fn = kg_form5(n);
		if (fo == F_OTHER && fn == F_OTHER)
			continue;

		seg->site = r->base + s;
		seg->end = s + 5;

		if (fo == F_OTHER || fn == F_OTHER) {
			/* Optimised kprobe: arbitrary instruction bytes -> JMP to a detour buffer. */
			if (fo == F_OTHER && fn == F_JMP && delta == 0) {
				unsigned long t = kg_branch_target(seg->site, n);

				seg->v = (kg_in_module_area(t) && !kg_in_tracked_module(t) &&
					  !kg_addr_in_kernel_text(t)) ? KG_V_WATCH : KG_V_CRITICAL;
				seg->flags = KG_TEXTF_UNKNOWN_TARGET;
				return true;
			}
			continue;
		}

		if (fo == F_XOR5 || fo == F_RET5 || fn == F_XOR5 || fn == F_RET5) {
			/* static_call NULL/RET0: legitimate, but also exactly what "neutralise
			 * this check" looks like - never accept silently. */
			seg->v = KG_V_WATCH;
			return true;
		}

		if (fn == F_CALL || fn == F_JMP) {
			unsigned long t = kg_branch_target(seg->site, n);
			bool ok = kg_addr_in_kernel_text(t) || kg_region_contains(r, t);

			if (!ok && fn == F_CALL)
				ok = kg_in_tracked_module(t) || kg_in_module_area(t);
			if (!ok) {
				seg->flags = KG_TEXTF_UNKNOWN_TARGET;
				/* an optimised kprobe's detour buffer lives in the module area */
				seg->v = (fn == F_JMP && kg_in_module_area(t) && !kg_in_tracked_module(t)) ?
					 KG_V_WATCH : KG_V_CRITICAL;
				return true;
			}
		}
		seg->v = KG_V_BENIGN;
		return true;
	}
	return false;
}

/*
 * Classify the modified run [@rs, @re) of @r, whose new bytes are @newb.  The
 * run may span several adjacent patch sites (a function with a handful of
 * static branches flips them together), so it is consumed site by site; the
 * worst verdict wins.  kg_region_lock held.
 */
static struct kg_verdict_info kg_classify(struct kg_region *r, size_t rs, size_t re, const u8 *newb)
{
	struct kg_verdict_info out = { KG_V_BENIGN, r->kernel ? KG_TEXTF_KERNEL : 0, r->base + rs, re - rs };
	size_t pos = rs;
	bool first = true;

	while (pos < re) {
		struct kg_seg seg;

		if (newb[pos - rs] == r->copy[pos]) {       /* gap byte inside a merged run */
			pos++;
			continue;
		}
		if (!kg_match_site(r, pos, rs, re, newb, first, &seg)) {
			if (re - rs == 1 && (newb[0] == 0xcc || r->copy[rs] == 0xcc)) {
				/* a lone int3 is a kprobe breakpoint */
				out.v = max(out.v, KG_V_WATCH);
				out.flags |= KG_TEXTF_BREAKPOINT;
			} else {
				out.v = KG_V_CRITICAL;
				out.site = r->base + pos;
				out.wlen = re - pos;
			}
			return out;
		}
		if (seg.v > out.v) {
			out.v = seg.v;
			out.site = seg.site;
			out.wlen = 5;
		}
		out.flags |= seg.flags;
		pos = seg.end > pos ? seg.end : pos + 1;
		first = false;
	}
	return out;
}

/*----------------------------------------------------------------------------
 * Verification of one region (kg_region_lock held)
 *--------------------------------------------------------------------------*/
static void kg_handle_run(struct kg_region *r, size_t rs, size_t re, const u8 *newb)
{
	struct kg_verdict_info vi = kg_classify(r, rs, re, newb);
	size_t show = min_t(size_t, re - rs, 16);
	u64 p2;

	switch (vi.v) {
	case KG_V_BENIGN:
		kg_stat_inc(text_dynamic_patches);
		pr_debug("%s: dynamic patch site at +%#zx (%zu bytes) accepted\n", r->name, rs, vi.wlen);
		break;
	case KG_V_WATCH:
	case KG_V_CRITICAL:
		p2 = ((u64)vi.flags << 32) | (u32)(re - rs);
		kg_stat_inc(text_patch_detected);
		kg_report(KG_ALERT_TEXT_PATCH,
			  vi.v == KG_V_CRITICAL ? KG_LEVEL_CRITICAL : KG_LEVEL_WATCH,
			  r->base + rs, p2,
			  "%s text modified at %s+%#zx, %zu byte(s): %*phN -> %*phN%s",
			  r->kernel ? "kernel" : "module", r->name, rs, re - rs,
			  (int)show, &r->copy[rs], (int)show, newb,
			  vi.flags & KG_TEXTF_UNKNOWN_TARGET ? " [branch target outside known code]" : "");
		break;
	}
	/* Accept the new bytes either way: one alert per modification, not one per pass. */
	memcpy(&r->copy[rs], newb, re - rs);
}

static void kg_chunk_check(struct kg_region *r, size_t off, size_t n)
{
	const u8 *live = (const u8 *)(r->base + off);
	u8 *cur = kg_tmp;
	u8 *old = r->copy + off;
	size_t i, j;

	/*
	 * Sample twice, 20 ms apart, and only trust bytes that agree: text_poke()
	 * passes through transient states (int3 markers, half-written operands).
	 */
	kg_stream_copy(cur, live, n);
	msleep(20);
	for (i = 0; i < n; i++)
		if (cur[i] != live[i])
			cur[i] = old[i];        /* unstable byte: treat as unchanged this pass */

	i = 0;
	while (i < n) {
		size_t rs, re, gap;

		while (i < n && cur[i] == old[i])
			i++;
		if (i >= n)
			break;
		rs = i;
		re = i + 1;
		gap = 0;
		for (j = i + 1; j < n && gap <= 3; j++) {
			if (cur[j] != old[j]) {
				re = j + 1;
				gap = 0;
			} else {
				gap++;
			}
		}
		/* runs that start in the overlap belong to the next chunk */
		if (rs < KG_CHUNK || off + n >= r->size)
			kg_handle_run(r, off + rs, off + re, cur + rs);
		i = re;
	}
}

static void kg_region_verify(struct kg_region *r)
{
	size_t off;

	for (off = 0; off < r->size; off += KG_CHUNK) {
		size_t n = min_t(size_t, KG_CHUNK + KG_OVERLAP, r->size - off);

		bool same;

		/* 64 KiB at a time: ~10 us non-preemptible, and invisible to the PMU handler */
		preempt_disable();
		this_cpu_write(kg_self_busy, true);
		same = !memcmp((const void *)(r->base + off), r->copy + off, n);
		this_cpu_write(kg_self_busy, false);
		preempt_enable();
		if (same)
			continue;
		kg_chunk_check(r, off, n);
	}
}

static void kg_text_verify_all(void)
{
	struct kg_region *r, *tmp;

	if (!kg_text_enabled)
		return;
	mutex_lock(&kg_region_lock);
	list_for_each_entry_safe(r, tmp, &kg_regions, node) {
		kg_region_verify(r);
		cond_resched();
	}
	mutex_unlock(&kg_region_lock);
}

/*----------------------------------------------------------------------------
 * CPU control state (Windows: IdtVerifyKeyboardHandler)
 *--------------------------------------------------------------------------*/
struct kg_cpust {
	bool valid;
	u16  idt_limit;
	unsigned long idt_base;
	u64  lstar, cstar, star, smask, sysenter;
	unsigned long cr0, cr4;
	u64  ibrs;
};

#define KG_CR4_PINS   (X86_CR4_SMEP | X86_CR4_SMAP | X86_CR4_UMIP | X86_CR4_FSGSBASE)

/* Register ids used in CTRL_REG_TAMPER Param1 (low half) */
#define KG_REG_CR0    0x10000000u
#define KG_REG_CR4    0x10000004u
#define KG_REG_IDTR   0x10000100u

static struct kg_cpust *kg_cpu_base;
static gate_desc *kg_idt_base;              /* 256-entry baseline copy */
static bool kg_idt_enabled;

static void kg_cpust_collect(void *info)
{
	struct kg_cpust *c = &((struct kg_cpust *)info)[raw_smp_processor_id()];
	struct desc_ptr idtr;
	u64 v;

	memset(c, 0, sizeof(*c));
	store_idt(&idtr);
	c->idt_base = idtr.address;
	c->idt_limit = idtr.size;
	kg_rdmsr_safe(MSR_LSTAR, &c->lstar);
	kg_rdmsr_safe(MSR_CSTAR, &c->cstar);
	kg_rdmsr_safe(MSR_STAR, &c->star);
	kg_rdmsr_safe(MSR_SYSCALL_MASK, &c->smask);
	if (boot_cpu_has(X86_FEATURE_SEP))
		kg_rdmsr_safe(MSR_IA32_SYSENTER_EIP, &c->sysenter);
	c->cr0 = read_cr0();
	c->cr4 = __read_cr4();
	/*
	 * SPEC_CTRL is owned by the kernel: only READ it, and only where bit 0 is
	 * a constant (eIBRS).  Elsewhere the kernel toggles it around entry/exit.
	 */
	if (boot_cpu_has(X86_FEATURE_IBRS_ENHANCED) && !kg_rdmsr_safe(MSR_IA32_SPEC_CTRL, &v))
		c->ibrs = v & SPEC_CTRL_IBRS;
	c->valid = true;
}

static void kg_reg_alert(int cpu, u32 reg, u64 newv, const char *what)
{
	kg_stat_inc(idt_hook_detected);
	kg_report(KG_ALERT_CTRL_REG_TAMPER, KG_LEVEL_CRITICAL,
		  ((u64)cpu << 32) | reg, newv, "CPU%d %s changed since baseline (now %#llx)",
		  cpu, what, newv);
}

static void kg_cpust_compare(int cpu, struct kg_cpust *b, const struct kg_cpust *c)
{
#define CHECK_MSR(field, msr, label)                                                   \
	do {                                                                            \
		if (b->field != c->field) {                                             \
			kg_reg_alert(cpu, (msr), c->field, label);                       \
			b->field = c->field;                                            \
		}                                                                       \
	} while (0)

	CHECK_MSR(lstar, MSR_LSTAR, "MSR_LSTAR (64-bit syscall entry)");
	CHECK_MSR(cstar, MSR_CSTAR, "MSR_CSTAR (compat syscall entry)");
	CHECK_MSR(star, MSR_STAR, "MSR_STAR");
	CHECK_MSR(smask, MSR_SYSCALL_MASK, "MSR_SYSCALL_MASK");
	CHECK_MSR(sysenter, MSR_IA32_SYSENTER_EIP, "MSR_IA32_SYSENTER_EIP");
	CHECK_MSR(ibrs, MSR_IA32_SPEC_CTRL, "IA32_SPEC_CTRL.IBRS");
#undef CHECK_MSR

	if ((b->cr0 & X86_CR0_WP) != (c->cr0 & X86_CR0_WP)) {
		kg_reg_alert(cpu, KG_REG_CR0, c->cr0, "CR0.WP (kernel write protection)");
		b->cr0 = c->cr0;
	}
	if ((b->cr4 & KG_CR4_PINS) != (c->cr4 & KG_CR4_PINS)) {
		kg_reg_alert(cpu, KG_REG_CR4, c->cr4, "CR4 protection bits (SMEP/SMAP/UMIP/FSGSBASE)");
		b->cr4 = c->cr4;
	}
	if (kg_idt_enabled && b->idt_base != c->idt_base) {
		kg_stat_inc(idt_hook_detected);
		kg_report(KG_ALERT_IDT_HOOK, KG_LEVEL_CRITICAL, c->idt_base, 0x100,
			  "CPU%d IDTR base moved since baseline", cpu);
		b->idt_base = c->idt_base;
	}
}

/* Compare the live IDT against the baseline, and check handlers are in kernel text. */
static void kg_idt_verify(const struct kg_cpust *c, bool baseline_pass)
{
	gate_desc *cur = (gate_desc *)c->idt_base;
	int v, n = min_t(int, 256, (c->idt_limit + 1) / (int)sizeof(gate_desc));

	for (v = 0; v < n; v++) {
		unsigned long handler = gate_offset(&cur[v]);
		bool changed = !baseline_pass && memcmp(&cur[v], &kg_idt_base[v], sizeof(gate_desc));

		if (!cur[v].bits.p && !changed)
			continue;
		if (changed || (baseline_pass && kg_text_end && !kg_addr_in_kernel_text(handler))) {
			kg_stat_inc(idt_hook_detected);
			kg_report(KG_ALERT_IDT_HOOK, KG_LEVEL_CRITICAL, handler, v,
				  "IDT[%#x] %s (handler %pS)", v,
				  changed ? "changed since baseline" : "handler outside kernel text",
				  (void *)handler);
			/* one alert per anomaly, not one per pass */
			memcpy(&kg_idt_base[v], &cur[v], sizeof(gate_desc));
		}
	}
}

static void kg_cpu_state_check(void)
{
	struct kg_cpust *now;
	int cpu, first = -1;

	if (!kg_cpu_base)
		return;
	now = kcalloc(nr_cpu_ids, sizeof(*now), GFP_KERNEL);
	if (!now)
		return;

	on_each_cpu(kg_cpust_collect, now, 1);

	for_each_online_cpu(cpu) {
		if (!now[cpu].valid)
			continue;
		if (!kg_cpu_base[cpu].valid) {      /* CPU hot-added after load: trust on first sight */
			kg_cpu_base[cpu] = now[cpu];
			continue;
		}
		kg_cpust_compare(cpu, &kg_cpu_base[cpu], &now[cpu]);
		if (first < 0)
			first = cpu;
	}
	if (kg_idt_enabled && first >= 0)
		kg_idt_verify(&now[first], false);
	kfree(now);
}

static int kg_cpu_state_baseline(void)
{
	struct kg_cpust *now;
	int cpu, first = -1;

	kg_cpu_base = kcalloc(nr_cpu_ids, sizeof(*kg_cpu_base), GFP_KERNEL);
	now = kcalloc(nr_cpu_ids, sizeof(*now), GFP_KERNEL);
	if (!kg_cpu_base || !now) {
		kfree(kg_cpu_base);
		kg_cpu_base = NULL;
		kfree(now);
		return -ENOMEM;
	}
	on_each_cpu(kg_cpust_collect, now, 1);
	for_each_online_cpu(cpu) {
		kg_cpu_base[cpu] = now[cpu];
		if (first < 0 && now[cpu].valid)
			first = cpu;
	}

#ifdef X86_FEATURE_FRED
	kg_idt_enabled = !cpu_feature_enabled(X86_FEATURE_FRED);   /* FRED bypasses the IDT */
#else
	kg_idt_enabled = true;
#endif
	if (kg_idt_enabled && first >= 0) {
		kg_idt_base = kmemdup((void *)now[first].idt_base, 256 * sizeof(gate_desc), GFP_KERNEL);
		if (kg_idt_base)
			kg_idt_verify(&now[first], true);
		else
			kg_idt_enabled = false;
	}
	kfree(now);
	return 0;
}

/*----------------------------------------------------------------------------
 * Module lifecycle (Windows: PsSetLoadImageNotifyRoutine is mentioned in the
 * source comments but never used; the notifier is the real Linux hook)
 *--------------------------------------------------------------------------*/
#define KG_TAINT_SUSPECT   ((1UL << TAINT_UNSIGNED_MODULE) | (1UL << TAINT_FORCED_MODULE))

static void kg_module_add(struct module *mod)
{
	const struct module_memory *mm = &mod->mem[MOD_TEXT];

	if (!kg_text_enabled || !mm->size)
		return;
	if (!p_text_modules && mod != THIS_MODULE)      /* the guard always watches its own text */
		return;
	mutex_lock(&kg_region_lock);
	kg_region_add(mod->name, (unsigned long)mm->base, mm->size, false, mod);
	mutex_unlock(&kg_region_lock);
}

static void kg_module_remove(struct module *mod)
{
	struct kg_region *r, *tmp;

	mutex_lock(&kg_region_lock);
	list_for_each_entry_safe(r, tmp, &kg_regions, node) {
		if (r->mod == mod) {
			kg_region_del(r);
			break;
		}
	}
	mutex_unlock(&kg_region_lock);
}

static int kg_module_notify(struct notifier_block *nb, unsigned long action, void *data)
{
	struct module *mod = data;

	if (mod == THIS_MODULE)
		return NOTIFY_DONE;

	switch (action) {
	case MODULE_STATE_LIVE:
		kg_module_add(mod);
		if (kg_baseline_done) {
			u64 np[2];
			bool signed_ok = module_sig_ok(mod);
			bool suspect = !signed_ok || (mod->taints & KG_TAINT_SUSPECT);

			kg_pack_name(mod->name, np);
			kg_report(KG_ALERT_MODULE_LOADED, suspect ? KG_LEVEL_WATCH : KG_LEVEL_INFO,
				  np[0], np[1], "module %s loaded (%s signature%s)", mod->name,
				  signed_ok ? "valid" : "no valid",
				  (mod->taints & (1UL << TAINT_OOT_MODULE)) ? ", out-of-tree" : "");
		}
		break;
	case MODULE_STATE_GOING:
		kg_module_remove(mod);
		break;
	}
	return NOTIFY_DONE;
}

static struct notifier_block kg_module_nb = { .notifier_call = kg_module_notify };
static bool kg_module_nb_registered;

/*
 * Existing modules: walk the module list starting from our own entry (older
 * modules follow it; the list head is a bare list_head in kernel .data, which
 * is recognised because it is outside the module address range).
 */
#define KG_MAX_BOOT_MODULES 1024

static void kg_enumerate_modules(void)
{
	struct module **held;
	struct module *m;
	int n = 0, i;

	held = kvcalloc(KG_MAX_BOOT_MODULES, sizeof(*held), GFP_KERNEL);
	if (!held)
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(m, &THIS_MODULE->list, list) {
		if (!kg_in_module_area((unsigned long)m))
			break;                  /* reached the list head */
		if (m == THIS_MODULE || m->state != MODULE_STATE_LIVE)
			continue;
		if (n < KG_MAX_BOOT_MODULES && try_module_get(m))
			held[n++] = m;
	}
	rcu_read_unlock();

	for (i = 0; i < n; i++) {
		kg_module_add(held[i]);
		module_put(held[i]);
	}
	kvfree(held);
}

/*----------------------------------------------------------------------------
 * Periodic worker (Windows: IntegrityWorkerThread)
 *--------------------------------------------------------------------------*/
static struct delayed_work kg_integ_work;
static bool kg_integ_stop;
static bool kg_state_corrupt_reported;

static void kg_integ_workfn(struct work_struct *w)
{
	kg_cpu_state_check();
	kg_text_verify_all();

	if (!kg_guard_verify()) {
		if (!kg_state_corrupt_reported) {
			kg_state_corrupt_reported = true;
			kg_report(KG_ALERT_SHARED_STATE_CORRUPT, KG_LEVEL_CRITICAL, 0, 0,
				  "driver policy state failed its integrity check");
		}
	}

	if (!READ_ONCE(kg_integ_stop))
		queue_delayed_work(kg_wq, &kg_integ_work,
				   msecs_to_jiffies(max(kg_integ_interval_ms, 100U)));
}

/*----------------------------------------------------------------------------
 * init / exit (Windows: KernelIntegrityInitialize / Uninitialize)
 *--------------------------------------------------------------------------*/
int kg_integrity_init(void)
{
	int ret;

	ret = kg_cpu_state_baseline();
	if (ret)
		return ret;

	if (p_text && kg_find_text_bounds() == 0) {
		kg_tmp = kvmalloc(KG_CHUNK + KG_OVERLAP, GFP_KERNEL);
		if (kg_tmp) {
			mutex_lock(&kg_region_lock);
			ret = kg_region_add("vmlinux", kg_text_start, kg_text_end - kg_text_start,
					    true, NULL);
			if (!ret)
				kg_text_enabled = true;
			mutex_unlock(&kg_region_lock);
			if (ret)
				pr_warn("cannot baseline kernel text: %d\n", ret);
		}
	}

	if (kg_text_enabled) {
		/* this module's own text: the guard must notice being patched too */
		kg_module_add(THIS_MODULE);
		kg_enumerate_modules();
	}
	/* Load reports do not depend on text monitoring, so the notifier is always installed. */
	if (!register_module_notifier(&kg_module_nb))
		kg_module_nb_registered = true;
	kg_baseline_done = true;

	pr_info("integrity baseline: %u text region(s), %zu KiB, CPU state on %u CPUs%s\n",
		kg_nregions, kg_copy_bytes >> 10, num_online_cpus(),
		kg_idt_enabled ? ", IDT" : "");

	kg_integ_stop = false;
	INIT_DELAYED_WORK(&kg_integ_work, kg_integ_workfn);
	queue_delayed_work(kg_wq, &kg_integ_work, msecs_to_jiffies(kg_integ_interval_ms));
	return 0;
}

void kg_integrity_exit(void)
{
	struct kg_region *r, *tmp;

	if (!kg_cpu_base)
		return;

	if (kg_module_nb_registered)
		unregister_module_notifier(&kg_module_nb);
	WRITE_ONCE(kg_integ_stop, true);
	cancel_delayed_work_sync(&kg_integ_work);

	mutex_lock(&kg_region_lock);
	list_for_each_entry_safe(r, tmp, &kg_regions, node)
		kg_region_del(r);
	mutex_unlock(&kg_region_lock);

	kvfree(kg_tmp);
	kg_tmp = NULL;
	kfree(kg_idt_base);
	kg_idt_base = NULL;
	kfree(kg_cpu_base);
	kg_cpu_base = NULL;
	kg_text_enabled = false;
}
