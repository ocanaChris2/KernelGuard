// SPDX-License-Identifier: GPL-2.0
/*
 * kg_test_tamper.c - TEST FIXTURE, loaded only inside the throw-away VM guest.
 *
 * Deliberately tampers with kernel state so the VM suite can verify that
 * kernelguard notices.  Every action is reversible and is undone on rmmod.
 * Nothing here is installed by any script outside tests/vm.
 *
 *   echo modtext    > /sys/module/kg_test_tamper/parameters/apply   patch this module's own text
 *   echo kerneltext > .../apply                                     patch two padding bytes of vmlinux text
 *   echo cstar      > .../apply                                     change MSR_CSTAR on CPU 1
 *   echo wp         > .../apply                                     clear CR0.WP on CPU 1
 *   echo idt        > .../apply                                     raise the DPL of a (never-raised) IDT gate
 *   echo undo       > .../apply                                     undo whatever is applied
 */
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/smp.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <asm/desc.h>
#include <asm/msr.h>
#include <asm/pgtable.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 15, 0)
#define t_rdmsr(m, v)   rdmsrq((m), *(v))
#define t_wrmsr(m, v)   wrmsrq((m), (v))
#else
#define t_rdmsr(m, v)   rdmsrl((m), *(v))
#define t_wrmsr(m, v)   wrmsrl((m), (v))
#endif

/* Called once at init, never again: its NOP body is what we patch (far from the fentry site). */
static noinline void victim(void)
{
	asm volatile(".rept 64\n\tnop\n\t.endr");
}

static unsigned char *mod_patch;
static unsigned char mod_saved[2];
static unsigned char *kern_patch;
static unsigned char kern_saved[2];
static u64 cstar_saved;
static bool cstar_on, wp_on, idt_on;
static int idt_vec;
static gate_desc idt_saved;

/*
 * Write to read-only kernel memory through a temporary writable alias of its
 * physical page (what text_poke() does with a private mm).  Clearing CR0.WP and
 * writing through the read-only mapping would set the PTE's Dirty bit, which a
 * CET-enabled kernel then mistakes for a shadow-stack page and WARNs about -
 * an artefact of the fixture, not of the driver under test.
 */
static int poke(void *dst, const void *src, size_t n)
{
	unsigned long addr = (unsigned long)dst;
	phys_addr_t pa = slow_virt_to_phys(dst);
	struct page *pg = pfn_to_page(pa >> PAGE_SHIFT);
	void *alias;

	if (offset_in_page(addr) + n > PAGE_SIZE)
		return -EINVAL;
	alias = vmap(&pg, 1, VM_MAP, PAGE_KERNEL);
	if (!alias)
		return -ENOMEM;
	memcpy(alias + offset_in_page(addr), src, n);
	vunmap(alias);
	return 0;
}

static bool va_is_rx(unsigned long va)
{
	unsigned int level;
	pte_t *pte = lookup_address(va, &level);

	return pte && pte_present(*pte) && pte_exec(*pte) && !pte_write(*pte);
}

static unsigned char *find_padding(void)
{
	unsigned long anchor = (unsigned long)&_printk & PAGE_MASK, hi = anchor + PAGE_SIZE, a;
	int run;

	while (va_is_rx(hi))
		hi += PAGE_SIZE;
	/* preferred: 0xcc fill at the very end of the text mapping */
	for (a = hi - 1, run = 0; a > hi - 65536; a--) {
		if (*(unsigned char *)a == 0xcc) {
			if (++run >= 6)
				return (unsigned char *)a;
		} else {
			run = 0;
		}
	}
	/* fallback: any 8-byte int3 run after _printk */
	for (a = anchor; a < anchor + (1UL << 20); a++) {
		if (!memcmp((void *)a, "\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc", 8))
			return (unsigned char *)a;
	}
	return NULL;
}

static void cstar_fn(void *arg)
{
	bool on = *(bool *)arg;

	if (on) {
		t_rdmsr(MSR_CSTAR, &cstar_saved);
		t_wrmsr(MSR_CSTAR, cstar_saved ^ 0x1000);
	} else {
		t_wrmsr(MSR_CSTAR, cstar_saved);
	}
}

static void wp_fn(void *arg)
{
	bool on = *(bool *)arg;
	unsigned long cr0 = read_cr0();

	if (on)
		asm volatile("mov %0, %%cr0" : : "r"(cr0 & ~X86_CR0_WP) : "memory");
	else
		asm volatile("mov %0, %%cr0" : : "r"(cr0 | X86_CR0_WP) : "memory");
}

static void undo(void)
{
	bool off = false;

	if (mod_patch) {
		poke(mod_patch, mod_saved, sizeof(mod_saved));
		mod_patch = NULL;
	}
	if (kern_patch) {
		poke(kern_patch, kern_saved, sizeof(kern_saved));
		kern_patch = NULL;
	}
	if (cstar_on) {
		smp_call_function_single(1, cstar_fn, &off, 1);
		cstar_on = false;
	}
	if (wp_on) {
		smp_call_function_single(1, wp_fn, &off, 1);
		wp_on = false;
	}
	if (idt_on) {
		struct desc_ptr d;

		store_idt(&d);
		poke(&((gate_desc *)d.address)[idt_vec], &idt_saved, sizeof(idt_saved));
		idt_on = false;
	}
}

static int apply_set(const char *val, const struct kernel_param *kp)
{
	bool on = true;
	char cmd[16];

	strscpy(cmd, strim((char *)val), sizeof(cmd));
	if (!strcmp(cmd, "undo")) {
		undo();
		return 0;
	}
	if (!strcmp(cmd, "modtext")) {
		unsigned char evil[2] = { 0x90, 0x91 };

		mod_patch = (unsigned char *)victim + 32;
		memcpy(mod_saved, mod_patch, sizeof(mod_saved));
		poke(mod_patch, evil, sizeof(evil));
	} else if (!strcmp(cmd, "kerneltext")) {
		unsigned char evil[2] = { 0x90, 0x91 };

		kern_patch = find_padding();
		if (!kern_patch) {
			pr_err("kg_test_tamper: no padding found\n");
			return -ENOENT;
		}
		memcpy(kern_saved, kern_patch, sizeof(kern_saved));
		poke(kern_patch, evil, sizeof(evil));
	} else if (!strcmp(cmd, "cstar")) {
		smp_call_function_single(1, cstar_fn, &on, 1);
		cstar_on = true;
	} else if (!strcmp(cmd, "wp")) {
		smp_call_function_single(1, wp_fn, &on, 1);
		wp_on = true;
	} else if (!strcmp(cmd, "idt")) {
		/*
		 * Vector 0xeb is the last external vector below the system vectors and is
		 * never raised in the test guest.  Making it callable from ring 3 is a
		 * realistic IDT tamper that cannot change how a hardware interrupt is
		 * delivered, so it is safe to leave in place for a moment.
		 */
		struct desc_ptr d;
		gate_desc *idt, evil;

		store_idt(&d);
		idt = (gate_desc *)d.address;
		idt_vec = 0xeb;
		idt_saved = idt[idt_vec];
		evil = idt_saved;
		evil.bits.dpl = 3;
		if (poke(&idt[idt_vec], &evil, sizeof(evil)))
			return -EIO;
		idt_on = true;
	} else {
		return -EINVAL;
	}
	pr_info("kg_test_tamper: applied '%s'\n", cmd);
	return 0;
}

static const struct kernel_param_ops apply_ops = { .set = apply_set };
module_param_cb(apply, &apply_ops, NULL, 0200);

static int __init tt_init(void)
{
	victim();       /* keep the symbol referenced */
	return 0;
}

static void __exit tt_exit(void)
{
	undo();
}

module_init(tt_init);
module_exit(tt_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("kernelguard VM test fixture - tampers with kernel state (test guest only)");
