// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_hw.c - Module 2 (hardware half): PCIe discovery, OS/hardware cross-check
 * and DMA-exposure audit.  Counterpart of the PCI/VT-d parts of
 * windows/src/hw_keylogger_detect.c.  The keyboard-path half is kg_input.c.
 *
 *  Discovery      Walk the PCI tree straight from the ECAM (memory-mapped config
 *                 space) found in the ACPI MCFG table, following bridge
 *                 secondary-bus registers, bypassing the PCI core's own lists.
 *                 (PciGetEcamBaseFromAcpi is an unimplemented stub on Windows.)
 *
 *  Cross-check    Compare that hardware view with the PCI core:
 *                   hidden from the OS   answers in ECAM but is not enumerated
 *                   missing in hardware  enumerated but silent in ECAM
 *                   identity mismatch    vendor/device/class differ between views
 *                 Reported as ALERT_PCI_DISCREPANCY once seen on two consecutive
 *                 scans, so a hot-plug racing the scan is not a false alarm.
 *
 *  DMA audit      A device that is bus-master-enabled (Command.BME, read from
 *                 hardware) and not authorised is a DMA exposure.  Authorised =
 *                 present when the module loaded (trust on first use - the
 *                 README's "clean-boot inventory") or listed in dma_allow=.
 *                 Windows treats every device as unauthorised until listed, so
 *                 with its default empty list the mitigation would cut the boot
 *                 disk; that is not a workable default.
 *                 With enforce=1 the offender's bus mastering is cleared through
 *                 the PCI core, and through a raw ECAM write if the OS view
 *                 disagrees (Windows Tier 2).  Bridges are never touched: they
 *                 must forward their children's DMA.
 *
 *  Not ported: editing VT-d context entries and issuing register-based
 *  invalidations (Windows Tier 1).  The IOMMU belongs to the intel-iommu /
 *  amd-iommu driver, which keeps its own copy of those tables, serialises with
 *  its own locks and uses queued invalidation; poking them from a module races
 *  with it and can bring DMA down for every device.  The IOMMU state is
 *  *audited* through the IOMMU API instead: a device with unrestricted DMA
 *  (no IOMMU domain, or an identity domain) is reported as more severe.
 */
#include "kg.h"

#include <linux/acpi.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

#define KG_MAX_ECAM     16
#define KG_MAX_PCI      1024
#define KG_MAX_SUSPECT  64

struct kg_ecam_seg {
	phys_addr_t base;
	u16 seg;
	u8 bus_start, bus_end;
};

struct kg_pci_ent {
	u16 seg;
	u8  bus, dev, fn;
	u16 vid, did;
	u32 class_rev;          /* class code << 8 | revision, as at config offset 8 */
	u16 cmd;
	u8  hdr;                /* header type incl. multifunction bit */
	bool from_ecam;
};

struct kg_suspect {
	struct kg_pci_ent e;
	u8 kind;                /* KG_PCI_* */
	u8 seen;                /* consecutive scans */
	bool reported;
};

static struct kg_ecam_seg kg_ecam[KG_MAX_ECAM];
static int kg_necam;

static struct kg_pci_ent *kg_cur;       /* latest scan */
static unsigned int kg_ncur;
static struct kg_pci_ent *kg_base;      /* authorised set (TOFU) */
static unsigned int kg_nbase;
static struct kg_suspect kg_susp[KG_MAX_SUSPECT];

/* Per unauthorised bus master: what has already been announced about it. */
struct kg_dma_rec {
	struct kg_pci_ent e;
	bool alerted;                   /* UNAUTHORIZED_DMA raised     */
	bool cleared;                   /* DEVICE_BME_DISABLED raised  */
};
static struct kg_dma_rec kg_dma_recs[KG_MAX_SUSPECT];
static unsigned int kg_ndma;

static struct delayed_work kg_hw_work;
/*
 * True until kg_hw_init() has set the work item up, and again after exit: the posture ladder kicks
 * this monitor on every raise, including while it is still starting or when hw=0 left it off, and
 * a kick must never reach an uninitialised work item.
 */
static bool kg_hw_stop = true;
static bool kg_hw_running;
static struct notifier_block kg_pci_nb;
static bool kg_pci_nb_registered;

bool kg_hw_ecam_active(void)
{
	return kg_hw_running && kg_necam > 0;
}

unsigned int kg_hw_device_count(void)
{
	return READ_ONCE(kg_ncur);
}

static inline u32 kg_bdf(const struct kg_pci_ent *e)
{
	return ((u32)e->seg << 24) | ((u32)e->bus << 16) | ((u32)e->dev << 8) | e->fn;
}

static inline bool kg_same_dev(const struct kg_pci_ent *a, const struct kg_pci_ent *b)
{
	return a->seg == b->seg && a->bus == b->bus && a->dev == b->dev && a->fn == b->fn;
}

static inline bool kg_same_identity(const struct kg_pci_ent *a, const struct kg_pci_ent *b)
{
	return kg_same_dev(a, b) && a->vid == b->vid && a->did == b->did;
}

/*----------------------------------------------------------------------------
 * ECAM location (ACPI MCFG) - Windows: PciGetEcamBaseFromAcpi (stub)
 *--------------------------------------------------------------------------*/
static int kg_ecam_init(void)
{
#ifdef CONFIG_ACPI
	struct acpi_table_header *hdr;
	struct acpi_mcfg_allocation *a;
	int i, n;

	if (acpi_disabled)
		return -ENODEV;
	if (ACPI_FAILURE(acpi_get_table(ACPI_SIG_MCFG, 0, &hdr)))
		return -ENODEV;

	n = (hdr->length - sizeof(struct acpi_table_mcfg)) / sizeof(*a);
	a = (struct acpi_mcfg_allocation *)((u8 *)hdr + sizeof(struct acpi_table_mcfg));
	for (i = 0; i < n && kg_necam < KG_MAX_ECAM; i++) {
		if (!a[i].address || a[i].end_bus_number < a[i].start_bus_number)
			continue;
		kg_ecam[kg_necam].base = a[i].address;
		kg_ecam[kg_necam].seg = a[i].pci_segment;
		kg_ecam[kg_necam].bus_start = a[i].start_bus_number;
		kg_ecam[kg_necam].bus_end = a[i].end_bus_number;
		kg_necam++;
	}
	acpi_put_table(hdr);
	return kg_necam ? 0 : -ENODEV;
#else
	return -ENODEV;
#endif
}

static const struct kg_ecam_seg *kg_ecam_find(u16 seg, u8 bus)
{
	int i;

	for (i = 0; i < kg_necam; i++)
		if (kg_ecam[i].seg == seg && bus >= kg_ecam[i].bus_start && bus <= kg_ecam[i].bus_end)
			return &kg_ecam[i];
	return NULL;
}

/* Map the 1 MiB ECAM window of one bus (uncached). */
static void __iomem *kg_ecam_map(const struct kg_ecam_seg *e, u8 bus)
{
	return ioremap(e->base + ((phys_addr_t)(bus - e->bus_start) << 20), SZ_1M);
}

/*----------------------------------------------------------------------------
 * Tree walk (Windows: PciWalkBusTree, which scans every bus blindly; this one
 * follows bridge secondary-bus registers exactly as the hardware is routed)
 *--------------------------------------------------------------------------*/
static void kg_walk_bus(const struct kg_ecam_seg *e, u8 bus, int depth, unsigned long *visited)
{
	u8 secondaries[32];
	int nsec = 0, i;
	void __iomem *m;
	int dev, fn;

	if (depth > 8 || test_and_set_bit(bus, visited))
		return;
	m = kg_ecam_map(e, bus);
	if (!m)
		return;

	for (dev = 0; dev < 32; dev++) {
		bool multifn = false;

		for (fn = 0; fn < 8; fn++) {
			void __iomem *cfg = m + (dev << 15) + (fn << 12);
			u32 id = readl(cfg + PCI_VENDOR_ID);
			struct kg_pci_ent *ent;
			u8 hdr;

			if ((id & 0xffff) == 0xffff || (id & 0xffff) == 0 || id == 0xffffffff) {
				if (fn == 0)
					break;
				continue;
			}
			hdr = readb(cfg + PCI_HEADER_TYPE);
			if (fn == 0)
				multifn = hdr & 0x80;

			if (kg_ncur < KG_MAX_PCI) {
				ent = &kg_cur[kg_ncur++];
				ent->seg = e->seg;
				ent->bus = bus;
				ent->dev = dev;
				ent->fn = fn;
				ent->vid = id & 0xffff;
				ent->did = id >> 16;
				ent->class_rev = readl(cfg + PCI_CLASS_REVISION);
				ent->cmd = readw(cfg + PCI_COMMAND);
				ent->hdr = hdr;
				ent->from_ecam = true;
			}

			if ((hdr & 0x7f) == PCI_HEADER_TYPE_BRIDGE && nsec < (int)ARRAY_SIZE(secondaries)) {
				u8 sec = readb(cfg + PCI_SECONDARY_BUS);

				if (sec > bus && sec <= e->bus_end)
					secondaries[nsec++] = sec;
			}
			if (fn == 0 && !multifn)
				break;
		}
	}
	iounmap(m);

	for (i = 0; i < nsec; i++)
		kg_walk_bus(e, secondaries[i], depth + 1, visited);
}

static void kg_scan_ecam(void)
{
	unsigned long visited[BITS_TO_LONGS(256)];
	struct pci_bus *pb = NULL;
	int i;

	kg_ncur = 0;
	for (i = 0; i < kg_necam; i++) {
		bitmap_zero(visited, 256);
		kg_walk_bus(&kg_ecam[i], kg_ecam[i].bus_start, 0, visited);

		/* Root buses the OS knows about beyond the first (multi-root platforms). */
		pb = NULL;
		while ((pb = pci_find_next_bus(pb)) != NULL) {
			if (pb->parent || pci_domain_nr(pb) != kg_ecam[i].seg)
				continue;
			if (pb->number >= kg_ecam[i].bus_start && pb->number <= kg_ecam[i].bus_end)
				kg_walk_bus(&kg_ecam[i], pb->number, 0, visited);
		}
	}
}

/* No MCFG: fall back to the OS view so the DMA audit still works. */
static void kg_scan_os(void)
{
	struct pci_dev *pdev = NULL;

	kg_ncur = 0;
	for_each_pci_dev(pdev) {
		struct kg_pci_ent *ent;
		u16 cmd = 0;
		u8 hdr = 0;

		if (pdev->is_virtfn || kg_ncur >= KG_MAX_PCI)
			continue;
		pci_read_config_word(pdev, PCI_COMMAND, &cmd);
		pci_read_config_byte(pdev, PCI_HEADER_TYPE, &hdr);
		ent = &kg_cur[kg_ncur++];
		ent->seg = pci_domain_nr(pdev->bus);
		ent->bus = pdev->bus->number;
		ent->dev = PCI_SLOT(pdev->devfn);
		ent->fn = PCI_FUNC(pdev->devfn);
		ent->vid = pdev->vendor;
		ent->did = pdev->device;
		ent->class_rev = (pdev->class << 8) | pdev->revision;
		ent->cmd = cmd;
		ent->hdr = hdr;
		ent->from_ecam = false;
	}
}

/*----------------------------------------------------------------------------
 * OS <-> hardware cross-check (needs ECAM)
 *--------------------------------------------------------------------------*/

/*
 * A device in D3cold (power removed - typically a hybrid-graphics dGPU) answers
 * config reads with all-ones, exactly like an absent one.  So does everything
 * behind a bridge whose link is down.  Such devices are not "missing".
 */
static bool kg_pdev_powered_off(struct pci_dev *pdev)
{
	struct pci_bus *bus;

	if (pdev->current_state == PCI_D3cold || pci_channel_offline(pdev))
		return true;
	for (bus = pdev->bus; bus && bus->self; bus = bus->parent)
		if (bus->self->current_state == PCI_D3cold)
			return true;
	return false;
}

static void kg_suspect_report(struct kg_suspect *s)
{
	static const char *const what[] = { "?", "answers in hardware but is hidden from the OS",
					    "known to the OS but silent in hardware",
					    "identity differs between hardware and OS" };
	u64 p2 = ((u64)s->kind << 32) | ((u32)s->e.vid << 16) | s->e.did;

	s->reported = true;
	kg_stat_inc(hw_discrepancy_count);
	kg_report(KG_ALERT_PCI_DISCREPANCY,
		  s->kind == KG_PCI_IDENTITY_MISMATCH ? KG_LEVEL_CRITICAL : KG_LEVEL_WATCH,
		  kg_bdf(&s->e), p2, "PCI %04x:%02x:%02x.%x [%04x:%04x] %s",
		  s->e.seg, s->e.bus, s->e.dev, s->e.fn, s->e.vid, s->e.did,
		  s->kind < ARRAY_SIZE(what) ? what[s->kind] : what[0]);
}

/* Note a discrepancy candidate for this scan; alert when it persists. */
static void kg_note_suspect(const struct kg_pci_ent *e, u8 kind, u8 *touched)
{
	int i, free_slot = -1;

	for (i = 0; i < KG_MAX_SUSPECT; i++) {
		struct kg_suspect *s = &kg_susp[i];

		if (!s->seen) {
			if (free_slot < 0)
				free_slot = i;
			continue;
		}
		if (s->kind == kind && kg_same_dev(&s->e, e)) {
			touched[i] = 1;
			if (s->seen < 255)
				s->seen++;
			if (s->seen >= 2 && !s->reported)
				kg_suspect_report(s);
			return;
		}
	}
	if (free_slot >= 0) {
		kg_susp[free_slot].e = *e;
		kg_susp[free_slot].kind = kind;
		kg_susp[free_slot].seen = 1;
		kg_susp[free_slot].reported = false;
		touched[free_slot] = 1;
	}
}

static void kg_cross_check(void)
{
	u8 touched[KG_MAX_SUSPECT] = { };
	struct pci_dev *pdev = NULL;
	unsigned int i;

	/* hardware -> OS */
	for (i = 0; i < kg_ncur; i++) {
		struct kg_pci_ent *e = &kg_cur[i];

		pdev = pci_get_domain_bus_and_slot(e->seg, e->bus, PCI_DEVFN(e->dev, e->fn));
		if (!pdev) {
			kg_note_suspect(e, KG_PCI_HIDDEN_FROM_OS, touched);
			continue;
		}
		if (pdev->vendor != e->vid || pdev->device != e->did ||
		    (pdev->class >> 8) != (e->class_rev >> 16))
			kg_note_suspect(e, KG_PCI_IDENTITY_MISMATCH, touched);
		pci_dev_put(pdev);
	}

	/* OS -> hardware (only where ECAM actually covers the device) */
	pdev = NULL;
	for_each_pci_dev(pdev) {
		bool found = false;
		struct kg_pci_ent probe = { };

		if (pdev->is_virtfn || kg_pdev_powered_off(pdev))
			continue;
		probe.seg = pci_domain_nr(pdev->bus);
		probe.bus = pdev->bus->number;
		probe.dev = PCI_SLOT(pdev->devfn);
		probe.fn = PCI_FUNC(pdev->devfn);
		probe.vid = pdev->vendor;
		probe.did = pdev->device;
		if (!kg_ecam_find(probe.seg, probe.bus))
			continue;
		for (i = 0; i < kg_ncur && !found; i++)
			found = kg_same_dev(&kg_cur[i], &probe);
		if (!found)
			kg_note_suspect(&probe, KG_PCI_MISSING_IN_HW, touched);
	}

	/* a suspect not seen this time has resolved (hot-plug settled) */
	for (i = 0; i < KG_MAX_SUSPECT; i++)
		if (kg_susp[i].seen && !touched[i])
			memset(&kg_susp[i], 0, sizeof(kg_susp[i]));
}

/*----------------------------------------------------------------------------
 * DMA audit
 *--------------------------------------------------------------------------*/
static bool kg_dma_authorized(const struct kg_pci_ent *e)
{
	char bdf[16], id[12];
	unsigned int i;

	for (i = 0; i < kg_nbase; i++)
		if (kg_same_identity(&kg_base[i], e))
			return true;

	snprintf(bdf, sizeof(bdf), "%04x:%02x:%02x.%x", e->seg, e->bus, e->dev, e->fn);
	snprintf(id, sizeof(id), "%04x:%04x", e->vid, e->did);
	return kg_list_contains(kg_dma_allow, bdf) || kg_list_contains(kg_dma_allow, id);
}

/* Returns true when the device sits in a protected IOMMU domain. */
static bool kg_iommu_protected(struct pci_dev *pdev)
{
	struct iommu_domain *dom = iommu_get_domain_for_dev(&pdev->dev);

	return dom && dom->type != IOMMU_DOMAIN_IDENTITY;
}

static bool kg_bme_now(const struct kg_pci_ent *e)
{
	const struct kg_ecam_seg *seg = kg_ecam_find(e->seg, e->bus);
	void __iomem *m;
	u16 cmd;

	if (!seg)
		return false;
	m = kg_ecam_map(seg, e->bus);
	if (!m)
		return false;
	cmd = readw(m + (e->dev << 15) + (e->fn << 12) + PCI_COMMAND);
	iounmap(m);
	return cmd & PCI_COMMAND_MASTER;
}

/* Raw ECAM write of Command with BME cleared (16-bit: Status shares the dword and is write-1-to-clear). */
static bool kg_ecam_clear_master(const struct kg_pci_ent *e)
{
	const struct kg_ecam_seg *seg = kg_ecam_find(e->seg, e->bus);
	void __iomem *m = seg ? kg_ecam_map(seg, e->bus) : NULL;
	void __iomem *reg;

	if (!m)
		return false;
	reg = m + (e->dev << 15) + (e->fn << 12) + PCI_COMMAND;
	writew(readw(reg) & ~PCI_COMMAND_MASTER, reg);
	iounmap(m);
	return !kg_bme_now(e);
}

/* Windows: PciDisableBusMaster.  Tier 1 through the PCI core, Tier 2 raw ECAM. */
static bool kg_disable_bme(const struct kg_pci_ent *e, struct pci_dev *pdev)
{
	if (pdev)
		pci_clear_master(pdev);
	if (!kg_necam)
		return pdev != NULL;            /* no hardware view to verify against */
	if (!kg_bme_now(e))
		return true;
	return kg_ecam_clear_master(e);         /* the OS view disagrees with hardware: write it directly */
}

static struct kg_dma_rec *kg_dma_rec_get(const struct kg_pci_ent *e)
{
	unsigned int i;

	for (i = 0; i < kg_ndma; i++)
		if (kg_same_identity(&kg_dma_recs[i].e, e))
			return &kg_dma_recs[i];
	if (kg_ndma >= KG_MAX_SUSPECT) {
		pr_warn_once("too many unauthorised bus masters to track individually\n");
		return NULL;
	}
	kg_dma_recs[kg_ndma].e = *e;
	kg_dma_recs[kg_ndma].alerted = kg_dma_recs[kg_ndma].cleared = false;
	return &kg_dma_recs[kg_ndma++];
}

/* Forget devices that have left, so a later re-plug is judged afresh. */
static void kg_dma_rec_prune(void)
{
	unsigned int i, j = 0, k;

	for (i = 0; i < kg_ndma; i++) {
		bool present = false;

		for (k = 0; k < kg_ncur && !present; k++)
			present = kg_same_identity(&kg_cur[k], &kg_dma_recs[i].e);
		if (present)
			kg_dma_recs[j++] = kg_dma_recs[i];
	}
	kg_ndma = j;
}

static void kg_dma_audit(void)
{
	unsigned int i;

	for (i = 0; i < kg_ncur; i++) {
		struct kg_pci_ent *e = &kg_cur[i];
		struct kg_dma_rec *rec;
		struct pci_dev *pdev;
		bool open_dma;
		u64 p2;

		/* endpoints only; a bridge without bus mastering would cut off its children */
		if ((e->hdr & 0x7f) != PCI_HEADER_TYPE_NORMAL || !(e->cmd & PCI_COMMAND_MASTER))
			continue;
		if (kg_dma_authorized(e))
			continue;

		pdev = pci_get_domain_bus_and_slot(e->seg, e->bus, PCI_DEVFN(e->dev, e->fn));
		open_dma = !pdev || !kg_iommu_protected(pdev);
		rec = kg_dma_rec_get(e);
		p2 = ((u32)e->vid << 16) | e->did;

		if (rec && !rec->alerted) {
			bool exposed = pdev && (pdev->untrusted || pdev->external_facing ||
						pci_is_thunderbolt_attached(pdev));

			rec->alerted = true;
			kg_stat_inc(hw_dma_violation_count);
			kg_report(KG_ALERT_UNAUTHORIZED_DMA,
				  (exposed && open_dma) ? KG_LEVEL_CRITICAL : KG_LEVEL_WATCH,
				  kg_bdf(e), p2,
				  "unauthorised bus master %04x:%02x:%02x.%x [%04x:%04x]%s%s%s",
				  e->seg, e->bus, e->dev, e->fn, e->vid, e->did,
				  pdev ? "" : " (not enumerated by the OS)",
				  exposed ? ", external-facing" : "",
				  open_dma ? ", no IOMMU translation" : ", behind an IOMMU domain");
		}

		/* Enforcement is re-applied every pass; it is announced once, when it first succeeds. */
		if (kg_enforcing()) {
			if (kg_disable_bme(e, pdev)) {
				if (rec && !rec->cleared) {
					rec->cleared = true;
					kg_report(KG_ALERT_DEVICE_BME_DISABLED, KG_LEVEL_CRITICAL, kg_bdf(e), p2,
						  "bus mastering cleared on %04x:%02x:%02x.%x [%04x:%04x]",
						  e->seg, e->bus, e->dev, e->fn, e->vid, e->did);
				}
			} else {
				pr_err("could not clear bus mastering on %04x:%02x:%02x.%x\n",
				       e->seg, e->bus, e->dev, e->fn);
			}
		}
		if (pdev)
			pci_dev_put(pdev);
	}
	kg_dma_rec_prune();
}

/*
 * The authorised set is what the platform presents at load time: everything the
 * hardware answers for AND everything the OS enumerated.  The second half matters
 * for devices that are powered off right now (see above): without it, a dGPU that
 * wakes up an hour later would look like a brand-new bus master.
 */
static void kg_baseline_add_os_view(void)
{
	struct pci_dev *pdev = NULL;

	for_each_pci_dev(pdev) {
		struct kg_pci_ent e = { };
		unsigned int i;
		bool dup = false;

		if (pdev->is_virtfn)
			continue;
		e.seg = pci_domain_nr(pdev->bus);
		e.bus = pdev->bus->number;
		e.dev = PCI_SLOT(pdev->devfn);
		e.fn = PCI_FUNC(pdev->devfn);
		e.vid = pdev->vendor;
		e.did = pdev->device;
		for (i = 0; i < kg_nbase && !dup; i++)
			dup = kg_same_identity(&kg_base[i], &e);
		if (!dup && kg_nbase < KG_MAX_PCI)
			kg_base[kg_nbase++] = e;
	}
}

/*----------------------------------------------------------------------------
 * Worker (Windows: HwMonitorThreadFunc, every 5 s)
 *--------------------------------------------------------------------------*/
static void kg_hw_scan(void)
{
	if (kg_necam) {
		kg_scan_ecam();
		kg_cross_check();
	} else {
		kg_scan_os();
	}
	kg_dma_audit();
}

static void kg_hw_workfn(struct work_struct *w)
{
	kg_hw_scan();
	if (!READ_ONCE(kg_hw_stop))
		queue_delayed_work(kg_wq, &kg_hw_work,
				   msecs_to_jiffies(kg_scan_ms(kg_hw_interval_ms)));
}

void kg_hw_kick(void)
{
	if (!READ_ONCE(kg_hw_stop))
		mod_delayed_work(kg_wq, &kg_hw_work, 0);
}

static int kg_pci_notify(struct notifier_block *nb, unsigned long action, void *data)
{
	/* A new device, or a driver just bound (which is when BME usually turns on): look soon. */
	if ((action == BUS_NOTIFY_ADD_DEVICE || action == BUS_NOTIFY_BOUND_DRIVER) &&
	    !READ_ONCE(kg_hw_stop))
		mod_delayed_work(kg_wq, &kg_hw_work, msecs_to_jiffies(300));
	return NOTIFY_DONE;
}

/*----------------------------------------------------------------------------
 * init / exit (Windows: HwKeyloggerInitialize / HwKeyloggerUninitialize)
 *--------------------------------------------------------------------------*/
int kg_hw_init(void)
{
	int ret;

	kg_cur = vzalloc(array_size(KG_MAX_PCI, sizeof(*kg_cur)));
	kg_base = vzalloc(array_size(KG_MAX_PCI, sizeof(*kg_base)));
	if (!kg_cur || !kg_base) {
		ret = -ENOMEM;
		goto err;
	}

	ret = kg_ecam_init();
	if (ret) {
		pr_info("ECAM unavailable (%d) - PCI discrepancy detection off, DMA audit uses the OS view\n",
			ret);
		kg_necam = 0;
	} else {
		pr_info("ECAM: %d region(s), first at %pa (bus %u-%u)\n", kg_necam, &kg_ecam[0].base,
			kg_ecam[0].bus_start, kg_ecam[0].bus_end);
	}

	/*
	 * Discover, THEN trust: the first scan is the baseline and must not be audited
	 * against an empty one (that would flag every bus master present at load).
	 * Discrepancies already present are still reported, by the first worker passes.
	 */
	if (kg_necam)
		kg_scan_ecam();
	else
		kg_scan_os();
	memcpy(kg_base, kg_cur, kg_ncur * sizeof(*kg_base));
	kg_nbase = kg_ncur;
	if (kg_necam)
		kg_baseline_add_os_view();
	kg_ndma = 0;
	pr_info("PCI baseline: %u device(s) (%u answering in %s)\n", kg_nbase, kg_ncur,
		kg_necam ? "ECAM, plus the OS view" : "the OS view");

	INIT_DELAYED_WORK(&kg_hw_work, kg_hw_workfn);
	WRITE_ONCE(kg_hw_stop, false);          /* only now may a kick queue it */
	kg_pci_nb.notifier_call = kg_pci_notify;
	if (!bus_register_notifier(&pci_bus_type, &kg_pci_nb))
		kg_pci_nb_registered = true;

	kg_hw_running = true;
	queue_delayed_work(kg_wq, &kg_hw_work, msecs_to_jiffies(kg_scan_ms(kg_hw_interval_ms)));
	return 0;

err:
	vfree(kg_cur);
	vfree(kg_base);
	kg_cur = kg_base = NULL;
	return ret;
}

void kg_hw_exit(void)
{
	if (!kg_hw_running)
		return;

	WRITE_ONCE(kg_hw_stop, true);
	if (kg_pci_nb_registered)
		bus_unregister_notifier(&pci_bus_type, &kg_pci_nb);
	cancel_delayed_work_sync(&kg_hw_work);
	kg_hw_running = false;

	vfree(kg_cur);
	vfree(kg_base);
	kg_cur = kg_base = NULL;
	kg_ncur = kg_nbase = 0;
}
