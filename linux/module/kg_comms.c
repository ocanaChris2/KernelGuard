// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_comms.c - Module 5: secure kernel -> user communication.
 * Counterpart of windows/src/secure_comms.c.
 *
 * Two independent channels, as in the Windows driver:
 *
 *  Primary   A page of kernel memory mapped READ-ONLY into the monitor via
 *            mmap() on /dev/kernelguard.  Every notification carries an
 *            HMAC-SHA256 (per-boot key) and a sequence number.  The monitor
 *            reads it without a syscall per alert, so it is not affected by
 *            read()/ioctl() interposition.
 *
 *  Fallback  A kobject uevent (KOBJ_CHANGE on the device) plus the kernel log.
 *            This replaces the Windows "MSR covert channel": writing an
 *            arbitrary MSR is a #GP on almost every CPU, there was no reader
 *            for it, and on Linux a write to an implemented-but-unrelated MSR
 *            would corrupt CPU state.  uevents reach udev/systemd/desktop
 *            tooling with no polling and no dependence on our device node.
 *            They deliberately carry only type/level/sequence - uevents are
 *            world-readable - never addresses or parameters.
 *
 * Improvements over the Windows ring:
 *   - publication protocol: a slot's 'magic' is 0 while being rewritten and is
 *     release-stored last, so a reader detects torn reads (the Windows writer
 *     could advance WriteIndex before an earlier concurrent writer finished);
 *   - key from get_random_bytes() rather than RDTSC ^ system time;
 *   - the mapping cannot be made writable, the key ioctl needs CAP_SYS_ADMIN,
 *     and the key is wiped on unload.
 */
#include "kg.h"

#include <crypto/hash.h>
#include <linux/capability.h>
#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/kobject.h>
#include <linux/mm.h>
#include <linux/nospec.h>
#include <linux/poll.h>
#include <linux/random.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/wait.h>

static_assert(sizeof(struct kg_notification) == 72);
static_assert(offsetof(struct kg_notification, hmac) == KG_HMAC_AUTH_LEN);
static_assert(sizeof(struct kg_shared_region) == 16 + 72 * KG_NOTIFY_SLOTS);
static_assert(sizeof(struct kg_shared_region) <= PAGE_SIZE);

#define KG_RL_BURST         32U
#define KG_RL_INTERVAL_NS   (100ULL * NSEC_PER_MSEC)   /* 10 alerts/s sustained */

struct kg_comms {
	struct page *page;
	struct kg_shared_region *ring;
	struct crypto_shash *tfm;
	u8 key[KG_HMAC_KEY_SIZE];

	spinlock_t lock;                /* serialises slot allocation + publish */
	wait_queue_head_t wq;

	u64 rl_last_ns;                 /* token bucket for non-critical alerts */
	u32 rl_tokens;

	struct work_struct uevent_work; /* fallback channel */
	u32 ue_cursor;
	struct device *dev;
};

static struct kg_comms *kc;

/*----------------------------------------------------------------------------
 * Rate limiter (lock held).  Critical alerts always bypass it.
 *--------------------------------------------------------------------------*/
static bool kg_rl_allow(void)
{
	u64 now = ktime_get_ns();
	u64 add = (now - kc->rl_last_ns) / KG_RL_INTERVAL_NS;

	if (add) {
		kc->rl_tokens = min_t(u64, KG_RL_BURST, kc->rl_tokens + add);
		kc->rl_last_ns += add * KG_RL_INTERVAL_NS;
	}
	if (!kc->rl_tokens)
		return false;
	kc->rl_tokens--;
	return true;
}

/*----------------------------------------------------------------------------
 * Fallback channel: uevents, emitted from a work item because
 * kobject_uevent_env() allocates and may sleep.
 *--------------------------------------------------------------------------*/
static void kg_uevent_workfn(struct work_struct *work)
{
	struct kg_comms *c = kc;
	u32 end, i;

	if (!c)
		return;

	for (;;) {
		struct kg_notification snap;
		struct device *dev;
		char e_alert[40], e_level[40], e_seq[40];
		char *envp[] = { e_alert, e_level, e_seq, NULL };
		unsigned long flags;
		bool valid;

		spin_lock_irqsave(&c->lock, flags);
		dev = c->dev;
		end = c->ring->write_index;
		i = c->ue_cursor;
		if (!dev || i == end) {
			spin_unlock_irqrestore(&c->lock, flags);
			return;
		}
		if (end - i > KG_NOTIFY_SLOTS)      /* lapped: skip what was overwritten */
			i = end - KG_NOTIFY_SLOTS;
		snap = c->ring->notifications[i % KG_NOTIFY_SLOTS];
		c->ue_cursor = i + 1;
		valid = snap.magic == KG_NOTIFY_MAGIC && snap.sequence == i;
		spin_unlock_irqrestore(&c->lock, flags);

		if (!valid || snap.alert_level < KG_LEVEL_WATCH)
			continue;

		snprintf(e_alert, sizeof(e_alert), "KERNELGUARD_ALERT=0x%04x", snap.alert_type);
		snprintf(e_level, sizeof(e_level), "KERNELGUARD_LEVEL=%u", snap.alert_level);
		snprintf(e_seq, sizeof(e_seq), "KERNELGUARD_SEQ=%u", snap.sequence);

		if (!kobject_uevent_env(&dev->kobj, KOBJ_CHANGE, envp))
			kg_stat_inc(fallback_signals_sent);
	}
}

void kg_comms_set_device(struct device *dev)
{
	unsigned long flags;

	if (!kc)
		return;
	spin_lock_irqsave(&kc->lock, flags);
	kc->dev = dev;
	spin_unlock_irqrestore(&kc->lock, flags);

	if (dev)
		queue_work(kg_wq, &kc->uevent_work);   /* flush anything raised during init */
	else
		cancel_work_sync(&kc->uevent_work);    /* a running instance may hold the old dev */
}

/*----------------------------------------------------------------------------
 * kg_comms_notify (Windows: SecureCommNotify)
 *--------------------------------------------------------------------------*/
int kg_comms_notify(u32 type, u32 level, u64 p1, u64 p2)
{
	struct kg_notification n = { }, *dst;
	struct kg_shared_region *r;
	unsigned long flags;
	u32 seq, slot;
	int ret;

	if (!kc)
		return -ENODEV;
	r = kc->ring;

	n.magic       = KG_NOTIFY_MAGIC;
	n.alert_type  = type;
	n.alert_level = level;
	n.timestamp   = ktime_get_real_ns();
	n.param1      = p1;
	n.param2      = p2;

	spin_lock_irqsave(&kc->lock, flags);

	if (level < KG_LEVEL_CRITICAL && !kg_rl_allow()) {
		spin_unlock_irqrestore(&kc->lock, flags);
		kg_stat_inc(notifications_dropped);
		return -EBUSY;
	}

	seq = r->driver_nonce++;
	n.sequence = seq;

	ret = crypto_shash_tfm_digest(kc->tfm, (const u8 *)&n, KG_HMAC_AUTH_LEN, n.hmac);
	if (ret) {
		r->driver_nonce--;
		spin_unlock_irqrestore(&kc->lock, flags);
		pr_err("HMAC computation failed: %d\n", ret);
		return ret;
	}

	/* Spectre-v1 style clamp mirrors SafeArrayIndex() use in the Windows ring code. */
	slot = array_index_nospec(seq % KG_NOTIFY_SLOTS, KG_NOTIFY_SLOTS);

	/*
	 * Seqlock-style publish, paired with the reader in kgmon.c (read_slot):
	 *   1. magic = 0            readers that see this treat the slot as being rewritten
	 *   2. smp_wmb()            the invalidation is visible before any field changes,
	 *                           so a reader can never pair the OLD magic with NEW fields
	 *   3. fill the fields
	 *   4. release-store magic  the fields are visible before the slot looks valid
	 *   5. release-store write_index   ...and before it is counted as published
	 * The reader does the mirror image: acquire-load magic, copy, fence, re-read magic.
	 */
	dst = &r->notifications[slot];
	WRITE_ONCE(dst->magic, 0);
	smp_wmb();      /* invalidation visible before the fields change (pairs with reader fence) */
	dst->sequence    = n.sequence;
	dst->alert_type  = n.alert_type;
	dst->alert_level = n.alert_level;
	dst->timestamp   = n.timestamp;
	dst->param1      = n.param1;
	dst->param2      = n.param2;
	memcpy(dst->hmac, n.hmac, sizeof(dst->hmac));
	/* fields visible before the slot looks valid (pairs with the reader's acquire of magic) */
	smp_store_release(&dst->magic, KG_NOTIFY_MAGIC);
	/* ...and before it is counted as published (pairs with acquire of write_index) */
	smp_store_release(&r->write_index, seq + 1);

	spin_unlock_irqrestore(&kc->lock, flags);

	kg_stat_inc(notifications_sent);
	wake_up_interruptible(&kc->wq);
	if (level >= KG_LEVEL_WATCH)
		queue_work(kg_wq, &kc->uevent_work);
	return 0;
}

/*----------------------------------------------------------------------------
 * File-operation helpers used by kg_main.c
 *--------------------------------------------------------------------------*/
int kg_comms_get_key(u8 out[KG_HMAC_KEY_SIZE])
{
	if (!kc)
		return -ENODEV;
	/* The device node is 0600, but do not rely on that alone. */
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	memcpy(out, kc->key, KG_HMAC_KEY_SIZE);
	return 0;
}

int kg_comms_mmap(struct vm_area_struct *vma)
{
	unsigned long len = vma->vm_end - vma->vm_start;

	if (!kc)
		return -ENODEV;
	if (vma->vm_pgoff != 0 || len > PAGE_SIZE)
		return -EINVAL;
	if (vma->vm_flags & VM_WRITE)
		return -EPERM;                  /* the ring is kernel-write, user-read */

	vm_flags_clear(vma, VM_MAYWRITE);       /* no later mprotect(PROT_WRITE) either */
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

	/*
	 * vm_insert_page() takes a reference, so a lingering mapping stays valid
	 * even if the module is unloaded after the monitor closed the fd.
	 */
	return vm_insert_page(vma, vma->vm_start, kc->page);
}

void kg_comms_open(u32 *seen)
{
	/* acquire: pairs with the release-store of write_index in kg_comms_notify() */
	*seen = kc ? smp_load_acquire(&kc->ring->write_index) : 0;
}

__poll_t kg_comms_poll(struct file *file, struct poll_table_struct *wait)
{
	u32 *seen = file->private_data;
	u32 w;

	if (!kc)
		return EPOLLERR;

	poll_wait(file, &kc->wq, wait);         /* registered BEFORE the check: no lost wake-up */
	/* acquire: pairs with the release-store of write_index in kg_comms_notify() */
	w = smp_load_acquire(&kc->ring->write_index);
	if (w != READ_ONCE(*seen)) {
		WRITE_ONCE(*seen, w);
		return EPOLLIN | EPOLLRDNORM;
	}
	return 0;
}

/*----------------------------------------------------------------------------
 * init / exit (Windows: SecureCommInitialize / SecureCommUninitialize)
 *--------------------------------------------------------------------------*/
int kg_comms_init(void)
{
	int ret;

	kc = kg_sens_alloc(sizeof(*kc), KG_SENS_KEY_MATERIAL);
	if (!kc)
		return -ENOMEM;

	spin_lock_init(&kc->lock);
	init_waitqueue_head(&kc->wq);
	INIT_WORK(&kc->uevent_work, kg_uevent_workfn);
	kc->rl_tokens = KG_RL_BURST;
	kc->rl_last_ns = ktime_get_ns();

	kc->page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!kc->page) {
		ret = -ENOMEM;
		goto err_free;
	}
	kc->ring = page_address(kc->page);

	kc->tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(kc->tfm)) {
		ret = PTR_ERR(kc->tfm);
		kc->tfm = NULL;
		pr_err("cannot allocate hmac(sha256): %d\n", ret);
		goto err_page;
	}

	get_random_bytes(kc->key, sizeof(kc->key));
	ret = crypto_shash_setkey(kc->tfm, kc->key, sizeof(kc->key));
	if (ret) {
		pr_err("cannot key hmac(sha256): %d\n", ret);
		goto err_tfm;
	}

	pr_info("secure channel ready (ring %zu bytes, %d slots)\n",
		sizeof(struct kg_shared_region), KG_NOTIFY_SLOTS);
	return 0;

err_tfm:
	crypto_free_shash(kc->tfm);
err_page:
	__free_page(kc->page);
err_free:
	kg_sens_free(kc);
	kc = NULL;
	return ret;
}

void kg_comms_exit(void)
{
	struct kg_comms *c = kc;

	if (!c)
		return;

	kg_comms_set_device(NULL);
	cancel_work_sync(&c->uevent_work);
	kc = NULL;

	crypto_free_shash(c->tfm);
	/* A lingering user mapping keeps its own page reference; give it zeros. */
	memzero_explicit(c->ring, PAGE_SIZE);
	__free_page(c->page);
	memzero_explicit(c->key, sizeof(c->key));
	kg_sens_free(c);
}
