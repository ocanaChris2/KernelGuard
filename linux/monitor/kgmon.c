// SPDX-License-Identifier: GPL-2.0-only
/*
 * kgmon.c - KernelGuard monitor for Linux.
 * Counterpart of windows/usermode/{main,driver_comm,log_window}.c.
 *
 * The Windows monitor is a tray application: a polling thread validates each
 * notification's HMAC and raises a balloon.  This is the terminal / service
 * equivalent:
 *
 *   kgmon                  follow alerts (backlog first), verify every HMAC
 *   kgmon status           driver state, per-CPU mitigation table, counters
 *   kgmon posture [set L]  graduated-response posture: show it, or step it (root)
 *   kgmon selftest         SHA-256 / HMAC-SHA256 known-answer tests
 *   kgmon run --sensitive -- CMD...
 *                          exec CMD with the kernel's native per-task
 *                          mitigations enabled (see cmd_run())
 *
 * Alert delivery: stdout, optional CSV log (same columns as the Windows
 * "Save Log" file), optional syslog, optional desktop notification.
 *
 * Protocol (kernelguard_uapi.h): the ring is mapped read-only; slot N%16 holds
 * notification N.  A slot is valid while its magic is KG_NOTIFY_MAGIC and is
 * re-checked after copying (seqlock).  Gaps and torn reads are distinguished
 * from forgeries so an overrun is not misreported as an HMAC failure.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <inttypes.h>
#include <poll.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <linux/prctl.h>

#include "kernelguard_uapi.h"
#include "kg_hmac.h"

_Static_assert(sizeof(struct kg_notification) == 72, "notification layout");
_Static_assert(offsetof(struct kg_notification, hmac) == KG_HMAC_AUTH_LEN, "hmac offset");
_Static_assert(sizeof(struct kg_shared_region) == 16 + 72 * KG_NOTIFY_SLOTS, "ring layout");

#define KGMON_VERSION   "1.0.0-linux"
#define POLL_MS         150         /* Windows POLL_INTERVAL_MS */

/* PIDTYPE_TGID is a kernel-internal enum value; prctl(PR_SCHED_CORE) wants it. */
#ifndef PIDTYPE_TGID_UAPI
#define PIDTYPE_TGID_UAPI   1
#endif

static volatile sig_atomic_t g_stop;

struct opts {
	const char *device;
	const char *logfile;
	const char *notify_user;
	int  use_syslog;
	int  use_notify;
	int  once;                  /* drain backlog then exit                     */
	int  new_only;              /* skip the backlog                            */
	int  quiet;
	long max_alerts;            /* exit after this many alerts (0 = never)     */
};

/*----------------------------------------------------------------------------
 * Small helpers
 *--------------------------------------------------------------------------*/
static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "kgmon: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

static const char *level_text(uint32_t l)
{
	switch (l) {
	case KG_LEVEL_INFO:  return "Info";
	case KG_LEVEL_WATCH: return "Warning";
	default:             return "CRITICAL";
	}
}

static const char *strategy_text(uint32_t s)
{
	static const char *const n[] = { "none", "verw", "l1d-flush", "verw+l1d", "full-spectrum" };

	return s < sizeof(n) / sizeof(n[0]) ? n[s] : "?";
}

static const char *posture_text(uint32_t p)
{
	static const char *const n[KG_POSTURE_COUNT] = { "NORMAL", "ELEVATED", "HIGH", "FAIL-SAFE" };

	return p < KG_POSTURE_COUNT ? n[p] : "?";
}

/* "normal", "elevated", "high", "failsafe" / "fail-safe", or 0-3. */
static int parse_posture(const char *s)
{
	static const struct { const char *name; int v; } t[] = {
		{ "normal", KG_POSTURE_NORMAL }, { "elevated", KG_POSTURE_ELEVATED },
		{ "high", KG_POSTURE_HIGH }, { "failsafe", KG_POSTURE_FAILSAFE },
		{ "fail-safe", KG_POSTURE_FAILSAFE },
	};

	for (size_t i = 0; i < sizeof(t) / sizeof(t[0]); i++)
		if (!strcasecmp(s, t[i].name))
			return t[i].v;
	if (s[0] >= '0' && s[0] < '0' + KG_POSTURE_COUNT && !s[1])
		return s[0] - '0';
	return -1;
}

/* Handler / module names travel in Param1|Param2 as 16 bytes of ASCII. */
static void unpack_name(uint64_t p1, uint64_t p2, char out[17])
{
	memcpy(out, &p1, 8);
	memcpy(out + 8, &p2, 8);
	out[16] = '\0';
	for (int i = 0; i < 16; i++)
		if (out[i] && (out[i] < 0x20 || out[i] > 0x7e))
			out[i] = '?';
}

static const char *alert_text(uint32_t t)
{
	switch (t) {
	case KG_ALERT_PMU_L1D_ANOMALY:         return "L1D Cache Attack Pattern";
	case KG_ALERT_PMU_L2_ANOMALY:          return "LLC Cache Attack Pattern";
	case KG_ALERT_PMU_RDTSC_RATE:          return "Timing Reconnaissance (RDTSC)";
	case KG_ALERT_UNAUTHORIZED_KBD_FILTER: return "Unauthorized Keyboard Filter";
	case KG_ALERT_UNAUTHORIZED_DMA:        return "Unauthorized DMA Access";
	case KG_ALERT_PCI_DISCREPANCY:         return "PCIe Device Discrepancy";
	case KG_ALERT_KBD_FILTER_NEUTRALIZED:  return "Keyboard Filter Neutralized";
	case KG_ALERT_DMA_BLOCKED_IOMMU:       return "DMA Blocked (IOMMU)";
	case KG_ALERT_DEVICE_BME_DISABLED:     return "PCIe Bus Master Disabled";
	case KG_ALERT_IDT_HOOK:                return "IDT Hook Detected";
	case KG_ALERT_DISPATCH_HOOK:           return "Input Callback Hook";
	case KG_ALERT_TEXT_PATCH:              return "Kernel .text Patched";
	case KG_ALERT_CTRL_REG_TAMPER:         return "CPU Control State Tampered";
	case KG_ALERT_MODULE_LOADED:           return "Kernel Module Loaded";
	case KG_ALERT_SHARED_STATE_CORRUPT:    return "Driver State Corrupted";
	case KG_ALERT_FAIL_SAFE_ENTERED:       return "CRITICAL: Fail-Safe Mode";
	case KG_ALERT_POSTURE_CHANGED:         return "Response Posture Changed";
	default:                               return "Unknown Alert";
	}
}

static void format_details(const struct kg_notification *n, char *out, size_t len)
{
	char name[17];
	uint64_t p1 = n->param1, p2 = n->param2;

	switch (n->alert_type) {
	case KG_ALERT_PMU_L1D_ANOMALY:
	case KG_ALERT_PMU_L2_ANOMALY:
		snprintf(out, len, "offender tgid: %" PRIu64 "  cpu: %u  overflows/s: %u",
			 p1, (unsigned)(p2 >> 32), (unsigned)(p2 & 0xffffffffu));
		break;
	case KG_ALERT_UNAUTHORIZED_KBD_FILTER:
	case KG_ALERT_KBD_FILTER_NEUTRALIZED:
	case KG_ALERT_MODULE_LOADED:
		unpack_name(p1, p2, name);
		snprintf(out, len, "name: \"%s\"", name);
		break;
	case KG_ALERT_UNAUTHORIZED_DMA:
	case KG_ALERT_DEVICE_BME_DISABLED:
		snprintf(out, len, "%04x:%02x:%02x.%x  id %04x:%04x",
			 (unsigned)(p1 >> 24) & 0xffff, (unsigned)(p1 >> 16) & 0xff,
			 (unsigned)(p1 >> 8) & 0xff, (unsigned)p1 & 0xf,
			 (unsigned)(p2 >> 16) & 0xffff, (unsigned)p2 & 0xffff);
		break;
	case KG_ALERT_PCI_DISCREPANCY: {
		static const char *const k[] = { "?", "hidden from OS", "missing in hardware",
						 "identity mismatch" };
		unsigned kind = (unsigned)(p2 >> 32);

		snprintf(out, len, "%04x:%02x:%02x.%x  %s  id %04x:%04x",
			 (unsigned)(p1 >> 24) & 0xffff, (unsigned)(p1 >> 16) & 0xff,
			 (unsigned)(p1 >> 8) & 0xff, (unsigned)p1 & 0xf,
			 kind < 4 ? k[kind] : "?",
			 (unsigned)(p2 >> 16) & 0xffff, (unsigned)p2 & 0xffff);
		break;
	}
	case KG_ALERT_IDT_HOOK:
		snprintf(out, len, "Handler: 0x%016" PRIx64 "  vector: %" PRIu64, p1, p2);
		break;
	case KG_ALERT_DISPATCH_HOOK:
		snprintf(out, len, "Callback: 0x%016" PRIx64 "  kind: %" PRIu64, p1, p2 >> 32);
		break;
	case KG_ALERT_TEXT_PATCH:
		snprintf(out, len, "Addr: 0x%016" PRIx64 "  Len: %u%s%s%s", p1,
			 (unsigned)(p2 & 0xffffffffu),
			 (p2 >> 32) & KG_TEXTF_KERNEL ? "  [kernel]" : "  [module]",
			 (p2 >> 32) & KG_TEXTF_UNKNOWN_TARGET ? " [unknown branch target]" : "",
			 (p2 >> 32) & KG_TEXTF_BREAKPOINT ? " [int3]" : "");
		break;
	case KG_ALERT_CTRL_REG_TAMPER:
		snprintf(out, len, "cpu %u  reg 0x%x  new 0x%" PRIx64,
			 (unsigned)(p1 >> 32), (unsigned)(p1 & 0xffffffffu), p2);
		break;
	case KG_ALERT_POSTURE_CHANGED:
		snprintf(out, len, "%s -> %s  (%s)", posture_text((unsigned)(p1 >> 32)),
			 posture_text((unsigned)(p1 & 0xffffffffu)),
			 (p2 >> 32) == KG_POSTURE_WHY_DECAY ? "quiet period elapsed" : "operator request");
		break;
	default:
		snprintf(out, len, "Param1: 0x%" PRIx64 "  Param2: 0x%" PRIx64, p1, p2);
		break;
	}
}

/*----------------------------------------------------------------------------
 * Output sinks
 *--------------------------------------------------------------------------*/
static void ts_string(uint64_t ns, char *buf, size_t len)
{
	time_t sec = (time_t)(ns / 1000000000ull);
	unsigned ms = (unsigned)((ns % 1000000000ull) / 1000000ull);
	struct tm tm;
	char base[32];

	localtime_r(&sec, &tm);
	strftime(base, sizeof(base), "%Y-%m-%d %H:%M:%S", &tm);
	snprintf(buf, len, "%s.%03u", base, ms);
}

static void csv_field(FILE *f, const char *s)
{
	fputc('"', f);
	for (; *s; s++) {
		if (*s == '"')
			fputc('"', f);
		fputc(*s, f);
	}
	fputc('"', f);
}

static void notify_desktop(const struct opts *o, const char *title, const char *body)
{
	pid_t pid = fork();

	if (pid != 0)
		return;             /* parent (SIGCHLD is ignored, so no zombie) */

	if (o->notify_user && geteuid() == 0) {
		struct passwd *pw = getpwnam(o->notify_user);
		char bus[128], run[64];

		if (!pw) {
			char *end;
			unsigned long uid = strtoul(o->notify_user, &end, 10);

			pw = *end ? NULL : getpwuid((uid_t)uid);
		}
		if (!pw)
			_exit(2);
		snprintf(run, sizeof(run), "/run/user/%u", (unsigned)pw->pw_uid);
		snprintf(bus, sizeof(bus), "unix:path=%s/bus", run);
		if (initgroups(pw->pw_name, pw->pw_gid) || setgid(pw->pw_gid) || setuid(pw->pw_uid))
			_exit(3);
		setenv("XDG_RUNTIME_DIR", run, 1);
		setenv("DBUS_SESSION_BUS_ADDRESS", bus, 1);
	}
	execlp("notify-send", "notify-send", "-a", "KernelGuard", "-u", "critical",
	       title, body, (char *)NULL);
	_exit(127);
}

struct sinks {
	struct opts o;
	FILE *log;
	long shown;
};

static void emit(struct sinks *s, const struct kg_notification *n, int hmac_ok)
{
	char ts[48], details[192], line[512];

	ts_string(n->timestamp, ts, sizeof(ts));
	format_details(n, details, sizeof(details));

	snprintf(line, sizeof(line), "%s [%-8s] %-32s HMAC=%s seq=%u  %s",
		 ts, level_text(n->alert_level), alert_text(n->alert_type),
		 hmac_ok ? "OK" : "FAIL", n->sequence, details);
	if (!s->o.quiet) {
		puts(line);
		fflush(stdout);
	}

	if (s->log) {
		fprintf(s->log, "%s,%s,", ts, level_text(n->alert_level));
		csv_field(s->log, alert_text(n->alert_type));
		fprintf(s->log, ",%s,%u,0x%016" PRIx64 ",0x%016" PRIx64 ",",
			hmac_ok ? "OK" : "FAIL", n->sequence,
			(uint64_t)n->param1, (uint64_t)n->param2);
		csv_field(s->log, details);
		fputc('\n', s->log);
		fflush(s->log);
	}

	if (s->o.use_syslog)
		syslog(n->alert_level >= KG_LEVEL_CRITICAL ? LOG_CRIT :
		       n->alert_level == KG_LEVEL_WATCH ? LOG_WARNING : LOG_INFO,
		       "%s: %s (hmac %s, seq %u)", alert_text(n->alert_type), details,
		       hmac_ok ? "ok" : "FAILED", n->sequence);

	/* Windows raises a balloon for level >= 1, and a second one when the HMAC fails. */
	if (s->o.use_notify && n->alert_level >= KG_LEVEL_WATCH) {
		char body[256];

		snprintf(body, sizeof(body), "%s\n%s", alert_text(n->alert_type), details);
		notify_desktop(&s->o, n->alert_level >= KG_LEVEL_CRITICAL ?
			       "Critical Security Alert" : "Security Warning", body);
	}
	if (s->o.use_notify && !hmac_ok)
		notify_desktop(&s->o, "Notification Integrity Warning",
			       "Alert HMAC validation failed - notification may be forged.");

	s->shown++;
}

/*----------------------------------------------------------------------------
 * Ring reader
 *--------------------------------------------------------------------------*/
enum slot_result { SLOT_OK, SLOT_RETRY, SLOT_BAD };

static enum slot_result read_slot(const struct kg_shared_region *r, uint32_t seq,
				  struct kg_notification *out)
{
	const struct kg_notification *s = &r->notifications[seq % KG_NOTIFY_SLOTS];
	uint32_t m1 = __atomic_load_n(&s->magic, __ATOMIC_ACQUIRE);
	uint32_t m2;

	if (m1 != KG_NOTIFY_MAGIC)
		return SLOT_RETRY;              /* being rewritten */
	memcpy(out, s, sizeof(*out));
	__atomic_thread_fence(__ATOMIC_ACQUIRE);
	m2 = __atomic_load_n(&s->magic, __ATOMIC_RELAXED);
	if (m2 != KG_NOTIFY_MAGIC)
		return SLOT_RETRY;
	return out->sequence == seq ? SLOT_OK : SLOT_BAD;
}

static void drain(struct sinks *s, const struct kg_shared_region *r,
		  const uint8_t *key, uint32_t *cursor)
{
	uint32_t w = __atomic_load_n(&r->write_index, __ATOMIC_ACQUIRE);

	if (w - *cursor > KG_NOTIFY_SLOTS) {
		fprintf(stderr, "kgmon: ring overrun - %u notification(s) lost\n",
			w - *cursor - KG_NOTIFY_SLOTS);
		*cursor = w - KG_NOTIFY_SLOTS;
	}

	while (*cursor != w && !g_stop) {
		struct kg_notification n;
		enum slot_result res = SLOT_RETRY;
		int tries;

		for (tries = 0; tries < 50 && res == SLOT_RETRY; tries++) {
			res = read_slot(r, *cursor, &n);
			if (res == SLOT_RETRY)
				usleep(200);
		}

		if (res == SLOT_OK) {
			uint8_t mac[KG_HMAC_SIZE];
			int ok;

			kg_hmac_sha256(key, KG_HMAC_KEY_SIZE, &n, KG_HMAC_AUTH_LEN, mac);
			ok = kg_ct_equal(mac, n.hmac, KG_HMAC_SIZE);
			emit(s, &n, ok);
		} else {
			/* A valid slot with the wrong sequence number, after the kernel
			 * said it was published, is not a race: report it. */
			uint32_t w2 = __atomic_load_n(&r->write_index, __ATOMIC_ACQUIRE);

			if (w2 - *cursor > KG_NOTIFY_SLOTS - 1)
				fprintf(stderr, "kgmon: notification %u overwritten before it could be read\n", *cursor);
			else
				fprintf(stderr, "kgmon: TAMPER? slot for notification %u is unreadable or has a wrong sequence number\n", *cursor);
		}
		(*cursor)++;
		if (s->o.max_alerts && s->shown >= s->o.max_alerts)
			g_stop = 1;
	}
}

/*----------------------------------------------------------------------------
 * Connection
 *--------------------------------------------------------------------------*/
struct conn {
	int fd;
	struct kg_shared_region *ring;
	uint8_t key[KG_HMAC_KEY_SIZE];
};

static void conn_open(struct conn *c, const char *dev)
{
	struct kg_hmac_key k;
	void *m;

	c->fd = open(dev, O_RDONLY | O_CLOEXEC);
	if (c->fd < 0) {
		if (errno == ENOENT)
			die("%s not found - is the kernelguard module loaded?", dev);
		die("cannot open %s: %s", dev, strerror(errno));
	}
	if (ioctl(c->fd, KG_IOC_GET_HMAC_KEY, &k) < 0)
		die("KG_IOC_GET_HMAC_KEY: %s (root / CAP_SYS_ADMIN required)", strerror(errno));
	memcpy(c->key, k.key, sizeof(c->key));
	memset(&k, 0, sizeof(k));

	m = mmap(NULL, sizeof(struct kg_shared_region), PROT_READ, MAP_SHARED, c->fd, 0);
	if (m == MAP_FAILED)
		die("mmap ring: %s", strerror(errno));
	c->ring = m;
}

/*----------------------------------------------------------------------------
 * Sub-commands
 *--------------------------------------------------------------------------*/
static int cmd_monitor(struct opts *o)
{
	struct sinks s = { .o = *o };
	struct conn c;
	uint32_t cursor;
	struct sigaction sa = { .sa_handler = on_signal };
	int lock_fd;

	/* Windows: single-instance mutex. */
	lock_fd = open("/run/kernelguard-monitor.lock", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
	if (lock_fd >= 0 && flock(lock_fd, LOCK_EX | LOCK_NB) < 0)
		die("another kgmon instance is already running");

	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);

	if (o->logfile) {
		struct stat st;

		s.log = fopen(o->logfile, "a");
		if (!s.log)
			die("cannot open log %s: %s", o->logfile, strerror(errno));
		if (fstat(fileno(s.log), &st) == 0 && st.st_size == 0)
			fputs("Time,Level,AlertType,HMAC,Seq,Param1,Param2,Details\n", s.log);
	}
	if (o->use_syslog)
		openlog("kernelguard", LOG_PID, LOG_AUTHPRIV);

	conn_open(&c, o->device);

	{
		uint32_t w = __atomic_load_n(&c.ring->write_index, __ATOMIC_ACQUIRE);

		cursor = o->new_only ? w : (w > KG_NOTIFY_SLOTS ? w - KG_NOTIFY_SLOTS : 0);
	}
	if (!o->quiet) {
		fprintf(stderr, "kgmon %s: monitoring %s (%s)\n", KGMON_VERSION, o->device,
			o->once ? "backlog only" : "Ctrl-C to stop");
	}

	drain(&s, c.ring, c.key, &cursor);
	while (!g_stop && !o->once) {
		struct pollfd pfd = { .fd = c.fd, .events = POLLIN };
		int r = poll(&pfd, 1, POLL_MS);

		if (r < 0 && errno != EINTR)
			die("poll: %s", strerror(errno));
		if (r > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
			die("device error");
		drain(&s, c.ring, c.key, &cursor);
	}

	if (s.log)
		fclose(s.log);
	memset(c.key, 0, sizeof(c.key));
	return 0;
}

static int cmd_status(struct opts *o)
{
	struct conn c;
	struct kg_info info;
	unsigned int cpu;

	conn_open(&c, o->device);
	if (ioctl(c.fd, KG_IOC_GET_INFO, &info) < 0)
		die("KG_IOC_GET_INFO: %s", strerror(errno));

	printf("KernelGuard %s (ABI %u)\n", info.version, info.abi_version);
	printf("  mode            : %s%s\n", info.flags & KG_INFO_ENFORCE ? "ENFORCE" : "detect-only",
	       info.flags & KG_INFO_FAIL_SAFE ? "  *** FAIL-SAFE ***" : "");
	printf("  state integrity : %s\n", info.flags & KG_INFO_INTEGRITY_OK ? "ok" : "CORRUPT");
	{
		struct kg_posture_info pi;

		if (ioctl(c.fd, KG_IOC_GET_POSTURE, &pi) == 0)
			printf("  posture         : %s  (details: kgmon posture)\n", posture_text(pi.posture));
	}
	printf("  modules         : pmu=%s  pci-ecam=%s  text=%s  input=%s\n",
	       info.flags & KG_INFO_PMU_ACTIVE ? "on" : "off",
	       info.flags & KG_INFO_ECAM_ACTIVE ? "on" : "off",
	       info.flags & KG_INFO_TEXT_ACTIVE ? "on" : "off",
	       info.flags & KG_INFO_INPUT_ACTIVE ? "on" : "off");
	printf("  monitored       : %u text region(s) / %u KiB baseline, %u PCI device(s), %u keyboard(s)\n",
	       info.text_regions, info.text_kib, info.pci_devices, info.kbd_devices);
	printf("  hardware        : SMT=%s  L3-CAT=%s\n", info.flags & KG_INFO_SMT ? "yes" : "no",
	       info.flags & KG_INFO_CAT_L3 ? "yes (manage via resctrl)" : "no");

	/* Windows CatInitialize computes this partition; on Linux resctrl applies it. */
	for (cpu = 0; cpu < info.nr_cpus && (info.flags & KG_INFO_CAT_L3); cpu++) {
		struct kg_cpu_info ci = { .cpu = cpu };

		if (ioctl(c.fd, KG_IOC_GET_CPU_INFO, &ci) < 0)
			break;
		if (ci.online && ci.cat_ways) {
			printf("  L3 CAT plan     : %u ways; sensitive mask 0x%x, default mask 0x%x (apply with resctrl)\n",
			       ci.cat_ways, ci.cat_sensitive_cbm, ci.cat_default_cbm);
			break;
		}
	}

	printf("\n  cpu  online  strategy(base)          cost   features\n");
	for (cpu = 0; cpu < info.nr_cpus; cpu++) {
		struct kg_cpu_info ci = { .cpu = cpu };

		if (ioctl(c.fd, KG_IOC_GET_CPU_INFO, &ci) < 0)
			break;
		if (!ci.online)
			continue;
		printf("  %-4u %-7s %-13s(%-13s) %4uns  0x%04x%s%s%s%s%s\n", cpu, "yes",
		       strategy_text(ci.strategy), strategy_text(ci.base_strategy), ci.flush_cost_ns,
		       ci.features,
		       ci.features & KG_FEAT_VERW_FLUSH ? " md_clear" : "",
		       ci.features & KG_FEAT_L1D_FLUSH ? " l1d_flush" : "",
		       ci.features & KG_FEAT_IBPB ? " ibpb" : "",
		       ci.features & KG_FEAT_MDS_NO ? " mds_no" : "",
		       ci.features & KG_FEAT_RDCL_NO ? " rdcl_no" : "");
	}

	printf("\n  counters\n");
#define P(f) printf("    %-26s %" PRIu64 "\n", #f, (uint64_t)info.stats.f)
	P(pmu_alert_level); P(pmu_l1d_overflows); P(pmu_llc_overflows);
	P(hw_discrepancy_count); P(hw_dma_violation_count);
	P(idt_hook_detected); P(dispatch_hook_detected); P(text_patch_detected);
	P(text_dynamic_patches); P(failed_module_hash_count);
	P(total_flush_count); P(active_mitigation_flags);
	P(notifications_sent); P(notifications_dropped); P(fallback_signals_sent);
	P(sens_page_count);
#undef P
	return 0;
}

/*
 * `kgmon posture`            show the response posture and what is driving it
 * `kgmon posture set LEVEL`  step the posture up or down (root)
 */
static int cmd_posture(struct opts *o, int argc, char **argv)
{
	struct conn c;
	struct kg_posture_info pi;
	char ts[48];

	if (argc >= 1 && strcmp(argv[0], "set"))
		die("usage: kgmon posture [set normal|elevated|high|failsafe]");
	if (argc == 1 || argc > 2)
		die("usage: kgmon posture set normal|elevated|high|failsafe");

	conn_open(&c, o->device);

	if (argc == 2) {
		struct kg_posture_req rq = { 0 };
		int want = parse_posture(argv[1]);

		if (want < 0)
			die("unknown posture '%s' (normal, elevated, high, failsafe)", argv[1]);
		rq.target = (uint32_t)want;
		if (ioctl(c.fd, KG_IOC_SET_POSTURE, &rq) < 0) {
			if (errno == EUCLEAN)
				die("refused: the module's policy state was found corrupted, so the baseline "
				    "it would restore cannot be trusted; unload and reload kernelguard");
			die("KG_IOC_SET_POSTURE: %s (root required)", strerror(errno));
		}
	}

	if (ioctl(c.fd, KG_IOC_GET_POSTURE, &pi) < 0)
		die("KG_IOC_GET_POSTURE: %s (module too old?)", strerror(errno));

	ts_string(pi.since_ns, ts, sizeof(ts));
	printf("posture          : %s  (since %s, entered %" PRIu64 "x)\n", posture_text(pi.posture), ts,
	       (uint64_t)pi.entered[pi.posture < KG_POSTURE_COUNT ? pi.posture : 0]);
	if (pi.last_trigger_ns) {
		ts_string(pi.last_trigger_ns, ts, sizeof(ts));
		printf("last trigger     : %s  at %s\n", alert_text(pi.last_trigger_alert), ts);
	} else {
		printf("last trigger     : none\n");
	}
	printf("automatic raises : up to %s", posture_text(pi.max_posture));
	if (pi.decay_s)
		printf("; ELEVATED falls back to NORMAL after %u s without a trigger\n", pi.decay_s);
	else
		printf("; ELEVATED never decays by itself\n");
	printf("enforcement      : %s%s\n", pi.flags & KG_POSTURE_F_ENFORCING ? "ACTIVE" : "detect-only",
	       pi.flags & KG_POSTURE_F_AUTO_ENFORCE ? " (auto_enforce: switches on at HIGH)" : "");
	printf("scan intervals   : PCI/input %u ms, integrity %u ms\n", pi.hw_interval_ms, pi.integ_interval_ms);
	if (pi.flags & KG_POSTURE_F_UNTRUSTED)
		printf("WARNING          : the policy state was corrupted; the posture cannot be lowered, reload the module\n");
	printf("entered          : normal %" PRIu64 "  elevated %" PRIu64 "  high %" PRIu64 "  fail-safe %" PRIu64 "\n",
	       (uint64_t)pi.entered[0], (uint64_t)pi.entered[1], (uint64_t)pi.entered[2], (uint64_t)pi.entered[3]);

	memset(c.key, 0, sizeof(c.key));
	return 0;
}

static int cmd_selftest(void)
{
	int bad = kg_hmac_selftest();

	printf("SHA-256 / HMAC-SHA256 known-answer tests: %s\n", bad ? "FAILED" : "passed");
	return bad ? 1 : 0;
}

/*
 * `kgmon run --sensitive -- CMD`  (Windows: sensitive-process tagging).
 *
 * The Windows driver tags "sensitive" processes and intends to flush caches and
 * isolate SMT siblings when they are scheduled (that hook is never installed in
 * the shipped driver).  Linux already has supported per-task controls for
 * exactly this, so instead of a scheduler hook in an out-of-tree module they
 * are applied here, before exec, and inherited by the command:
 *
 *   PR_SPEC_L1D_FLUSH       flush L1D when the task is switched out
 *   PR_SPEC_INDIRECT_BRANCH IBPB / STIBP for the task (speculation DISABLED)
 *   PR_SPEC_STORE_BYPASS    SSBD for the task (speculation DISABLED)
 *   PR_SCHED_CORE           core-scheduling cookie: only tasks sharing the cookie
 *                           ever run on the SMT siblings of this task's core
 *
 * Each control can be unavailable (CPU not affected, kernel option off,
 * seccomp policy); failures are reported and are not fatal.
 */
static void try_prctl(const char *what, long r, int err)
{
	if (r == 0)
		fprintf(stderr, "kgmon: %-40s enabled\n", what);
	else
		fprintf(stderr, "kgmon: %-40s unavailable (%s)\n", what, strerror(err));
}

static int cmd_run(int argc, char **argv)
{
	int i, sensitive = 0, first = -1;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--sensitive")) {
			sensitive = 1;
		} else if (!strcmp(argv[i], "--")) {
			first = i + 1;
			break;
		} else {
			first = i;
			break;
		}
	}
	if (first < 0 || first >= argc)
		die("usage: kgmon run [--sensitive] [--] COMMAND [ARGS...]");

	if (sensitive) {
		long r;

		r = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_L1D_FLUSH, PR_SPEC_ENABLE, 0, 0);
		try_prctl("L1D flush on context switch", r, errno);
		r = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_INDIRECT_BRANCH, PR_SPEC_DISABLE, 0, 0);
		try_prctl("indirect-branch mitigation (IBPB/STIBP)", r, errno);
		r = prctl(PR_SET_SPECULATION_CTRL, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE, 0, 0);
		try_prctl("speculative-store-bypass disable", r, errno);
		r = prctl(PR_SCHED_CORE, PR_SCHED_CORE_CREATE, 0, PIDTYPE_TGID_UAPI, 0);
		try_prctl("core scheduling (SMT isolation)", r, errno);
	}

	execvp(argv[first], &argv[first]);
	die("exec %s: %s", argv[first], strerror(errno));
	return 127;
}

static void usage(FILE *f)
{
	fputs(
"Usage: kgmon [OPTIONS] [COMMAND]\n"
"\n"
"Commands:\n"
"  (none) | watch        follow alerts from the driver (default)\n"
"  status                show driver state, per-CPU mitigation table and counters\n"
"  posture [set LEVEL]   show the response posture (normal, elevated, high, fail-safe)\n"
"                        or, as root, step it up or down after an investigation\n"
"  selftest              run SHA-256/HMAC known-answer tests and exit\n"
"  run [--sensitive] [--] CMD...\n"
"                        exec CMD with per-task L1D-flush / IBPB / SSBD / core\n"
"                        scheduling enabled where the kernel supports them\n"
"\n"
"Options:\n"
"  -d, --device PATH     driver node (default /dev/kernelguard)\n"
"  -l, --log FILE        append alerts to FILE as CSV (Windows \"Save Log\" columns)\n"
"  -s, --syslog          also send alerts to syslog (authpriv)\n"
"  -N, --notify[=USER]   desktop notifications via notify-send; as root, USER (name\n"
"                        or uid) selects whose session receives them\n"
"  -1, --once            print the ring backlog and exit\n"
"      --new-only        skip the backlog, show only new alerts\n"
"  -m, --max N           exit after N alerts\n"
"  -q, --quiet           no stdout output (use with --log/--syslog)\n"
"  -V, --version\n"
"  -h, --help\n", f);
}

int main(int argc, char **argv)
{
	static const struct option lo[] = {
		{ "device", required_argument, 0, 'd' },
		{ "log", required_argument, 0, 'l' },
		{ "syslog", no_argument, 0, 's' },
		{ "notify", optional_argument, 0, 'N' },
		{ "once", no_argument, 0, '1' },
		{ "new-only", no_argument, 0, 1000 },
		{ "max", required_argument, 0, 'm' },
		{ "quiet", no_argument, 0, 'q' },
		{ "version", no_argument, 0, 'V' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};
	struct opts o = { .device = "/dev/" KG_DEV_NAME };
	int c;

	/* `run` takes the rest of the command line verbatim. */
	if (argc >= 2 && !strcmp(argv[1], "run"))
		return cmd_run(argc - 2, argv + 2);

	while ((c = getopt_long(argc, argv, "+d:l:sN::1m:qVh", lo, NULL)) != -1) {
		switch (c) {
		case 'd': o.device = optarg; break;
		case 'l': o.logfile = optarg; break;
		case 's': o.use_syslog = 1; break;
		case 'N': o.use_notify = 1; o.notify_user = optarg; break;
		case '1': o.once = 1; break;
		case 1000: o.new_only = 1; break;
		case 'm': o.max_alerts = strtol(optarg, NULL, 10); break;
		case 'q': o.quiet = 1; break;
		case 'V': printf("kgmon %s\n", KGMON_VERSION); return 0;
		case 'h': usage(stdout); return 0;
		default: usage(stderr); return 2;
		}
	}

	if (optind < argc) {
		const char *cmd = argv[optind];

		if (!strcmp(cmd, "status"))
			return cmd_status(&o);
		if (!strcmp(cmd, "posture"))
			return cmd_posture(&o, argc - optind - 1, argv + optind + 1);
		if (!strcmp(cmd, "selftest"))
			return cmd_selftest();
		if (strcmp(cmd, "watch")) {
			fprintf(stderr, "kgmon: unknown command '%s'\n", cmd);
			usage(stderr);
			return 2;
		}
	}
	return cmd_monitor(&o);
}
