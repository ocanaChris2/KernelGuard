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
 *   kgmon ack              acknowledge the alerts seen so far (escalation policy)
 *   kgmon policy check     validate an escalation policy file
 *   kgmon posture [set L]  graduated-response posture: show it, or step it (root)
 *   kgmon modid FILE|-     the mod_deny= entry (name@srcversion) of a .ko file
 *   kgmon selftest         SHA-256 / HMAC, escalation-policy and module-file parser tests
 *   kgmon run --sensitive -- CMD...
 *                          exec CMD with the kernel's native per-task
 *                          mitigations enabled (see cmd_run())
 *
 * Alert delivery: stdout, optional CSV log (same columns as the Windows
 * "Save Log" file), optional syslog, optional desktop notification, and an
 * optional escalation policy (kg_policy.h): actions run when alerts match a
 * rule, and again when an incident repeats or stays unacknowledged.
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <linux/prctl.h>

#include "kernelguard_uapi.h"
#include "kg_hmac.h"
#include "kg_modid.h"
#include "kg_policy.h"

_Static_assert(sizeof(struct kg_notification) == 72, "notification layout");
_Static_assert(sizeof(struct kg_modgate_info) == 56, "modgate info layout");
_Static_assert(offsetof(struct kg_notification, hmac) == KG_HMAC_AUTH_LEN, "hmac offset");
_Static_assert(sizeof(struct kg_shared_region) == 16 + 72 * KG_NOTIFY_SLOTS, "ring layout");

#define KGMON_VERSION   "1.0.0-linux"
#define POLL_MS         150         /* Windows POLL_INTERVAL_MS */
#define DEF_POLICY      "/etc/kernelguard/policy.conf"
#define DEF_STATE_DIR   "/run/kernelguard"
#define DEF_ACK_FILE    DEF_STATE_DIR "/ack"
#define MAX_CHILDREN    32
#define NOTIFY_TIMEOUT_S 10

/* PIDTYPE_TGID is a kernel-internal enum value; prctl(PR_SCHED_CORE) wants it. */
#ifndef PIDTYPE_TGID_UAPI
#define PIDTYPE_TGID_UAPI   1
#endif

static volatile sig_atomic_t g_stop;

struct opts {
	const char *device;
	const char *logfile;
	const char *notify_user;
	const char *policy_file;    /* explicit --policy FILE                      */
	const char *ack_file;
	int  no_policy;             /* --no-policy: ignore the default file too    */
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
	case KG_ALERT_VULN_DRIVER:             return "Vulnerable Driver Loaded";
	case KG_ALERT_DRIVER_BLOCKED:          return "Driver Load Blocked";
	case KG_ALERT_LOAD_POLICY:             return "Driver Load Policy";
	case KG_ALERT_SHARED_STATE_CORRUPT:    return "Driver State Corrupted";
	case KG_ALERT_FAIL_SAFE_ENTERED:       return "CRITICAL: Fail-Safe Mode";
	case KG_ALERT_POSTURE_CHANGED:         return "Response Posture Changed";
	case KGP_ALERT_FORGED:                 return "Forged Notification";
	case KGP_ALERT_OVERRUN:                return "Notifications Lost";
	case KGP_ALERT_TAMPER:                 return "Ring Tamper Suspected";
	default:                               return "Unknown Alert";
	}
}

static const char *alert_title(uint32_t code)
{
	return alert_text(code);
}

/* LOAD_POLICY: what the OS's own driver-load defences looked like when the module started. */
static void load_policy_text(uint64_t weak, uint64_t raw, char *out, size_t len)
{
	snprintf(out, len, "sig_enforce=%s lockdown=%s secure_boot=%s  %s%s%s%s",
		 raw & KG_LP_RAW_SIG_ENFORCE ? "yes" : "no",
		 raw & KG_LP_RAW_LOCKDOWN ? "yes" : "no",
		 raw & KG_LP_RAW_SECUREBOOT ? "yes" : "no",
		 weak & 0xffu ? "weak:" : "all on",
		 weak & KG_LP_NO_SIG_ENFORCE ? " sig_enforce" : "",
		 weak & KG_LP_NO_LOCKDOWN ? " lockdown" : "",
		 weak & KG_LP_NO_SECUREBOOT ? " secure_boot" : "");
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
	case KG_ALERT_VULN_DRIVER:
	case KG_ALERT_DRIVER_BLOCKED:
		unpack_name(p1, p2, name);
		snprintf(out, len, "name: \"%s\"", name);
		break;
	case KG_ALERT_LOAD_POLICY:
		load_policy_text(p1, p2, out, len);
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

/*
 * Helper processes (desktop notifications, policy actions) are tracked so they
 * are reaped, killed with their whole process group when they overrun their
 * timeout, and never pile up: a flood of alerts cannot fork-bomb the machine.
 */
struct child {
	pid_t pid;                  /* 0 = free slot */
	time_t deadline;
	char name[KGP_NAME_LEN];
};
static struct child g_children[MAX_CHILDREN];

static time_t mono_s(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

static struct child *child_free_slot(void)
{
	for (int i = 0; i < MAX_CHILDREN; i++)
		if (!g_children[i].pid)
			return &g_children[i];
	return NULL;
}

static void child_track(struct child *c, pid_t pid, unsigned timeout_s, const char *name)
{
	c->pid = pid;
	c->deadline = mono_s() + timeout_s;
	snprintf(c->name, sizeof(c->name), "%s", name);
}

static void children_reap(int use_syslog)
{
	for (int i = 0; i < MAX_CHILDREN; i++) {
		struct child *c = &g_children[i];
		int st;
		pid_t r;

		if (!c->pid)
			continue;
		r = waitpid(c->pid, &st, WNOHANG);
		if (r == c->pid) {
			if (WIFEXITED(st) && WEXITSTATUS(st) != 0) {
				fprintf(stderr, "kgmon: %s exited with status %d\n", c->name, WEXITSTATUS(st));
				if (use_syslog)
					syslog(LOG_WARNING, "%s exited with status %d", c->name, WEXITSTATUS(st));
			} else if (WIFSIGNALED(st) && WTERMSIG(st) != SIGKILL) {
				fprintf(stderr, "kgmon: %s killed by signal %d\n", c->name, WTERMSIG(st));
			}
			c->pid = 0;
		} else if (r < 0 && errno == ECHILD) {
			c->pid = 0;
		} else if (mono_s() >= c->deadline) {
			fprintf(stderr, "kgmon: %s timed out, killing it\n", c->name);
			if (use_syslog)
				syslog(LOG_WARNING, "%s timed out and was killed", c->name);
			kill(-c->pid, SIGKILL);     /* the action leads its own process group */
			kill(c->pid, SIGKILL);
			c->deadline = mono_s() + 5; /* reaped on a later pass */
		}
	}
}

static void notify_desktop(const struct opts *o, const char *title, const char *body)
{
	struct child *slot = child_free_slot();
	pid_t pid;

	if (!slot) {
		fprintf(stderr, "kgmon: too many helper processes running, dropped a desktop notification\n");
		return;
	}
	pid = fork();
	if (pid < 0)
		return;
	if (pid != 0) {
		child_track(slot, pid, NOTIFY_TIMEOUT_S, "notify-send");
		return;
	}
	setsid();

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
	int have_policy;
	struct kgp_policy pol;
	struct kgp_engine eng;
	struct stat ack_seen;       /* identity of the ack file when last read */
};

/*----------------------------------------------------------------------------
 * Escalation policy: running actions
 *--------------------------------------------------------------------------*/
static void iso_utc(uint64_t ns, char *buf, size_t len)
{
	time_t sec = (time_t)(ns / 1000000000ull);
	struct tm tm;

	gmtime_r(&sec, &tm);
	strftime(buf, len, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

/* Runs in the forked child: build a minimal environment and exec. */
static void exec_action(const struct kgp_action *act, const struct kgp_rule *rule,
			const struct kgp_alert *al, int tier, uint32_t count, long age_s)
{
	char host[128] = "", when[40], *env[24], buf[24][KGP_DETAILS_LEN + 32];
	const char *name = kgp_code_name(al->code);
	int n = 0;
	sigset_t none;
	int nul;

	setsid();
	signal(SIGPIPE, SIG_DFL);
	signal(SIGINT, SIG_DFL);
	signal(SIGTERM, SIG_DFL);
	sigemptyset(&none);
	sigprocmask(SIG_SETMASK, &none, NULL);
	nul = open("/dev/null", O_RDWR);
	if (nul >= 0) {
		dup2(nul, 0);
		if (nul > 2)
			close(nul);
	}
	dup2(2, 1);                 /* whatever the action prints lands in the journal / stderr */

	gethostname(host, sizeof(host) - 1);
	iso_utc(al->time_ns, when, sizeof(when));

#define ENV(...) do { snprintf(buf[n], sizeof(buf[n]), __VA_ARGS__); env[n] = buf[n]; n++; } while (0)
	ENV("PATH=/usr/sbin:/usr/bin:/sbin:/bin");
	ENV("KG_HOST=%s", host);
	ENV("KG_RULE=%s", rule->name);
	ENV("KG_ACTION=%s", act->name);
	ENV("KG_TIER=%d", tier);
	ENV("KG_COUNT=%u", count);
	ENV("KG_AGE_S=%ld", age_s);
	ENV("KG_ALERT=%s", name ? name : "UNKNOWN");
	ENV("KG_ALERT_CODE=0x%04x", al->code);
	ENV("KG_TITLE=%s", alert_title(al->code));
	ENV("KG_LEVEL=%s", kgp_level_name(al->level));
	ENV("KG_LEVEL_NUM=%d", al->level);
	ENV("KG_SEQ=%u", al->seq);
	ENV("KG_TIME=%s", when);
	ENV("KG_PARAM1=0x%016" PRIx64, al->param1);
	ENV("KG_PARAM2=0x%016" PRIx64, al->param2);
	ENV("KG_DETAILS=%s", al->details);
#undef ENV
	env[n] = NULL;

	execve(act->argv[0], act->argv, env);
	fprintf(stderr, "kgmon: cannot run action %s (%s): %s\n", act->name, act->argv[0], strerror(errno));
	_exit(127);
}

static void run_action(void *ctx, const struct kgp_policy *pol, const struct kgp_action *act,
		       const struct kgp_rule *rule, const struct kgp_alert *al,
		       int tier, uint32_t count, uint64_t first_s)
{
	struct sinks *s = ctx;
	struct child *slot = child_free_slot();
	pid_t pid;

	(void)pol;
	if (!slot) {
		fprintf(stderr, "kgmon: too many actions running, dropped %s for rule %s\n", act->name, rule->name);
		if (s->o.use_syslog)
			syslog(LOG_ERR, "too many actions running, dropped %s for rule %s", act->name, rule->name);
		return;
	}
	if (s->o.use_syslog)
		syslog(LOG_NOTICE, "%s: running action %s for %s (tier %d, %u occurrence(s))",
		       rule->name, act->name, kgp_code_name(al->code) ? kgp_code_name(al->code) : "alert",
		       tier, count);

	fflush(NULL);               /* nothing buffered may be written twice by the child */
	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "kgmon: fork: %s\n", strerror(errno));
		return;
	}
	if (pid == 0)
		exec_action(act, rule, al, tier, count, (long)(mono_s() - (time_t)first_s));
	child_track(slot, pid, act->timeout_s, act->name);
}

static unsigned level_to_policy(uint32_t l)
{
	return l >= KG_LEVEL_CRITICAL ? KGP_CRITICAL : l == KG_LEVEL_WATCH ? KGP_WARNING : KGP_INFO;
}

static void policy_pseudo(struct sinks *s, uint32_t code, int level, uint32_t seq, const char *fmt, ...)
	__attribute__((format(printf, 5, 6)));

/* Something kgmon itself concluded (forged notification, lost notifications, tampered ring). */
static void policy_pseudo(struct sinks *s, uint32_t code, int level, uint32_t seq, const char *fmt, ...)
{
	struct kgp_alert a;
	struct timespec now;
	va_list ap;

	if (!s->have_policy)
		return;
	memset(&a, 0, sizeof(a));
	clock_gettime(CLOCK_REALTIME, &now);
	a.code = code;
	a.level = level;
	a.seq = seq;
	a.time_ns = (uint64_t)now.tv_sec * 1000000000ull + (uint64_t)now.tv_nsec;
	va_start(ap, fmt);
	vsnprintf(a.details, sizeof(a.details), fmt, ap);
	va_end(ap);
	kgp_alert(&s->eng, (uint64_t)mono_s(), &a, run_action, s);
}

static void policy_feed(struct sinks *s, const struct kg_notification *n, int hmac_ok, const char *details)
{
	struct kgp_alert a;

	if (!s->have_policy)
		return;
	if (!hmac_ok) {
		/* Nothing in a notification that failed authentication may steer an action. */
		policy_pseudo(s, KGP_ALERT_FORGED, KGP_FORGED, n->sequence,
			      "notification %u failed HMAC verification", n->sequence);
		return;
	}
	memset(&a, 0, sizeof(a));
	a.code = n->alert_type;
	a.level = (int)level_to_policy(n->alert_level);
	a.seq = n->sequence;
	a.param1 = n->param1;
	a.param2 = n->param2;
	a.time_ns = n->timestamp;
	snprintf(a.details, sizeof(a.details), "%s", details);
	kgp_alert(&s->eng, (uint64_t)mono_s(), &a, run_action, s);
}

/* `kgmon ack` leaves the highest acknowledged sequence number in a root-owned file. */
static void policy_check_ack(struct sinks *s)
{
	const char *path = s->o.ack_file ? s->o.ack_file : DEF_ACK_FILE;
	struct stat st;
	FILE *f;
	unsigned long seq;

	if (stat(path, &st) < 0)
		return;
	if (st.st_ino == s->ack_seen.st_ino && st.st_mtim.tv_sec == s->ack_seen.st_mtim.tv_sec &&
	    st.st_mtim.tv_nsec == s->ack_seen.st_mtim.tv_nsec)
		return;
	s->ack_seen = st;
	if (!S_ISREG(st.st_mode) || (st.st_uid != 0 && st.st_uid != geteuid()) ||
	    (st.st_mode & (S_IWGRP | S_IWOTH))) {
		fprintf(stderr, "kgmon: ignoring %s (must be a regular file owned by root, not writable by others)\n", path);
		return;
	}
	f = fopen(path, "re");
	if (!f)
		return;
	if (fscanf(f, "%lu", &seq) == 1) {
		kgp_ack(&s->eng, (uint32_t)seq);
		fprintf(stderr, "kgmon: alerts up to sequence %lu acknowledged\n", seq);
		if (s->o.use_syslog)
			syslog(LOG_NOTICE, "alerts up to sequence %lu acknowledged", seq);
	}
	fclose(f);
}

/*----------------------------------------------------------------------------
 * systemd integration (sd_notify without libsystemd)
 *--------------------------------------------------------------------------*/
static void sd_notify_msg(const char *msg)
{
	const char *path = getenv("NOTIFY_SOCKET");
	struct sockaddr_un sa = { .sun_family = AF_UNIX };
	socklen_t len;
	int fd;

	if (!path || !*path || strlen(path) >= sizeof(sa.sun_path))
		return;
	memcpy(sa.sun_path, path, strlen(path));
	len = (socklen_t)(offsetof(struct sockaddr_un, sun_path) + strlen(path));
	if (path[0] == '@')
		sa.sun_path[0] = '\0';     /* abstract socket */
	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return;
	(void)sendto(fd, msg, strlen(msg), MSG_NOSIGNAL, (struct sockaddr *)&sa, len);
	close(fd);
}

/* Ping the service manager's watchdog at half the configured interval. */
static void watchdog_tick(void)
{
	static time_t next;
	const char *usec = getenv("WATCHDOG_USEC");
	long half_ms;

	if (!usec)
		return;
	half_ms = strtol(usec, NULL, 10) / 2000;
	if (half_ms <= 0)
		return;
	if (mono_s() >= next) {
		sd_notify_msg("WATCHDOG=1");
		next = mono_s() + (half_ms + 999) / 1000;
	}
}

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

	policy_feed(s, n, hmac_ok, details);

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
		unsigned lost = w - *cursor - KG_NOTIFY_SLOTS;

		fprintf(stderr, "kgmon: ring overrun - %u notification(s) lost\n", lost);
		policy_pseudo(s, KGP_ALERT_OVERRUN, KGP_CRITICAL, *cursor,
			      "%u notification(s) lost: the ring was lapped", lost);
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

			if (w2 - *cursor > KG_NOTIFY_SLOTS - 1) {
				fprintf(stderr, "kgmon: notification %u overwritten before it could be read\n", *cursor);
				policy_pseudo(s, KGP_ALERT_OVERRUN, KGP_CRITICAL, *cursor,
					      "notification %u was overwritten before it could be read", *cursor);
			} else {
				fprintf(stderr, "kgmon: TAMPER? slot for notification %u is unreadable or has a wrong sequence number\n", *cursor);
				policy_pseudo(s, KGP_ALERT_TAMPER, KGP_FORGED, *cursor,
					      "slot for notification %u is unreadable or has a wrong sequence number", *cursor);
			}
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

	/* A policy the operator asked for must load, or the service fails loudly instead of never escalating. */
	if (!o->once && !o->no_policy) {
		const char *pf = o->policy_file;
		char err[256];
		struct stat st;

		if (!pf && stat(DEF_POLICY, &st) == 0)
			pf = DEF_POLICY;
		if (pf) {
			if (kgp_load_file(&s.pol, pf, err, sizeof(err)))
				die("policy: %s", err);
			kgp_init(&s.eng, &s.pol);
			s.have_policy = 1;
			mkdir(DEF_STATE_DIR, 0700);
			fprintf(stderr, "kgmon: policy %s: %d action(s), %d rule(s)\n", pf, s.pol.nactions, s.pol.nrules);
			if (o->once)
				s.have_policy = 0;
		}
	}

	if (o->logfile) {
		struct stat st;

		s.log = fopen(o->logfile, "ae");
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
	if (!o->once)
		sd_notify_msg("READY=1\nSTATUS=watching for alerts");
	while (!g_stop && !o->once) {
		struct pollfd pfd = { .fd = c.fd, .events = POLLIN };
		int r = poll(&pfd, 1, POLL_MS);

		if (r < 0 && errno != EINTR)
			die("poll: %s", strerror(errno));
		if (r > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
			die("device error");
		drain(&s, c.ring, c.key, &cursor);

		children_reap(o->use_syslog);
		if (s.have_policy) {
			policy_check_ack(&s);
			kgp_tick(&s.eng, (uint64_t)mono_s(), run_action, &s);
		}
		watchdog_tick();
	}
	if (!o->once)
		sd_notify_msg("STOPPING=1");

	if (s.log)
		fclose(s.log);
	if (s.have_policy)
		kgp_free(&s.pol);
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
	{
		struct kg_modgate_info mg;

		if (ioctl(c.fd, KG_IOC_GET_MODGATE, &mg) == 0) {
			if (mg.flags & KG_MODGATE_F_ACTIVE) {
				printf("  module gate     : %s, deny %u, allow %u, lock %s (baseline %u)\n",
				       mg.flags & KG_MODGATE_F_ENFORCING ? "refusing" : "detect-only",
				       mg.n_deny, mg.n_allow, mg.flags & KG_MODGATE_F_LOCK ? "on" : "off",
				       mg.n_baseline);
				printf("  gate counters   : denied %" PRIu64 ", refused %" PRIu64 ", lock hits %" PRIu64
				       ", ignored entries %u\n", (uint64_t)mg.deny_hits, (uint64_t)mg.blocked,
				       (uint64_t)mg.lock_hits, mg.ignored);
			} else {
				printf("  module gate     : off (modgate=0)\n");
			}
			if (mg.flags & KG_MODGATE_F_AUDITED) {
				char lp[128];

				load_policy_text(mg.lp_mask, mg.lp_raw, lp, sizeof(lp));
				printf("  load policy     : %s\n", lp);
			}
		}
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

/*
 * `kgmon ack`   acknowledge every alert seen so far: an "unacked=" escalation of the running
 *               monitor stops for them, and a repeat afterwards is a new incident.
 */
static int cmd_ack(struct opts *o)
{
	const char *path = o->ack_file ? o->ack_file : DEF_ACK_FILE;
	char tmp[256], *slash;
	struct conn c;
	uint32_t w;
	FILE *f;

	conn_open(&c, o->device);
	w = __atomic_load_n(&c.ring->write_index, __ATOMIC_ACQUIRE);
	memset(c.key, 0, sizeof(c.key));
	if (!w) {
		printf("nothing to acknowledge: the driver has raised no alerts yet\n");
		return 0;
	}

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	slash = strrchr(tmp, '/');
	if (slash && slash != tmp) {
		*slash = '\0';
		mkdir(tmp, 0700);
		*slash = '/';
	}
	f = fopen(tmp, "we");
	if (!f)
		die("cannot write %s: %s", tmp, strerror(errno));
	fchmod(fileno(f), 0600);
	fprintf(f, "%u\n", w - 1);
	if (fclose(f) || rename(tmp, path))
		die("cannot update %s: %s", path, strerror(errno));
	printf("acknowledged alerts up to sequence %u\n", w - 1);
	return 0;
}

/* `kgmon policy check [FILE]` */
static int cmd_policy(struct opts *o, int argc, char **argv)
{
	const char *path = argc >= 2 ? argv[1] : o->policy_file ? o->policy_file : DEF_POLICY;
	struct kgp_policy pol;
	char err[256];

	if (argc < 1 || strcmp(argv[0], "check") || argc > 2)
		die("usage: kgmon policy check [FILE]");
	if (kgp_load_file(&pol, path, err, sizeof(err))) {
		fprintf(stderr, "kgmon: %s\n", err);
		return 1;
	}
	printf("%s: ok, %d action(s), %d rule(s)\n", path, pol.nactions, pol.nrules);
	for (int i = 0; i < pol.nrules; i++) {
		const struct kgp_rule *r = &pol.rules[i];

		printf("  rule %-16s level>=%-8s %s%s\n", r->name, kgp_level_name(r->min_level),
		       r->repeat_n ? "repeat " : "", r->unacked_s ? "unacked" : "");
	}
	kgp_free(&pol);
	return 0;
}

/*
 * `kgmon modid [--entry] FILE.ko|-`
 *
 * Prints what the driver-load gate matches a module by, read from the file: its name and
 * srcversion (mod_deny= takes NAME or NAME@SRCVERSION), plus the file's SHA-256 for the audit
 * trail.  `-` reads standard input, which is how a compressed module gets in:
 *     zstd -dc /lib/modules/$(uname -r)/kernel/.../x.ko.zst | kgmon modid -
 * Needs no driver and no privileges; the file is parsed, never loaded.
 */
#define MODID_MAX_BYTES (256u << 20)    /* the largest module anyone ships is a few tens of MiB */

static uint8_t *read_module_file(const char *path, size_t *lenp)
{
	int fd = strcmp(path, "-") ? open(path, O_RDONLY | O_CLOEXEC) : STDIN_FILENO;
	size_t cap = 1u << 20, len = 0;
	uint8_t *buf;

	if (fd < 0)
		die("%s: %s", path, strerror(errno));
	buf = malloc(cap);
	if (!buf)
		die("out of memory");
	for (;;) {
		ssize_t n;

		if (len == cap) {
			uint8_t *nb;

			if (cap >= MODID_MAX_BYTES)
				die("%s: larger than %u MiB, not a kernel module", path, MODID_MAX_BYTES >> 20);
			cap *= 2;
			nb = realloc(buf, cap);
			if (!nb)
				die("out of memory");
			buf = nb;
		}
		n = read(fd, buf + len, cap - len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			die("%s: %s", path, strerror(errno));
		}
		if (!n)
			break;
		len += (size_t)n;
	}
	if (fd != STDIN_FILENO)
		close(fd);
	*lenp = len;
	return buf;
}

static int cmd_modid(int argc, char **argv)
{
	struct kg_modid m;
	uint8_t *img;
	size_t len;
	char entry[96], hex[65];
	const char *shown;
	int entry_only = 0, rc;

	if (argc >= 1 && !strcmp(argv[0], "--entry")) {
		entry_only = 1;
		argc--;
		argv++;
	}
	if (argc != 1)
		die("usage: kgmon modid [--entry] FILE.ko|-");

	shown = strcmp(argv[0], "-") ? argv[0] : "(stdin)";
	img = read_module_file(argv[0], &len);
	rc = kg_modid_parse(img, len, &m);
	free(img);
	if (rc)
		die("%s: %s", shown, kg_modid_strerror(rc));

	kg_modid_entry(&m, entry, sizeof(entry));
	if (entry_only) {
		puts(entry);
		return 0;
	}
	for (int i = 0; i < 32; i++)
		snprintf(hex + 2 * i, 3, "%02x", m.sha256[i]);

	printf("module      : %s\n", m.name);
	printf("srcversion  : %s\n", m.srcversion[0] ? m.srcversion : "(none: an entry matches every version)");
	printf("version     : %s\n", m.version[0] ? m.version : "(none)");
	printf("vermagic    : %s\n", m.vermagic[0] ? m.vermagic : "(none)");
	printf("signature   : %s\n", m.sig_marker ? "appended (the kernel checks it at load)"
						  : "not appended (refused when the kernel enforces signatures)");
	printf("sha256      : %s\n", hex);
	printf("mod_deny    : %s\n", entry);
	return 0;
}

static int cmd_selftest(void)
{
	int bad = kg_hmac_selftest();
	int pbad = kgp_selftest();
	int mbad = kg_modid_selftest();

	printf("SHA-256 / HMAC-SHA256 known-answer tests: %s\n", bad ? "FAILED" : "passed");
	printf("escalation policy tests: %s\n", pbad ? "FAILED" : "passed");
	printf("module file parser tests: %s\n", mbad ? "FAILED" : "passed");
	return bad || pbad || mbad ? 1 : 0;
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
"  ack                   acknowledge the alerts seen so far (stops \"unacked=\" escalation)\n"
"  policy check [FILE]   validate an escalation policy file and exit\n"
"  modid [--entry] FILE  print the mod_deny= entry (NAME@SRCVERSION) of a .ko file; FILE\n"
"                        may be - to read standard input (for .ko.zst: zstd -dc x | kgmon modid -)\n"
"  selftest              run the SHA-256/HMAC, escalation-policy and module-file tests and exit\n"
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
"  -p, --policy FILE     escalation policy (default /etc/kernelguard/policy.conf when present)\n"
"      --no-policy       do not load a policy, not even the default file\n"
"      --ack-file FILE   where `kgmon ack` leaves its mark (default /run/kernelguard/ack)\n"
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
		{ "policy", required_argument, 0, 'p' },
		{ "no-policy", no_argument, 0, 1001 },
		{ "ack-file", required_argument, 0, 1002 },
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

	while ((c = getopt_long(argc, argv, "+d:l:sN::1m:p:qVh", lo, NULL)) != -1) {
		switch (c) {
		case 'd': o.device = optarg; break;
		case 'l': o.logfile = optarg; break;
		case 's': o.use_syslog = 1; break;
		case 'N': o.use_notify = 1; o.notify_user = optarg; break;
		case '1': o.once = 1; break;
		case 1000: o.new_only = 1; break;
		case 'm': o.max_alerts = strtol(optarg, NULL, 10); break;
		case 'p': o.policy_file = optarg; break;
		case 1001: o.no_policy = 1; break;
		case 1002: o.ack_file = optarg; break;
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
		if (!strcmp(cmd, "modid"))
			return cmd_modid(argc - optind - 1, argv + optind + 1);
		if (!strcmp(cmd, "ack"))
			return cmd_ack(&o);
		if (!strcmp(cmd, "policy"))
			return cmd_policy(&o, argc - optind - 1, argv + optind + 1);
		if (strcmp(cmd, "watch")) {
			fprintf(stderr, "kgmon: unknown command '%s'\n", cmd);
			usage(stderr);
			return 2;
		}
	}
	return cmd_monitor(&o);
}
