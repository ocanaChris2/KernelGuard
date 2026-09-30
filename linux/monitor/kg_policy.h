/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kg_policy.h - alert escalation policy for kgmon.
 *
 * A policy file maps alerts to actions (commands) and says when an incident that
 * keeps happening, or that nobody acknowledged, is handed to a second set of
 * actions.  The engine here is pure logic: it is given the time and calls back to
 * "run" an action, so it can be tested without forking anything (kgp_selftest).
 *
 * File format (line oriented, '#' starts a comment, values may be "quoted"):
 *
 *   action NAME [timeout=SEC] /absolute/path [ARG...]
 *   rule   NAME [alert=LIST] [level=LEVEL] [throttle=SEC] do=ACTIONS
 *               [repeat=N/SEC] [unacked=SEC] [then=ACTIONS] [reset=SEC]
 *
 *   alert=     comma separated names (see kgp_code_name), 0xNNNN codes or "*" (default: any)
 *   level=     minimum level: info, warning, critical, forged (default: info)
 *   throttle=  seconds during which a repeat of the same incident does not run
 *              the "do" actions again (default 60, 0 = every alert runs them)
 *   repeat=    N/SEC: the incident is escalated when it arrives N times within SEC seconds
 *   unacked=   SEC: the incident is escalated when it is still unacknowledged after SEC seconds
 *   then=      the actions an escalation runs (once per incident)
 *   reset=     seconds of silence after which an incident is forgotten (default 3600)
 *
 * An incident is one rule x alert type x first parameter (offender, address,
 * device...).  All matching rules apply.  `kgmon ack` acknowledges every
 * notification seen so far, which stops "unacked" escalation for them; a repeat
 * after an acknowledgement is a new incident.
 *
 * Alerts whose HMAC failed are never matched by content: they only raise the
 * pseudo alert FORGED, whose details carry nothing the sender chose.
 */
#ifndef KG_POLICY_H
#define KG_POLICY_H

#include <stddef.h>
#include <stdint.h>

#define KGP_MAX_ACTIONS     16
#define KGP_MAX_RULES       32
#define KGP_MAX_CODES       16
#define KGP_MAX_INCIDENTS   64
#define KGP_MAX_ARGS        16
#define KGP_MAX_REPEAT      16
#define KGP_NAME_LEN        32
#define KGP_DETAILS_LEN     192

enum kgp_level { KGP_INFO = 0, KGP_WARNING = 1, KGP_CRITICAL = 2, KGP_FORGED = 3 };

/* Pseudo alerts raised by kgmon itself (outside the 16-bit kernel code space). */
#define KGP_ALERT_FORGED    0x10001u   /* a notification failed HMAC verification */
#define KGP_ALERT_OVERRUN   0x10002u   /* notifications were lost: the ring was lapped */
#define KGP_ALERT_TAMPER    0x10003u   /* a published slot was unreadable or had a wrong sequence number */

struct kgp_alert {
	uint32_t code;                  /* KG_ALERT_* or KGP_ALERT_* */
	int      level;                 /* enum kgp_level */
	uint32_t seq;
	uint64_t param1, param2;
	uint64_t time_ns;               /* CLOCK_REALTIME */
	char     details[KGP_DETAILS_LEN];
};

struct kgp_action {
	char     name[KGP_NAME_LEN];
	char    *argv[KGP_MAX_ARGS + 1];        /* argv[0] is an absolute path */
	int      argc;
	unsigned timeout_s;
};

struct kgp_rule {
	char     name[KGP_NAME_LEN];
	uint32_t codes[KGP_MAX_CODES];
	int      ncodes;                /* 0 = any alert */
	int      min_level;
	unsigned throttle_s;
	uint32_t do_mask;               /* bit i = action i */
	unsigned repeat_n, repeat_window_s;
	unsigned unacked_s;
	uint32_t then_mask;
	unsigned reset_s;
};

struct kgp_policy {
	struct kgp_action actions[KGP_MAX_ACTIONS];
	int nactions;
	struct kgp_rule rules[KGP_MAX_RULES];
	int nrules;
};

struct kgp_incident {
	int      used;
	int      rule;
	uint32_t code;
	uint64_t p1;
	uint64_t first_s, last_s, last_run_s;   /* engine clock (seconds) */
	uint32_t last_seq;
	uint32_t count;
	uint64_t recent[KGP_MAX_REPEAT];        /* arrival times, newest at [count % N] */
	int      escalated, acked;
	struct kgp_alert last;
};

struct kgp_engine {
	const struct kgp_policy *pol;
	struct kgp_incident inc[KGP_MAX_INCIDENTS];
};

/* Called to run one action for an alert; tier 0 = "do", tier 1 = escalation ("then"). */
typedef void (*kgp_run_fn)(void *ctx, const struct kgp_policy *pol, const struct kgp_action *act,
			   const struct kgp_rule *rule, const struct kgp_alert *al,
			   int tier, uint32_t count, uint64_t first_s);

const char *kgp_code_name(uint32_t code);                       /* NULL when unknown */
int  kgp_code_from_name(const char *name, uint32_t *code);      /* 0 on success */
const char *kgp_level_name(int level);

/*
 * Parse policy text.  Returns 0 on success; otherwise the 1-based line number of
 * the first error, with a description in @err.  @check_fs also insists that every
 * action's program exists and is not writable by group or others.
 */
int  kgp_parse(struct kgp_policy *pol, const char *text, int check_fs, char *err, size_t errlen);
/* Read and parse a file; it must be a regular file owned by root (or the caller) and not group/other writable. */
int  kgp_load_file(struct kgp_policy *pol, const char *path, char *err, size_t errlen);
void kgp_free(struct kgp_policy *pol);

void kgp_init(struct kgp_engine *e, const struct kgp_policy *pol);
void kgp_alert(struct kgp_engine *e, uint64_t now_s, const struct kgp_alert *al, kgp_run_fn run, void *ctx);
void kgp_tick(struct kgp_engine *e, uint64_t now_s, kgp_run_fn run, void *ctx);
void kgp_ack(struct kgp_engine *e, uint32_t up_to_seq);
unsigned kgp_open_incidents(const struct kgp_engine *e);

int  kgp_selftest(void);                                        /* number of failed checks */

#endif /* KG_POLICY_H */
