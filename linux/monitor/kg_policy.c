// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_policy.c - alert escalation policy for kgmon (see kg_policy.h for the file format).
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "kernelguard_uapi.h"
#include "kg_policy.h"

/*----------------------------------------------------------------------------
 * Names
 *--------------------------------------------------------------------------*/
static const struct { uint32_t code; const char *name; } kgp_names[] = {
	{ KG_ALERT_PMU_L1D_ANOMALY,         "PMU_L1D_ANOMALY" },
	{ KG_ALERT_PMU_L2_ANOMALY,          "PMU_L2_ANOMALY" },
	{ KG_ALERT_PMU_RDTSC_RATE,          "PMU_RDTSC_RATE" },
	{ KG_ALERT_UNAUTHORIZED_KBD_FILTER, "UNAUTHORIZED_KBD_FILTER" },
	{ KG_ALERT_UNAUTHORIZED_DMA,        "UNAUTHORIZED_DMA" },
	{ KG_ALERT_PCI_DISCREPANCY,         "PCI_DISCREPANCY" },
	{ KG_ALERT_KBD_FILTER_NEUTRALIZED,  "KBD_FILTER_NEUTRALIZED" },
	{ KG_ALERT_DMA_BLOCKED_IOMMU,       "DMA_BLOCKED_IOMMU" },
	{ KG_ALERT_DEVICE_BME_DISABLED,     "DEVICE_BME_DISABLED" },
	{ KG_ALERT_IDT_HOOK,                "IDT_HOOK" },
	{ KG_ALERT_DISPATCH_HOOK,           "DISPATCH_HOOK" },
	{ KG_ALERT_TEXT_PATCH,              "TEXT_PATCH" },
	{ KG_ALERT_CTRL_REG_TAMPER,         "CTRL_REG_TAMPER" },
	{ KG_ALERT_MODULE_LOADED,           "MODULE_LOADED" },
	{ KG_ALERT_VULN_DRIVER,             "VULN_DRIVER" },
	{ KG_ALERT_DRIVER_BLOCKED,          "DRIVER_BLOCKED" },
	{ KG_ALERT_LOAD_POLICY,             "LOAD_POLICY" },
	{ KG_ALERT_SHARED_STATE_CORRUPT,    "SHARED_STATE_CORRUPT" },
	{ KG_ALERT_FAIL_SAFE_ENTERED,       "FAIL_SAFE_ENTERED" },
	{ KG_ALERT_POSTURE_CHANGED,         "POSTURE_CHANGED" },
	{ KGP_ALERT_FORGED,                 "FORGED" },
	{ KGP_ALERT_OVERRUN,                "OVERRUN" },
	{ KGP_ALERT_TAMPER,                 "TAMPER" },
};

const char *kgp_code_name(uint32_t code)
{
	for (size_t i = 0; i < sizeof(kgp_names) / sizeof(kgp_names[0]); i++)
		if (kgp_names[i].code == code)
			return kgp_names[i].name;
	return NULL;
}

int kgp_code_from_name(const char *name, uint32_t *code)
{
	for (size_t i = 0; i < sizeof(kgp_names) / sizeof(kgp_names[0]); i++) {
		if (!strcasecmp(kgp_names[i].name, name)) {
			*code = kgp_names[i].code;
			return 0;
		}
	}
	if (name[0] == '0' && (name[1] == 'x' || name[1] == 'X') && name[2]) {
		char *end;
		unsigned long v = strtoul(name, &end, 16);

		if (!*end && v <= 0xffff) {
			*code = (uint32_t)v;
			return 0;
		}
	}
	return -1;
}

const char *kgp_level_name(int level)
{
	switch (level) {
	case KGP_INFO:     return "info";
	case KGP_WARNING:  return "warning";
	case KGP_CRITICAL: return "critical";
	case KGP_FORGED:   return "forged";
	default:           return "?";
	}
}

static int level_from_name(const char *s)
{
	for (int l = KGP_INFO; l <= KGP_FORGED; l++)
		if (!strcasecmp(s, kgp_level_name(l)))
			return l;
	return -1;
}

/*----------------------------------------------------------------------------
 * Parser
 *--------------------------------------------------------------------------*/
static void __attribute__((format(printf, 3, 4)))
set_err(char *err, size_t len, const char *fmt, ...)
{
	va_list ap;

	if (!err || !len)
		return;
	va_start(ap, fmt);
	vsnprintf(err, len, fmt, ap);
	va_end(ap);
}

/*
 * Split @line in place into whitespace separated tokens; "double quotes" group
 * (and are removed), a backslash escapes a quote inside them.  Returns the token
 * count, or -1 on an unterminated quote / too many tokens.
 */
static int tokenize(char *line, char **tok, int max)
{
	int n = 0;
	char *p = line;

	while (*p) {
		char *out;

		while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
			p++;
		if (!*p || *p == '#')
			break;
		if (n >= max)
			return -1;
		tok[n++] = out = p;
		while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') {
			if (*p == '"') {
				p++;
				while (*p && *p != '"') {
					if (*p == '\\' && p[1] == '"')
						p++;
					*out++ = *p++;
				}
				if (*p != '"')
					return -1;
				p++;
			} else {
				*out++ = *p++;
			}
		}
		if (*p)
			p++;
		*out = '\0';
	}
	return n;
}

static int action_index(const struct kgp_policy *pol, const char *name)
{
	for (int i = 0; i < pol->nactions; i++)
		if (!strcmp(pol->actions[i].name, name))
			return i;
	return -1;
}

static int valid_name(const char *s)
{
	if (!*s || strlen(s) >= KGP_NAME_LEN)
		return 0;
	for (; *s; s++)
		if (!isalnum((unsigned char)*s) && *s != '_' && *s != '-' && *s != '.')
			return 0;
	return 1;
}

static int parse_uint(const char *s, unsigned lo, unsigned hi, unsigned *out)
{
	char *end;
	unsigned long v;

	if (!*s || *s == '-')
		return -1;
	errno = 0;
	v = strtoul(s, &end, 10);
	if (*end || errno || v < lo || v > hi)
		return -1;
	*out = (unsigned)v;
	return 0;
}

/* Comma separated action names -> bit mask. */
static int parse_action_list(const struct kgp_policy *pol, char *list, uint32_t *mask,
			     char *err, size_t errlen)
{
	char *save = NULL, *t;

	*mask = 0;
	for (t = strtok_r(list, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
		int i = action_index(pol, t);

		if (i < 0) {
			set_err(err, errlen, "unknown action '%s' (define it with an \"action\" line first)", t);
			return -1;
		}
		*mask |= 1u << i;
	}
	if (!*mask) {
		set_err(err, errlen, "empty action list");
		return -1;
	}
	return 0;
}

static int check_program(const char *path, char *err, size_t errlen)
{
	struct stat st;

	if (path[0] != '/') {
		set_err(err, errlen, "program '%s' must be an absolute path", path);
		return -1;
	}
	if (stat(path, &st) < 0) {
		set_err(err, errlen, "program '%s': %s", path, strerror(errno));
		return -1;
	}
	if (!S_ISREG(st.st_mode) || !(st.st_mode & S_IXUSR)) {
		set_err(err, errlen, "program '%s' is not an executable file", path);
		return -1;
	}
	if (st.st_mode & (S_IWGRP | S_IWOTH)) {
		set_err(err, errlen, "program '%s' is writable by group or others; refusing to run it as root", path);
		return -1;
	}
	if (st.st_uid != 0 && st.st_uid != geteuid()) {
		set_err(err, errlen, "program '%s' is not owned by root or by this user", path);
		return -1;
	}
	return 0;
}

static int parse_action(struct kgp_policy *pol, char **tok, int n, int check_fs, char *err, size_t errlen)
{
	struct kgp_action *a;
	int i = 2;

	if (n < 3) {
		set_err(err, errlen, "usage: action NAME [timeout=SEC] /path [ARG...]");
		return -1;
	}
	if (pol->nactions >= KGP_MAX_ACTIONS) {
		set_err(err, errlen, "too many actions");
		return -1;
	}
	if (!valid_name(tok[1])) {
		set_err(err, errlen, "bad action name '%s'", tok[1]);
		return -1;
	}
	if (action_index(pol, tok[1]) >= 0) {
		set_err(err, errlen, "action '%s' is defined twice", tok[1]);
		return -1;
	}

	a = &pol->actions[pol->nactions];
	memset(a, 0, sizeof(*a));
	snprintf(a->name, sizeof(a->name), "%s", tok[1]);
	a->timeout_s = 10;

	while (i < n && tok[i][0] != '/' && strchr(tok[i], '=')) {
		if (!strncmp(tok[i], "timeout=", 8)) {
			if (parse_uint(tok[i] + 8, 1, 3600, &a->timeout_s)) {
				set_err(err, errlen, "bad timeout '%s' (1-3600 seconds)", tok[i] + 8);
				goto fail;
			}
		} else {
			set_err(err, errlen, "unknown action option '%s'", tok[i]);
			goto fail;
		}
		i++;
	}
	if (i >= n) {
		set_err(err, errlen, "action '%s' has no program", a->name);
		goto fail;
	}
	if (n - i > KGP_MAX_ARGS) {
		set_err(err, errlen, "too many arguments for action '%s'", a->name);
		goto fail;
	}
	if (check_fs && check_program(tok[i], err, errlen))
		goto fail;
	if (tok[i][0] != '/') {
		set_err(err, errlen, "program '%s' must be an absolute path", tok[i]);
		goto fail;
	}
	for (; i < n; i++) {
		a->argv[a->argc] = strdup(tok[i]);
		if (!a->argv[a->argc]) {
			set_err(err, errlen, "out of memory");
			goto fail;
		}
		a->argc++;
	}
	pol->nactions++;
	return 0;

fail:
	for (int k = 0; k < a->argc; k++)
		free(a->argv[k]);
	memset(a, 0, sizeof(*a));
	return -1;
}

static int parse_rule(struct kgp_policy *pol, char **tok, int n, char *err, size_t errlen)
{
	struct kgp_rule *r;
	int have_do = 0, have_then = 0;
	char *thenlist = NULL;

	if (n < 3) {
		set_err(err, errlen, "usage: rule NAME [alert=..] [level=..] do=A,B [repeat=N/SEC] [unacked=SEC] [then=A,B]");
		return -1;
	}
	if (pol->nrules >= KGP_MAX_RULES) {
		set_err(err, errlen, "too many rules");
		return -1;
	}
	if (!valid_name(tok[1])) {
		set_err(err, errlen, "bad rule name '%s'", tok[1]);
		return -1;
	}
	for (int i = 0; i < pol->nrules; i++) {
		if (!strcmp(pol->rules[i].name, tok[1])) {
			set_err(err, errlen, "rule '%s' is defined twice", tok[1]);
			return -1;
		}
	}

	r = &pol->rules[pol->nrules];
	memset(r, 0, sizeof(*r));
	snprintf(r->name, sizeof(r->name), "%s", tok[1]);
	r->throttle_s = 60;
	r->reset_s = 3600;

	for (int i = 2; i < n; i++) {
		char *k = tok[i], *v = strchr(tok[i], '=');

		if (!v) {
			set_err(err, errlen, "expected key=value, got '%s'", k);
			return -1;
		}
		*v++ = '\0';

		if (!strcmp(k, "alert")) {
			char *save = NULL, *t;

			r->ncodes = 0;
			for (t = strtok_r(v, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
				if (!strcmp(t, "*")) {
					r->ncodes = 0;
					break;
				}
				if (r->ncodes >= KGP_MAX_CODES) {
					set_err(err, errlen, "too many alert types in one rule (max %d)", KGP_MAX_CODES);
					return -1;
				}
				if (kgp_code_from_name(t, &r->codes[r->ncodes])) {
					set_err(err, errlen, "unknown alert type '%s'", t);
					return -1;
				}
				r->ncodes++;
			}
		} else if (!strcmp(k, "level")) {
			r->min_level = level_from_name(v);
			if (r->min_level < 0) {
				set_err(err, errlen, "unknown level '%s' (info, warning, critical, forged)", v);
				return -1;
			}
		} else if (!strcmp(k, "throttle")) {
			if (parse_uint(v, 0, 86400, &r->throttle_s)) {
				set_err(err, errlen, "bad throttle '%s' (0-86400 seconds)", v);
				return -1;
			}
		} else if (!strcmp(k, "reset")) {
			if (parse_uint(v, 1, 30 * 86400, &r->reset_s)) {
				set_err(err, errlen, "bad reset '%s' (1-2592000 seconds)", v);
				return -1;
			}
		} else if (!strcmp(k, "unacked")) {
			if (parse_uint(v, 1, 30 * 86400, &r->unacked_s)) {
				set_err(err, errlen, "bad unacked '%s' (1-2592000 seconds)", v);
				return -1;
			}
		} else if (!strcmp(k, "repeat")) {
			char *slash = strchr(v, '/');

			if (!slash) {
				set_err(err, errlen, "repeat wants N/SEC, got '%s'", v);
				return -1;
			}
			*slash++ = '\0';
			if (parse_uint(v, 2, KGP_MAX_REPEAT, &r->repeat_n) ||
			    parse_uint(slash, 1, 86400, &r->repeat_window_s)) {
				set_err(err, errlen, "bad repeat (N is 2-16, SEC is 1-86400)");
				return -1;
			}
		} else if (!strcmp(k, "do")) {
			if (parse_action_list(pol, v, &r->do_mask, err, errlen))
				return -1;
			have_do = 1;
		} else if (!strcmp(k, "then")) {
			thenlist = v;
			have_then = 1;
		} else {
			set_err(err, errlen, "unknown rule option '%s'", k);
			return -1;
		}
	}

	if (!have_do) {
		set_err(err, errlen, "rule '%s' has no do= actions", r->name);
		return -1;
	}
	if (have_then && parse_action_list(pol, thenlist, &r->then_mask, err, errlen))
		return -1;
	if (have_then && !r->repeat_n && !r->unacked_s) {
		set_err(err, errlen, "rule '%s': then= needs repeat= or unacked=", r->name);
		return -1;
	}
	if (!have_then && (r->repeat_n || r->unacked_s)) {
		set_err(err, errlen, "rule '%s': repeat=/unacked= need then= actions", r->name);
		return -1;
	}
	pol->nrules++;
	return 0;
}

int kgp_parse(struct kgp_policy *pol, const char *text, int check_fs, char *err, size_t errlen)
{
	char *copy = strdup(text), *line;
	int lineno = 0, ret = 0;

	memset(pol, 0, sizeof(*pol));
	if (err && errlen)
		err[0] = '\0';
	if (!copy) {
		set_err(err, errlen, "out of memory");
		return 1;
	}

	for (char *p = copy; *p && !ret;) {
		char *tok[KGP_MAX_ARGS + 4];
		int n;

		line = p;
		p = strchr(p, '\n');
		if (p)
			*p++ = '\0';
		else
			p = line + strlen(line);
		lineno++;

		n = tokenize(line, tok, KGP_MAX_ARGS + 4);
		if (n < 0) {
			set_err(err, errlen, "unterminated quote or too many words");
			ret = lineno;
			break;
		}
		if (n == 0)
			continue;
		if (!strcmp(tok[0], "action")) {
			if (parse_action(pol, tok, n, check_fs, err, errlen))
				ret = lineno;
		} else if (!strcmp(tok[0], "rule")) {
			if (parse_rule(pol, tok, n, err, errlen))
				ret = lineno;
		} else {
			set_err(err, errlen, "unknown directive '%s' (expected action or rule)", tok[0]);
			ret = lineno;
		}
	}
	free(copy);
	if (ret)
		kgp_free(pol);
	return ret;
}

void kgp_free(struct kgp_policy *pol)
{
	for (int i = 0; i < pol->nactions; i++)
		for (int k = 0; k < pol->actions[i].argc; k++)
			free(pol->actions[i].argv[k]);
	memset(pol, 0, sizeof(*pol));
}

int kgp_load_file(struct kgp_policy *pol, const char *path, char *err, size_t errlen)
{
	struct stat st;
	char *buf;
	ssize_t got;
	int fd, ret;

	memset(pol, 0, sizeof(*pol));
	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		set_err(err, errlen, "%s: %s", path, strerror(errno));
		return -1;
	}
	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
		set_err(err, errlen, "%s is not a regular file", path);
		close(fd);
		return -1;
	}
	if (st.st_mode & (S_IWGRP | S_IWOTH)) {
		set_err(err, errlen, "%s is writable by group or others; refusing to use it (chmod go-w)", path);
		close(fd);
		return -1;
	}
	if (st.st_uid != 0 && st.st_uid != geteuid()) {
		set_err(err, errlen, "%s is not owned by root or by this user; refusing to use it", path);
		close(fd);
		return -1;
	}
	if (st.st_size > 256 * 1024) {
		set_err(err, errlen, "%s is unreasonably large", path);
		close(fd);
		return -1;
	}

	buf = malloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);
		set_err(err, errlen, "out of memory");
		return -1;
	}
	got = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (got < 0) {
		set_err(err, errlen, "%s: %s", path, strerror(errno));
		free(buf);
		return -1;
	}
	buf[got] = '\0';

	ret = kgp_parse(pol, buf, 1, err, errlen);
	free(buf);
	if (ret) {
		/* Prefix the line number so the caller can print one line. */
		char tmp[256];

		snprintf(tmp, sizeof(tmp), "%s:%d: %s", path, ret, err && errlen ? err : "");
		if (err && errlen)
			snprintf(err, errlen, "%s", tmp);
		return -1;
	}
	return 0;
}

/*----------------------------------------------------------------------------
 * Engine
 *--------------------------------------------------------------------------*/
void kgp_init(struct kgp_engine *e, const struct kgp_policy *pol)
{
	memset(e, 0, sizeof(*e));
	e->pol = pol;
}

static int rule_matches(const struct kgp_rule *r, const struct kgp_alert *al)
{
	if (al->level < r->min_level)
		return 0;
	if (!r->ncodes)
		return 1;
	for (int i = 0; i < r->ncodes; i++)
		if (r->codes[i] == al->code)
			return 1;
	return 0;
}

static void run_mask(struct kgp_engine *e, uint32_t mask, const struct kgp_rule *r,
		     const struct kgp_incident *in, int tier, kgp_run_fn run, void *ctx)
{
	for (int i = 0; i < e->pol->nactions; i++)
		if (mask & (1u << i))
			run(ctx, e->pol, &e->pol->actions[i], r, &in->last, tier, in->count, in->first_s);
}

/* Find the incident for (rule, code, p1), or take a free / the least recently used slot. */
static struct kgp_incident *incident_slot(struct kgp_engine *e, int rule, uint32_t code, uint64_t p1, int *fresh)
{
	struct kgp_incident *free_slot = NULL, *oldest = NULL;

	for (int i = 0; i < KGP_MAX_INCIDENTS; i++) {
		struct kgp_incident *in = &e->inc[i];

		if (in->used && in->rule == rule && in->code == code && in->p1 == p1) {
			*fresh = 0;
			return in;
		}
		if (!in->used && !free_slot)
			free_slot = in;
		if (in->used && (!oldest || in->last_s < oldest->last_s))
			oldest = in;
	}
	*fresh = 1;
	return free_slot ? free_slot : oldest;
}

void kgp_alert(struct kgp_engine *e, uint64_t now_s, const struct kgp_alert *al, kgp_run_fn run, void *ctx)
{
	for (int ri = 0; ri < e->pol->nrules; ri++) {
		const struct kgp_rule *r = &e->pol->rules[ri];
		struct kgp_incident *in;
		int fresh, run_base;

		if (!rule_matches(r, al))
			continue;

		in = incident_slot(e, ri, al->code, al->param1, &fresh);
		if (!fresh && in->acked) {
			/* It came back after somebody acknowledged it: a new episode. */
			fresh = 1;
		}
		if (fresh) {
			memset(in, 0, sizeof(*in));
			in->used = 1;
			in->rule = ri;
			in->code = al->code;
			in->p1 = al->param1;
			in->first_s = now_s;
		}

		in->last = *al;
		in->last_s = now_s;
		in->last_seq = al->seq;
		in->recent[in->count % KGP_MAX_REPEAT] = now_s;
		in->count++;

		run_base = fresh || now_s - in->last_run_s >= r->throttle_s;
		if (run_base) {
			in->last_run_s = now_s;
			run_mask(e, r->do_mask, r, in, 0, run, ctx);
		}

		if (r->repeat_n && !in->escalated && in->count >= r->repeat_n) {
			/* The Nth most recent arrival, with the newest at (count - 1) % N. */
			uint64_t nth = in->recent[(in->count - r->repeat_n) % KGP_MAX_REPEAT];

			if (now_s - nth <= r->repeat_window_s) {
				in->escalated = 1;
				run_mask(e, r->then_mask, r, in, 1, run, ctx);
			}
		}
	}
}

void kgp_tick(struct kgp_engine *e, uint64_t now_s, kgp_run_fn run, void *ctx)
{
	for (int i = 0; i < KGP_MAX_INCIDENTS; i++) {
		struct kgp_incident *in = &e->inc[i];
		const struct kgp_rule *r;

		if (!in->used)
			continue;
		r = &e->pol->rules[in->rule];

		if (now_s - in->last_s >= r->reset_s) {
			memset(in, 0, sizeof(*in));
			continue;
		}
		if (r->unacked_s && !in->acked && !in->escalated && now_s - in->first_s >= r->unacked_s) {
			in->escalated = 1;
			run_mask(e, r->then_mask, r, in, 1, run, ctx);
		}
	}
}

void kgp_ack(struct kgp_engine *e, uint32_t up_to_seq)
{
	for (int i = 0; i < KGP_MAX_INCIDENTS; i++) {
		struct kgp_incident *in = &e->inc[i];

		/* wrap-safe: last_seq <= up_to_seq */
		if (in->used && (int32_t)(up_to_seq - in->last_seq) >= 0)
			in->acked = 1;
	}
}

unsigned kgp_open_incidents(const struct kgp_engine *e)
{
	unsigned n = 0;

	for (int i = 0; i < KGP_MAX_INCIDENTS; i++)
		n += e->inc[i].used && !e->inc[i].acked;
	return n;
}

/*----------------------------------------------------------------------------
 * Self-test (no forking, no clock: the engine is driven with a made-up time)
 *--------------------------------------------------------------------------*/
struct st_log {
	int base, esc;
	char last_action[KGP_NAME_LEN];
	uint32_t last_count;
};

static void st_run(void *ctx, const struct kgp_policy *pol, const struct kgp_action *act,
		   const struct kgp_rule *rule, const struct kgp_alert *al, int tier,
		   uint32_t count, uint64_t first_s)
{
	struct st_log *l = ctx;

	(void)pol; (void)rule; (void)al; (void)first_s;
	if (tier)
		l->esc++;
	else
		l->base++;
	snprintf(l->last_action, sizeof(l->last_action), "%s", act->name);
	l->last_count = count;
}

static int st_fail;
#define ST_CHECK(cond, what) do { if (!(cond)) { fprintf(stderr, "  policy self-test FAILED: %s\n", what); st_fail++; } } while (0)

static struct kgp_alert st_alert(uint32_t code, int level, uint32_t seq, uint64_t p1)
{
	struct kgp_alert a;

	memset(&a, 0, sizeof(a));
	a.code = code;
	a.level = level;
	a.seq = seq;
	a.param1 = p1;
	return a;
}

int kgp_selftest(void)
{
	static const char *const good =
		"# a comment\n"
		"\n"
		"action page   /bin/true\n"
		"action ticket timeout=5 /bin/true \"an arg\" --x=1\n"
		"rule kbd    alert=UNAUTHORIZED_KBD_FILTER,0x0013 level=warning throttle=30 do=ticket repeat=3/60 then=page\n"
		"rule kernel alert=TEXT_PATCH,IDT_HOOK level=critical do=page,ticket\n"
		"rule slow   alert=PCI_DISCREPANCY do=ticket unacked=100 then=page\n"
		"rule forged alert=FORGED,OVERRUN,TAMPER level=forged throttle=0 do=page\n";
	struct kgp_policy pol;
	struct kgp_engine eng;
	struct kgp_alert a;
	struct st_log lg;
	char err[200];
	int line;

	st_fail = 0;

	/* ---- parsing ---- */
	line = kgp_parse(&pol, good, 0, err, sizeof(err));
	ST_CHECK(line == 0, "a valid policy parses");
	if (line) {
		fprintf(stderr, "    %d: %s\n", line, err);
		return st_fail;
	}
	ST_CHECK(pol.nactions == 2 && pol.nrules == 4, "2 actions and 4 rules were read");
	ST_CHECK(pol.actions[1].argc == 3 && !strcmp(pol.actions[1].argv[1], "an arg"), "quoted argument kept as one word");
	ST_CHECK(pol.actions[1].timeout_s == 5, "timeout= read");
	ST_CHECK(pol.rules[0].ncodes == 2 && pol.rules[0].codes[1] == 0x13, "alert list by name and by code");
	ST_CHECK(pol.rules[0].repeat_n == 3 && pol.rules[0].repeat_window_s == 60, "repeat=3/60 read");

	{
		static const struct { const char *text; int line; const char *why; } bad[] = {
			{ "rule r do=nothing\n", 1, "unknown action" },
			{ "action a /bin/true\nrule r alert=NOPE do=a\n", 2, "unknown alert type" },
			{ "action a /bin/true\nrule r level=loud do=a\n", 2, "unknown level" },
			{ "action a /bin/true\nrule r alert=IDT_HOOK\n", 2, "missing do=" },
			{ "action a /bin/true\nrule r do=a repeat=3/60\n", 2, "repeat without then" },
			{ "action a /bin/true\nrule r do=a then=a\n", 2, "then without repeat/unacked" },
			{ "action a relative/path\n", 1, "relative program path" },
			{ "action a\n", 1, "action without program" },
			{ "action a /bin/true\naction a /bin/true\n", 2, "duplicate action" },
			{ "\n\nbogus line\n", 3, "unknown directive, right line number after blanks" },
			{ "action a /bin/true \"unterminated\n", 1, "unterminated quote" },
			{ "action a /bin/true\nrule r do=a repeat=1/60 then=a\n", 2, "repeat needs at least 2" },
		};

		for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
			struct kgp_policy p;
			int l = kgp_parse(&p, bad[i].text, 0, err, sizeof(err));
			char what[96];

			snprintf(what, sizeof(what), "rejects: %s (line %d, got %d)", bad[i].why, bad[i].line, l);
			ST_CHECK(l == bad[i].line, what);
			if (!l)
				kgp_free(&p);
		}
	}

	/* ---- levels and matching ---- */
	kgp_init(&eng, &pol);
	memset(&lg, 0, sizeof(lg));
	a = st_alert(KG_ALERT_UNAUTHORIZED_KBD_FILTER, KGP_INFO, 1, 7);
	kgp_alert(&eng, 1000, &a, st_run, &lg);
	ST_CHECK(lg.base == 0, "an INFO alert does not match a level=warning rule");
	a = st_alert(KG_ALERT_TEXT_PATCH, KGP_WARNING, 2, 0);
	kgp_alert(&eng, 1000, &a, st_run, &lg);
	ST_CHECK(lg.base == 0, "a WARNING text patch does not match a level=critical rule");
	a = st_alert(KG_ALERT_TEXT_PATCH, KGP_CRITICAL, 3, 0);
	kgp_alert(&eng, 1000, &a, st_run, &lg);
	ST_CHECK(lg.base == 2, "a CRITICAL text patch runs both actions of its rule");

	/* ---- throttle, then escalation by repetition ---- */
	memset(&lg, 0, sizeof(lg));
	kgp_init(&eng, &pol);
	a = st_alert(KG_ALERT_UNAUTHORIZED_KBD_FILTER, KGP_WARNING, 10, 0xabc);
	kgp_alert(&eng, 2000, &a, st_run, &lg);
	ST_CHECK(lg.base == 1 && lg.esc == 0, "first alert runs the base action");
	a.seq = 11;
	kgp_alert(&eng, 2010, &a, st_run, &lg);
	ST_CHECK(lg.base == 1, "a repeat inside the throttle window runs nothing");
	a.seq = 12;
	kgp_alert(&eng, 2020, &a, st_run, &lg);
	ST_CHECK(lg.esc == 1 && !strcmp(lg.last_action, "page") && lg.last_count == 3,
		 "3 arrivals within 60 s escalate once, to the then= action, with the count");
	a.seq = 13;
	kgp_alert(&eng, 2025, &a, st_run, &lg);
	kgp_alert(&eng, 2026, &a, st_run, &lg);
	ST_CHECK(lg.esc == 1, "an incident escalates only once");
	a.seq = 14;
	kgp_alert(&eng, 2040, &a, st_run, &lg);
	ST_CHECK(lg.base == 2, "after the throttle window the base action runs again");

	/* a different offender is a different incident */
	{
		struct st_log l2 = { 0 };
		struct kgp_alert b = st_alert(KG_ALERT_UNAUTHORIZED_KBD_FILTER, KGP_WARNING, 20, 0xdef);

		kgp_alert(&eng, 2041, &b, st_run, &l2);
		ST_CHECK(l2.base == 1, "another offender (param1) is its own incident and runs the base action");
	}

	/* slow repeats do not escalate */
	memset(&lg, 0, sizeof(lg));
	kgp_init(&eng, &pol);
	a = st_alert(KG_ALERT_UNAUTHORIZED_KBD_FILTER, KGP_WARNING, 30, 1);
	kgp_alert(&eng, 3000, &a, st_run, &lg);
	kgp_alert(&eng, 3100, &a, st_run, &lg);
	kgp_alert(&eng, 3200, &a, st_run, &lg);
	ST_CHECK(lg.esc == 0, "3 arrivals spread over 200 s do not meet repeat=3/60");

	/* the repeat window is inclusive: 3 arrivals exactly 60 s apart from first to last escalate, 61 s do not */
	memset(&lg, 0, sizeof(lg));
	kgp_init(&eng, &pol);
	a = st_alert(KG_ALERT_UNAUTHORIZED_KBD_FILTER, KGP_WARNING, 80, 2);
	kgp_alert(&eng, 3500, &a, st_run, &lg);
	kgp_alert(&eng, 3530, &a, st_run, &lg);
	kgp_alert(&eng, 3560, &a, st_run, &lg);
	ST_CHECK(lg.esc == 1, "3 arrivals spanning exactly the 60 s window escalate");
	memset(&lg, 0, sizeof(lg));
	kgp_init(&eng, &pol);
	kgp_alert(&eng, 3500, &a, st_run, &lg);
	kgp_alert(&eng, 3530, &a, st_run, &lg);
	kgp_alert(&eng, 3561, &a, st_run, &lg);
	ST_CHECK(lg.esc == 0, "3 arrivals spanning 61 s do not");

	/* ---- escalation by age until acknowledged ---- */
	memset(&lg, 0, sizeof(lg));
	kgp_init(&eng, &pol);
	a = st_alert(KG_ALERT_PCI_DISCREPANCY, KGP_WARNING, 40, 5);
	kgp_alert(&eng, 4000, &a, st_run, &lg);
	kgp_tick(&eng, 4050, st_run, &lg);
	ST_CHECK(lg.esc == 0, "not escalated before unacked= has passed");
	kgp_tick(&eng, 4100, st_run, &lg);
	ST_CHECK(lg.esc == 1 && !strcmp(lg.last_action, "page"), "escalated after 100 s unacknowledged");
	kgp_tick(&eng, 4200, st_run, &lg);
	ST_CHECK(lg.esc == 1, "and only once");

	memset(&lg, 0, sizeof(lg));
	kgp_init(&eng, &pol);
	a = st_alert(KG_ALERT_PCI_DISCREPANCY, KGP_WARNING, 50, 5);
	kgp_alert(&eng, 5000, &a, st_run, &lg);
	ST_CHECK(kgp_open_incidents(&eng) == 1, "one open incident");
	kgp_ack(&eng, 50);
	ST_CHECK(kgp_open_incidents(&eng) == 0, "acknowledged");
	kgp_tick(&eng, 5500, st_run, &lg);
	ST_CHECK(lg.esc == 0, "an acknowledged incident never escalates");
	a.seq = 51;
	kgp_alert(&eng, 5600, &a, st_run, &lg);
	ST_CHECK(lg.base == 2 && kgp_open_incidents(&eng) == 1, "a repeat after the ack is a new incident (base action runs again)");
	kgp_ack(&eng, 49);
	ST_CHECK(kgp_open_incidents(&eng) == 1, "an ack that predates the alert does not cover it");
	kgp_tick(&eng, 5700, st_run, &lg);
	ST_CHECK(lg.esc == 1, "the new incident escalates on its own clock");

	/* ---- forged notifications, sequence wrap, reset ---- */
	memset(&lg, 0, sizeof(lg));
	kgp_init(&eng, &pol);
	a = st_alert(KGP_ALERT_FORGED, KGP_FORGED, 60, 0);
	kgp_alert(&eng, 6000, &a, st_run, &lg);
	kgp_alert(&eng, 6000, &a, st_run, &lg);
	ST_CHECK(lg.base == 2, "throttle=0 runs the action on every forged notification");
	a = st_alert(KGP_ALERT_FORGED, KGP_CRITICAL, 61, 0);
	{
		struct st_log l3 = { 0 };

		kgp_alert(&eng, 6001, &a, st_run, &l3);
		ST_CHECK(l3.base == 0, "a level=forged rule ignores lower levels");
	}
	kgp_init(&eng, &pol);
	a = st_alert(KG_ALERT_PCI_DISCREPANCY, KGP_WARNING, 0xfffffffeu, 9);
	memset(&lg, 0, sizeof(lg));
	kgp_alert(&eng, 7000, &a, st_run, &lg);
	kgp_ack(&eng, 2);                       /* sequence numbers wrapped past the alert */
	ST_CHECK(kgp_open_incidents(&eng) == 0, "ack comparison survives 32-bit sequence wrap");

	kgp_init(&eng, &pol);
	a = st_alert(KG_ALERT_PCI_DISCREPANCY, KGP_WARNING, 70, 9);
	kgp_alert(&eng, 8000, &a, st_run, &lg);
	kgp_tick(&eng, 8000 + 3600, st_run, &lg);
	ST_CHECK(kgp_open_incidents(&eng) == 0, "a silent incident is forgotten after reset= seconds");

	/* ---- a full table evicts the least recently used incident, never crashes ---- */
	kgp_init(&eng, &pol);
	for (uint32_t i = 0; i < KGP_MAX_INCIDENTS + 10; i++) {
		a = st_alert(KG_ALERT_PCI_DISCREPANCY, KGP_WARNING, 100 + i, i);
		kgp_alert(&eng, 9000 + i, &a, st_run, &lg);
	}
	ST_CHECK(kgp_open_incidents(&eng) == KGP_MAX_INCIDENTS, "incident table stays bounded");

	kgp_free(&pol);
	return st_fail;
}
