// SPDX-License-Identifier: GPL-2.0-only
/*
 * fuzz_policy.c - fuzz harness for the escalation policy parser and engine (kg_policy.c).
 *
 * Two ways to run it:
 *
 *   make fuzz-libfuzzer        needs clang; coverage guided
 *       ./fuzz/fuzz_policy_lf fuzz/corpus -max_total_time=300
 *
 *   make fuzz                  any gcc/clang; no libFuzzer needed. Mutates the corpus (bit flips,
 *       ./fuzz/fuzz_policy 200000         byte and line splices, truncation, duplication) with a
 *                                         fixed seed under AddressSanitizer + UBSan
 *
 * The input is policy text. Whatever parses is then driven through the engine with alerts, ticks
 * and acknowledgements derived from the same bytes, checking the engine's own invariants.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../kg_policy.h"

static void nop_run(void *ctx, const struct kgp_policy *pol, const struct kgp_action *act,
		    const struct kgp_rule *rule, const struct kgp_alert *al, int tier,
		    uint32_t count, uint64_t first_s)
{
	(void)pol; (void)act; (void)rule; (void)al; (void)tier; (void)count; (void)first_s;
	(*(unsigned long *)ctx)++;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct kgp_policy pol;
	struct kgp_engine eng;
	unsigned long runs = 0;
	char err[256];
	char *text = malloc(size + 1);
	uint64_t now = 1000;

	if (!text)
		return 0;
	memcpy(text, data, size);
	text[size] = '\0';

	if (kgp_parse(&pol, text, 0, err, sizeof(err)) == 0) {
		kgp_init(&eng, &pol);
		/* Drive the engine from the input bytes: (code, level, param, dt) tuples. */
		for (size_t i = 0; i + 3 < size && i < 4000; i += 4) {
			struct kgp_alert a;

			memset(&a, 0, sizeof(a));
			a.code = (uint32_t)(uint8_t)text[i] % 0x40u;
			a.level = (uint8_t)text[i + 1] % 4;
			a.param1 = (uint8_t)text[i + 2] % 5;
			a.seq = (uint32_t)i;
			now += (uint8_t)text[i + 3];
			switch ((uint8_t)text[i] >> 6) {
			case 0: case 1:
				kgp_alert(&eng, now, &a, nop_run, &runs);
				break;
			case 2:
				kgp_tick(&eng, now, nop_run, &runs);
				break;
			default:
				kgp_ack(&eng, a.seq);
				break;
			}
			if (kgp_open_incidents(&eng) > KGP_MAX_INCIDENTS)
				abort();
		}
		kgp_free(&pol);
	}
	free(text);
	return 0;
}

#ifndef FUZZ_LIBFUZZER
/* ---- standalone mutation driver ---- */
static uint64_t rng_state = 0x9E3779B97F4A7C15ull;

static uint32_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return (uint32_t)(rng_state >> 16);
}

static size_t mutate(uint8_t *buf, size_t len, size_t cap, const uint8_t *other, size_t olen)
{
	int n = 1 + (int)(rnd() % 4);

	while (n--) {
		switch (rnd() % 7) {
		case 0:  if (len) buf[rnd() % len] ^= (uint8_t)(1u << (rnd() % 8)); break;
		case 1:  if (len) buf[rnd() % len] = (uint8_t)rnd(); break;
		case 2:  if (len) len = rnd() % (len + 1); break;                        /* truncate */
		case 3:  if (len && len + 1 < cap) {                                     /* insert byte */
				 size_t at = rnd() % len;
				 memmove(buf + at + 1, buf + at, len - at);
				 buf[at] = (uint8_t)("=,/\"\n #\\x0"[rnd() % 10]);
				 len++;
			 }
			 break;
		case 4:  if (len && olen) {                                              /* splice a chunk of another seed */
				 size_t from = rnd() % olen, n2 = 1 + rnd() % 40, at = rnd() % (len + 1);
				 if (from + n2 > olen) n2 = olen - from;
				 if (len + n2 < cap) {
					 memmove(buf + at + n2, buf + at, len - at);
					 memcpy(buf + at, other + from, n2);
					 len += n2;
				 }
			 }
			 break;
		case 5:  if (len && len * 2 < cap) { memcpy(buf + len, buf, len); len *= 2; } break;   /* duplicate */
		default: if (len > 1) { size_t a = rnd() % len, b = rnd() % len; uint8_t t = buf[a]; buf[a] = buf[b]; buf[b] = t; } break;
		}
	}
	return len;
}

int main(int argc, char **argv)
{
	unsigned long iters = argc > 1 ? strtoul(argv[1], NULL, 10) : 100000;
	enum { MAX_SEEDS = 64, CAP = 1 << 16 };
	static uint8_t seeds[MAX_SEEDS][CAP];
	size_t slen[MAX_SEEDS];
	static uint8_t work[CAP];
	int nseeds = 0;

	for (int i = 2; i < argc && nseeds < MAX_SEEDS; i++) {
		FILE *f = fopen(argv[i], "rb");

		if (!f) {
			perror(argv[i]);
			return 2;
		}
		slen[nseeds] = fread(seeds[nseeds], 1, CAP - 1, f);
		fclose(f);
		nseeds++;
	}
	if (!nseeds) {
		strcpy((char *)seeds[0], "action a /bin/true\nrule r do=a\n");
		slen[0] = strlen((char *)seeds[0]);
		nseeds = 1;
	}

	for (unsigned long i = 0; i < iters; i++) {
		int s = (int)(rnd() % (unsigned)nseeds), o = (int)(rnd() % (unsigned)nseeds);
		size_t len = slen[s];

		memcpy(work, seeds[s], len);
		len = mutate(work, len, CAP, seeds[o], slen[o]);
		LLVMFuzzerTestOneInput(work, len);
	}
	printf("fuzz_policy: %lu inputs from %d seed(s), no crash, no sanitizer report\n", iters, nseeds);
	return 0;
}
#endif
