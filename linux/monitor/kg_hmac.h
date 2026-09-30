/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kg_hmac.h - self-contained SHA-256 / HMAC-SHA256 for the monitor.
 *
 * The Windows monitor calls BCrypt; on Linux the equivalent would be OpenSSL or
 * the kernel AF_ALG socket.  The monitor is the component that decides whether
 * a kernel alert is genuine, so it carries its own ~100-line implementation
 * (checked against FIPS 180-4 / RFC 4231 vectors by `kgmon selftest`) instead
 * of depending on a library that a compromised system could interpose.
 */
#ifndef KG_HMAC_H
#define KG_HMAC_H

#include <stddef.h>
#include <stdint.h>

struct kg_sha256 {
	uint32_t h[8];
	uint64_t total;
	uint8_t  buf[64];
	size_t   fill;
};

void kg_sha256_init(struct kg_sha256 *c);
void kg_sha256_update(struct kg_sha256 *c, const void *data, size_t len);
void kg_sha256_final(struct kg_sha256 *c, uint8_t out[32]);

void kg_hmac_sha256(const uint8_t *key, size_t keylen,
		    const void *msg, size_t msglen, uint8_t out[32]);

/* Constant-time comparison: returns 1 when equal. */
int kg_ct_equal(const void *a, const void *b, size_t n);

/* Returns 0 when every built-in test vector passes. */
int kg_hmac_selftest(void);

#endif
