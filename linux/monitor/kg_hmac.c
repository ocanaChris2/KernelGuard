// SPDX-License-Identifier: GPL-2.0
/* kg_hmac.c - SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104). */
#include <stdlib.h>
#include <string.h>

#include "kg_hmac.h"

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(uint32_t h[8], const uint8_t p[64])
{
	uint32_t w[64], a, b, c, d, e, f, g, hh, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)p[i * 4] << 24 | (uint32_t)p[i * 4 + 1] << 16 |
		       (uint32_t)p[i * 4 + 2] << 8 | (uint32_t)p[i * 4 + 3];
	for (; i < 64; i++) {
		uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = h[0]; b = h[1]; c = h[2]; d = h[3];
	e = h[4]; f = h[5]; g = h[6]; hh = h[7];

	for (i = 0; i < 64; i++) {
		t1 = hh + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
		t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
		hh = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	h[0] += a; h[1] += b; h[2] += c; h[3] += d;
	h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

void kg_sha256_init(struct kg_sha256 *c)
{
	static const uint32_t iv[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
	};

	memcpy(c->h, iv, sizeof(iv));
	c->total = 0;
	c->fill = 0;
}

void kg_sha256_update(struct kg_sha256 *c, const void *data, size_t len)
{
	const uint8_t *p = data;

	c->total += len;
	while (len) {
		size_t n = 64 - c->fill;

		if (n > len)
			n = len;
		memcpy(c->buf + c->fill, p, n);
		c->fill += n;
		p += n;
		len -= n;
		if (c->fill == 64) {
			sha256_block(c->h, c->buf);
			c->fill = 0;
		}
	}
}

void kg_sha256_final(struct kg_sha256 *c, uint8_t out[32])
{
	uint64_t bits = c->total * 8;
	uint8_t pad = 0x80;
	uint8_t zero = 0;
	uint8_t len[8];
	int i;

	kg_sha256_update(c, &pad, 1);
	while (c->fill != 56)
		kg_sha256_update(c, &zero, 1);
	for (i = 0; i < 8; i++)
		len[i] = (uint8_t)(bits >> (56 - 8 * i));
	kg_sha256_update(c, len, 8);

	for (i = 0; i < 8; i++) {
		out[i * 4]     = (uint8_t)(c->h[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
		out[i * 4 + 3] = (uint8_t)c->h[i];
	}
}

void kg_hmac_sha256(const uint8_t *key, size_t keylen,
		    const void *msg, size_t msglen, uint8_t out[32])
{
	uint8_t k[64] = { 0 }, ipad[64], opad[64], inner[32];
	struct kg_sha256 c;
	size_t i;

	if (keylen > 64) {
		kg_sha256_init(&c);
		kg_sha256_update(&c, key, keylen);
		kg_sha256_final(&c, k);
	} else {
		memcpy(k, key, keylen);
	}
	for (i = 0; i < 64; i++) {
		ipad[i] = k[i] ^ 0x36;
		opad[i] = k[i] ^ 0x5c;
	}

	kg_sha256_init(&c);
	kg_sha256_update(&c, ipad, 64);
	kg_sha256_update(&c, msg, msglen);
	kg_sha256_final(&c, inner);

	kg_sha256_init(&c);
	kg_sha256_update(&c, opad, 64);
	kg_sha256_update(&c, inner, 32);
	kg_sha256_final(&c, out);

	memset(k, 0, sizeof(k));
	memset(ipad, 0, sizeof(ipad));
	memset(opad, 0, sizeof(opad));
}

int kg_ct_equal(const void *a, const void *b, size_t n)
{
	const volatile uint8_t *x = a, *y = b;
	uint8_t diff = 0;
	size_t i;

	for (i = 0; i < n; i++)
		diff |= x[i] ^ y[i];
	return diff == 0;
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	return -1;
}

static int hex_eq(const uint8_t *got, const char *want_hex)
{
	uint8_t want[32];
	int i;

	for (i = 0; i < 32; i++) {
		int hi = hexval(want_hex[2 * i]), lo = hexval(want_hex[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return 0;
		want[i] = (uint8_t)(hi << 4 | lo);
	}
	return kg_ct_equal(got, want, 32);
}

static int sha_case(const void *msg, size_t len, const char *want)
{
	struct kg_sha256 c;
	uint8_t d[32];

	kg_sha256_init(&c);
	kg_sha256_update(&c, msg, len);
	kg_sha256_final(&c, d);
	return hex_eq(d, want);
}

static int hmac_case(const void *key, size_t klen, const void *msg, size_t mlen,
		     const char *want)
{
	uint8_t d[32];

	kg_hmac_sha256(key, klen, msg, mlen, d);
	return hex_eq(d, want);
}

int kg_hmac_selftest(void)
{
	static const char two_block[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	uint8_t k20[20], k131[131];
	struct kg_sha256 c;
	uint8_t d[32];
	char *million;
	int fail = 0, i;

	/* FIPS 180-4 / NIST examples */
	fail += !sha_case("", 0,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	fail += !sha_case("abc", 3,
		"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
	fail += !sha_case(two_block, strlen(two_block),
		"248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

	/* one million 'a' - exercises many blocks and the streaming update path */
	million = malloc(1000000);
	if (million) {
		memset(million, 'a', 1000000);
		kg_sha256_init(&c);
		for (i = 0; i < 1000000; i += 999)       /* uneven chunking on purpose */
			kg_sha256_update(&c, million + i, (1000000 - i) < 999 ? (size_t)(1000000 - i) : 999);
		kg_sha256_final(&c, d);
		fail += !hex_eq(d, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
		free(million);
	} else {
		fail++;
	}

	/* RFC 4231 test cases 1, 2 and 6 (key longer than the block size) */
	memset(k20, 0x0b, sizeof(k20));
	fail += !hmac_case(k20, sizeof(k20), "Hi There", 8,
		"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
	fail += !hmac_case("Jefe", 4, "what do ya want for nothing?", 28,
		"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
	memset(k131, 0xaa, sizeof(k131));
	fail += !hmac_case(k131, sizeof(k131),
		"Test Using Larger Than Block-Size Key - Hash Key First", 54,
		"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

	return fail;
}
