// SPDX-License-Identifier: GPL-2.0-only
/*
 * kg_modid.c - read a kernel module's identity from its ELF file (see kg_modid.h).
 *
 * Only what is needed: the section header table, the section-name table and .modinfo.  The
 * module is a 64-bit little-endian ET_REL object; anything else is refused rather than guessed
 * at.  All arithmetic on file offsets is done in 64 bits and compared against the length before
 * use, so a hostile header cannot make this read outside the buffer.
 */
#include <stdio.h>
#include <string.h>

#include "kg_hmac.h"
#include "kg_modid.h"

#define SHDR_SIZE       64
#define SHT_STRTAB      3
#define SHT_NOBITS      8
#define ET_REL          1

/* modules/module-signature.h: the marker sits after the signature, at the very end of the file */
static const char kg_sig_marker[] = "~Module signature appended~\n";
#define KG_SIG_MARKER_LEN (sizeof(kg_sig_marker) - 1)

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)(p[0] | (p[1] << 8));
}

static uint32_t rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
	return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

struct sec {
	uint32_t name, type;
	uint64_t off, size;
};

static void read_sec(const uint8_t *img, uint64_t shoff, unsigned idx, struct sec *s)
{
	const uint8_t *h = img + shoff + (uint64_t)idx * SHDR_SIZE;     /* the table was bounds-checked whole */

	s->name = rd32(h);
	s->type = rd32(h + 4);
	s->off = rd64(h + 24);
	s->size = rd64(h + 32);
}

/* The section's bytes are inside the file (SHT_NOBITS sections have none, so they never qualify). */
static int sec_in_file(const struct sec *s, size_t len)
{
	return s->type != SHT_NOBITS && s->off <= len && s->size <= len - s->off;
}

static int name_chars_ok(const char *s)
{
	if (!*s)
		return 0;
	for (; *s; s++)
		if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') ||
		      *s == '_' || *s == '-' || *s == '.'))
			return 0;
	return 1;
}

static int hex_chars_ok(const char *s)
{
	if (!*s)
		return 0;
	for (; *s; s++)
		if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'f') || (*s >= 'A' && *s <= 'F')))
			return 0;
	return 1;
}

/*
 * .modinfo is a run of NUL-terminated "key=value" strings.  The first occurrence of each wanted
 * key wins.  A value that does not fit its field is an error, not a silent truncation: the entry
 * printed for mod_deny= would otherwise be wrong.
 */
static int parse_modinfo(const uint8_t *p, uint64_t size, struct kg_modid *out)
{
	static const struct {
		const char *key;
		size_t off, cap;
	} want[] = {
		{ "name",       offsetof(struct kg_modid, name),       KG_MODID_NAME_MAX },
		{ "srcversion", offsetof(struct kg_modid, srcversion), KG_MODID_SRCVER_MAX },
		{ "version",    offsetof(struct kg_modid, version),    KG_MODID_STR_MAX },
		{ "vermagic",   offsetof(struct kg_modid, vermagic),   KG_MODID_STR_MAX },
	};
	int seen[sizeof(want) / sizeof(want[0])] = { 0 };
	const uint8_t *end = p + size;

	while (p < end) {
		const uint8_t *nul = memchr(p, 0, (size_t)(end - p));
		size_t n = nul ? (size_t)(nul - p) : (size_t)(end - p);

		for (size_t i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
			size_t kl = strlen(want[i].key);

			if (seen[i] || n <= kl + 1 || memcmp(p, want[i].key, kl) || p[kl] != '=')
				continue;
			if (n - kl - 1 >= want[i].cap)
				return KG_MODID_E_BAD_FIELD;
			memcpy((char *)out + want[i].off, p + kl + 1, n - kl - 1);
			seen[i] = 1;
		}
		p += n + 1;
	}

	if (!out->name[0])
		return KG_MODID_E_NO_NAME;
	if (!name_chars_ok(out->name) || (out->srcversion[0] && !hex_chars_ok(out->srcversion)))
		return KG_MODID_E_BAD_FIELD;
	return KG_MODID_OK;
}

int kg_modid_parse(const uint8_t *img, size_t len, struct kg_modid *out)
{
	uint64_t shoff;
	unsigned shnum, shstrndx, i;
	struct sec strs, s;
	const char *names;
	struct kg_sha256 h;
	int rc;

	memset(out, 0, sizeof(*out));

	if ((len >= 2 && img[0] == 0x1f && img[1] == 0x8b) ||                    /* gzip */
	    (len >= 4 && !memcmp(img, "\x28\xb5\x2f\xfd", 4)) ||                 /* zstd */
	    (len >= 6 && !memcmp(img, "\xfd" "7zXZ\0", 6)))                      /* xz   */
		return KG_MODID_E_COMPRESSED;
	if (len < 64 || memcmp(img, "\x7f" "ELF", 4))
		return KG_MODID_E_NOT_ELF;
	if (img[4] != 2 || img[5] != 1 || rd16(img + 16) != ET_REL)              /* ELF64, LE, relocatable */
		return KG_MODID_E_UNSUPPORTED;

	shoff = rd64(img + 0x28);
	shnum = rd16(img + 0x3c);
	shstrndx = rd16(img + 0x3e);
	if (rd16(img + 0x3a) != SHDR_SIZE || !shnum || shstrndx >= shnum)
		return KG_MODID_E_BAD_ELF;
	if (shoff > len || (uint64_t)shnum * SHDR_SIZE > len - shoff)
		return KG_MODID_E_BAD_ELF;

	read_sec(img, shoff, shstrndx, &strs);
	if (strs.type != SHT_STRTAB || !sec_in_file(&strs, len) || !strs.size)
		return KG_MODID_E_BAD_ELF;
	names = (const char *)img + strs.off;

	rc = KG_MODID_E_NO_MODINFO;
	for (i = 0; i < shnum; i++) {
		static const char want[] = ".modinfo";

		read_sec(img, shoff, i, &s);
		if (s.name >= strs.size || strs.size - s.name < sizeof(want))
			continue;                       /* name (with its NUL) would run past the table */
		if (memcmp(names + s.name, want, sizeof(want)))
			continue;
		if (!sec_in_file(&s, len))
			return KG_MODID_E_BAD_ELF;
		rc = parse_modinfo(img + s.off, s.size, out);
		break;
	}
	if (rc)
		return rc;

	out->sig_marker = len >= KG_SIG_MARKER_LEN &&
			  !memcmp(img + len - KG_SIG_MARKER_LEN, kg_sig_marker, KG_SIG_MARKER_LEN);
	kg_sha256_init(&h);
	kg_sha256_update(&h, img, len);
	kg_sha256_final(&h, out->sha256);
	return KG_MODID_OK;
}

const char *kg_modid_strerror(int rc)
{
	switch (rc) {
	case KG_MODID_OK:            return "ok";
	case KG_MODID_E_COMPRESSED:  return "compressed module: decompress it first (for example `zstd -dc x.ko.zst | kgmon modid -`)";
	case KG_MODID_E_NOT_ELF:     return "not an ELF file";
	case KG_MODID_E_UNSUPPORTED: return "not a 64-bit little-endian relocatable object (.ko)";
	case KG_MODID_E_BAD_ELF:     return "damaged ELF: a header or section points outside the file";
	case KG_MODID_E_NO_MODINFO:  return "no .modinfo section: not a kernel module";
	case KG_MODID_E_NO_NAME:     return ".modinfo has no name= entry";
	case KG_MODID_E_BAD_FIELD:   return "a .modinfo field is too long or has characters the gate would not accept";
	default:                     return "unknown error";
	}
}

void kg_modid_entry(const struct kg_modid *m, char *buf, size_t len)
{
	if (m->srcversion[0])
		snprintf(buf, len, "%s@%s", m->name, m->srcversion);
	else
		snprintf(buf, len, "%s", m->name);
}

/*----------------------------------------------------------------------------
 * Self-test: synthesised modules, including hostile ones
 *--------------------------------------------------------------------------*/
static int st_fail;
#define ST_CHECK(cond, what) do { if (!(cond)) { st_fail++; fprintf(stderr, "  modid FAIL: %s\n", (what)); } } while (0)

struct st_elf {
	unsigned type;                  /* e_type */
	const char *secname;            /* name of the modinfo section */
	uint64_t claim_size;            /* override sh_size of that section (0 = the real one) */
	unsigned shstrndx_delta;        /* added to e_shstrndx */
};

static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { put16(p, (uint16_t)v); put16(p + 2, (uint16_t)(v >> 16)); }
static void put64(uint8_t *p, uint64_t v) { put32(p, (uint32_t)v); put32(p + 4, (uint32_t)(v >> 32)); }

/* [ehdr][modinfo][shstrtab][3 section headers: null, modinfo, shstrtab] */
static size_t st_build(uint8_t *b, const char *mi, size_t milen, const struct st_elf *o)
{
	char strtab[64];
	size_t stlen, pos, shoff;
	uint32_t nm_modinfo = 1, nm_strtab;
	size_t k;

	memset(b, 0, 512 + milen);
	memcpy(b, "\x7f" "ELF", 4);
	b[4] = 2;
	b[5] = 1;
	b[6] = 1;
	put16(b + 16, (uint16_t)o->type);
	put16(b + 18, 62);
	put32(b + 20, 1);

	pos = 64;
	memcpy(b + pos, mi, milen);
	pos += milen;

	memset(strtab, 0, sizeof(strtab));
	k = 1;
	strcpy(strtab + k, o->secname);
	k += strlen(o->secname) + 1;
	nm_strtab = (uint32_t)k;
	strcpy(strtab + k, ".shstrtab");
	stlen = k + strlen(".shstrtab") + 1;
	memcpy(b + pos, strtab, stlen);

	shoff = pos + stlen;
	put64(b + 0x28, shoff);
	put16(b + 0x34, 64);
	put16(b + 0x3a, SHDR_SIZE);
	put16(b + 0x3c, 3);
	put16(b + 0x3e, (uint16_t)(2 + o->shstrndx_delta));

	put32(b + shoff + 64, nm_modinfo);                       /* section 1: .modinfo */
	put32(b + shoff + 64 + 4, 1);                            /* SHT_PROGBITS */
	put64(b + shoff + 64 + 24, 64);
	put64(b + shoff + 64 + 32, o->claim_size ? o->claim_size : milen);
	put32(b + shoff + 128, nm_strtab);                       /* section 2: .shstrtab */
	put32(b + shoff + 128 + 4, SHT_STRTAB);
	put64(b + shoff + 128 + 24, pos);
	put64(b + shoff + 128 + 32, stlen);
	return shoff + 3 * SHDR_SIZE;
}

int kg_modid_selftest(void)
{
	static const char mi[] = "license=GPL\0name=evil_mod\0srcversion=ABCDEF0123456789ABCDEF0\0"
				 "version=2.1\0name=second\0vermagic=7.0.0 SMP preempt\0";
	static const char mi_nosrc[] = "name=plain-mod\0vermagic=6.8.0 SMP\0";
	static const char mi_noname[] = "license=GPL\0vermagic=6.8.0 SMP\0";
	static const struct st_elf good = { 1, ".modinfo", 0, 0 };
	static uint8_t buf[2048];
	struct kg_modid m;
	char entry[96];
	size_t n;
	int rc;

	st_fail = 0;

	n = st_build(buf, mi, sizeof(mi) - 1, &good);
	rc = kg_modid_parse(buf, n, &m);
	ST_CHECK(rc == KG_MODID_OK, "a well-formed module parses");
	ST_CHECK(!strcmp(m.name, "evil_mod"), "the first name= wins over a later one");
	ST_CHECK(!strcmp(m.srcversion, "ABCDEF0123456789ABCDEF0"), "srcversion is read");
	ST_CHECK(!strcmp(m.version, "2.1"), "version is read");
	ST_CHECK(!strcmp(m.vermagic, "7.0.0 SMP preempt"), "vermagic is read");
	ST_CHECK(!m.sig_marker, "no signature marker on an unsigned file");
	kg_modid_entry(&m, entry, sizeof(entry));
	ST_CHECK(!strcmp(entry, "evil_mod@ABCDEF0123456789ABCDEF0"), "the mod_deny entry is NAME@SRCVERSION");

	{
		uint8_t signd[2048 + 64];
		struct kg_sha256 h;
		uint8_t want[32];

		memcpy(signd, buf, n);
		memcpy(signd + n, "sigbytes", 8);
		memcpy(signd + n + 8, kg_sig_marker, KG_SIG_MARKER_LEN);
		rc = kg_modid_parse(signd, n + 8 + KG_SIG_MARKER_LEN, &m);
		ST_CHECK(rc == KG_MODID_OK && m.sig_marker, "the appended-signature marker is noticed");
		kg_sha256_init(&h);
		kg_sha256_update(&h, signd, n + 8 + KG_SIG_MARKER_LEN);
		kg_sha256_final(&h, want);
		ST_CHECK(!memcmp(want, m.sha256, 32), "the digest covers the whole file, signature included");
	}

	n = st_build(buf, mi_nosrc, sizeof(mi_nosrc) - 1, &good);
	rc = kg_modid_parse(buf, n, &m);
	ST_CHECK(rc == KG_MODID_OK && !m.srcversion[0], "a module without srcversion parses");
	kg_modid_entry(&m, entry, sizeof(entry));
	ST_CHECK(!strcmp(entry, "plain-mod"), "and its entry is just the name");

	n = st_build(buf, mi_noname, sizeof(mi_noname) - 1, &good);
	ST_CHECK(kg_modid_parse(buf, n, &m) == KG_MODID_E_NO_NAME, ".modinfo without name= is refused");

	{
		static const struct st_elf other = { 1, ".comment", 0, 0 };

		n = st_build(buf, mi, sizeof(mi) - 1, &other);
		ST_CHECK(kg_modid_parse(buf, n, &m) == KG_MODID_E_NO_MODINFO, "no .modinfo section: not a module");
	}
	{
		static const struct st_elf exec = { 2, ".modinfo", 0, 0 };

		n = st_build(buf, mi, sizeof(mi) - 1, &exec);
		ST_CHECK(kg_modid_parse(buf, n, &m) == KG_MODID_E_UNSUPPORTED, "an executable is not a module");
	}
	{
		static const struct st_elf huge = { 1, ".modinfo", 0x7fffffffffffffffULL, 0 };

		n = st_build(buf, mi, sizeof(mi) - 1, &huge);
		ST_CHECK(kg_modid_parse(buf, n, &m) == KG_MODID_E_BAD_ELF, "a section larger than the file is refused");
	}
	{
		static const struct st_elf badidx = { 1, ".modinfo", 0, 9 };

		n = st_build(buf, mi, sizeof(mi) - 1, &badidx);
		ST_CHECK(kg_modid_parse(buf, n, &m) == KG_MODID_E_BAD_ELF, "a section-name table index out of range is refused");
	}

	n = st_build(buf, mi, sizeof(mi) - 1, &good);
	ST_CHECK(kg_modid_parse(buf, n - 1, &m) == KG_MODID_E_BAD_ELF, "a file cut inside the section headers is refused");
	ST_CHECK(kg_modid_parse(buf, 63, &m) == KG_MODID_E_NOT_ELF, "a file shorter than an ELF header is refused");
	ST_CHECK(kg_modid_parse(buf, 0, &m) == KG_MODID_E_NOT_ELF, "an empty file is refused");
	{
		uint8_t bad[64];

		memcpy(bad, buf, 64);
		bad[1] = 'X';
		ST_CHECK(kg_modid_parse(bad, 64, &m) == KG_MODID_E_NOT_ELF, "wrong magic is refused");
	}
	{
		static const uint8_t zst[8] = { 0x28, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0 };
		static const uint8_t xz[8] = { 0xfd, '7', 'z', 'X', 'Z', 0, 0, 0 };
		static const uint8_t gz[8] = { 0x1f, 0x8b, 8, 0, 0, 0, 0, 0 };

		ST_CHECK(kg_modid_parse(zst, 8, &m) == KG_MODID_E_COMPRESSED, "zstd is recognised and refused with a hint");
		ST_CHECK(kg_modid_parse(xz, 8, &m) == KG_MODID_E_COMPRESSED, "xz is recognised");
		ST_CHECK(kg_modid_parse(gz, 8, &m) == KG_MODID_E_COMPRESSED, "gzip is recognised");
	}
	{
		/* a name longer than the kernel accepts, and a srcversion that is not hex */
		char longname[160] = "name=";
		static const char mi_nonhex[] = "name=ok\0srcversion=NOT-HEX\0";

		memset(longname + 5, 'a', 70);
		n = st_build(buf, longname, 5 + 70 + 1, &good);
		ST_CHECK(kg_modid_parse(buf, n, &m) == KG_MODID_E_BAD_FIELD, "a name over 55 characters is refused, not truncated");
		n = st_build(buf, mi_nonhex, sizeof(mi_nonhex) - 1, &good);
		ST_CHECK(kg_modid_parse(buf, n, &m) == KG_MODID_E_BAD_FIELD, "a non-hex srcversion is refused");
	}
	{
		/* unterminated final entry and stray NULs must not read past the section */
		static const char mi_open[] = "name=abc\0\0\0srcversion=1234";

		n = st_build(buf, mi_open, sizeof(mi_open) - 1, &good);
		rc = kg_modid_parse(buf, n, &m);
		ST_CHECK(rc == KG_MODID_OK && !strcmp(m.name, "abc") && !strcmp(m.srcversion, "1234"),
			 "an unterminated last entry and padding are handled");
	}

	return st_fail;
}
