/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * kg_modid.h - what identifies a kernel module file to the driver-load gate (`kgmon modid`).
 *
 * The gate in the kernel module (kg_modgate.c) matches a module by its name and, optionally, its
 * srcversion.  Both are strings in the module's .modinfo section, inside the signed part of the
 * ELF.  This reads them from a .ko file so an operator can paste the exact mod_deny= entry
 * instead of guessing it, and adds the file's SHA-256 for the audit trail (the kernel cannot
 * match on it: a module's file is not visible to a notifier).
 *
 * The file is untrusted input (a suspected-vulnerable module is exactly what one would feed
 * this), so every offset is checked against the length and nothing is executed or mapped.
 */
#ifndef KG_MODID_H
#define KG_MODID_H

#include <stddef.h>
#include <stdint.h>

#define KG_MODID_NAME_MAX       56      /* the kernel's MODULE_NAME_LEN, including the NUL */
#define KG_MODID_SRCVER_MAX     32      /* srcversion is 23-24 characters; the gate accepts up to 31 */
#define KG_MODID_STR_MAX        128

struct kg_modid {
	char    name[KG_MODID_NAME_MAX];
	char    srcversion[KG_MODID_SRCVER_MAX];        /* empty when the module has none */
	char    version[KG_MODID_STR_MAX];              /* MODULE_VERSION(), empty when none */
	char    vermagic[KG_MODID_STR_MAX];
	int     sig_marker;                             /* the file ends with the appended-signature marker */
	uint8_t sha256[32];                             /* of the whole file, as given */
};

enum {
	KG_MODID_OK             = 0,
	KG_MODID_E_COMPRESSED   = -1,   /* .ko.zst / .xz / .gz: decompress first */
	KG_MODID_E_NOT_ELF      = -2,
	KG_MODID_E_UNSUPPORTED  = -3,   /* not a 64-bit little-endian relocatable object */
	KG_MODID_E_BAD_ELF      = -4,   /* a header or section points outside the file */
	KG_MODID_E_NO_MODINFO   = -5,
	KG_MODID_E_NO_NAME      = -6,   /* .modinfo has no name= entry */
	KG_MODID_E_BAD_FIELD    = -7,   /* a name or srcversion the gate would not accept */
};

/* Parse an in-memory .ko.  Returns KG_MODID_OK or one of the errors above. */
int kg_modid_parse(const uint8_t *img, size_t len, struct kg_modid *out);
const char *kg_modid_strerror(int rc);

/* The mod_deny= form: "NAME@SRCVERSION", or just "NAME" when the module has no srcversion. */
void kg_modid_entry(const struct kg_modid *m, char *buf, size_t len);

/* Returns the number of failed checks (0 = all passed). */
int kg_modid_selftest(void);

#endif
