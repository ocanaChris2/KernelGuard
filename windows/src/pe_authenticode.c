// pe_authenticode.c
// See pe_authenticode.h.  Follows "Windows Authenticode Portable Executable Signature Format":
//
//   1. hash the file from byte 0 up to the CheckSum field
//   2. skip the 4-byte CheckSum, hash up to the Certificate Table entry of the data directory
//   3. skip that 8-byte entry, hash the rest of the headers (up to SizeOfHeaders)
//   4. hash every section's raw data, in ascending PointerToRawData order
//   5. hash whatever follows the last section, minus the certificate blob
//
// Everything is read from the file with explicit little-endian loads (no struct overlay, no alignment
// assumptions) and with 64-bit arithmetic, so a hostile header cannot overflow a bounds check.

#include "pe_authenticode.h"

#define PEA_CHUNK 0x100000u     // hand the hash at most 1 MiB at a time: it is called from a kernel thread

static PEA_U16 Rd16(const PEA_U8 *p)
{
    return (PEA_U16)(p[0] | (p[1] << 8));
}

static PEA_U32 Rd32(const PEA_U8 *p)
{
    return (PEA_U32)p[0] | ((PEA_U32)p[1] << 8) | ((PEA_U32)p[2] << 16) | ((PEA_U32)p[3] << 24);
}

// Hash File[Off, Off+Len) in bounded pieces.  The caller has already checked the range against the file.
static int HashRange(const PEA_U8 *File, PEA_U64 Off, PEA_U64 Len, PEA_UPDATE Update, void *Ctx)
{
    while (Len) {
        PEA_U32 n = Len > PEA_CHUNK ? PEA_CHUNK : (PEA_U32)Len;

        if (Update(Ctx, File + Off, n) != 0)
            return PEA_E_HASH;
        Off += n;
        Len -= n;
    }
    return PEA_OK;
}

typedef struct _PEA_SECTION {
    PEA_U32 Offset;
    PEA_U32 Size;
} PEA_SECTION;

int PeaAuthenticodeHash(const PEA_U8 *File, PEA_U64 Length, PEA_UPDATE Update, void *Ctx)
{
    PEA_SECTION sec[PEA_MAX_SECTIONS];
    PEA_U64 lfanew, opt, optSize, ddOff, secTab, checkOff, certEntry = 0, sizeOfHeaders, sum, extra;
    PEA_U32 nSections, nDirs = 0, certOff = 0, certSize = 0, i, j;
    PEA_U16 magic;
    int rc, haveCertEntry = 0;

    // ---- DOS header, NT headers, optional header -------------------------------------------
    if (Length < 0x40 || File[0] != 'M' || File[1] != 'Z')
        return PEA_E_FORMAT;
    lfanew = Rd32(File + 0x3c);
    if (lfanew < 0x40 || lfanew > Length || Length - lfanew < 24)
        return PEA_E_FORMAT;
    if (File[lfanew] != 'P' || File[lfanew + 1] != 'E' || File[lfanew + 2] != 0 || File[lfanew + 3] != 0)
        return PEA_E_FORMAT;

    nSections = Rd16(File + lfanew + 6);
    optSize   = Rd16(File + lfanew + 20);
    opt       = lfanew + 24;
    if (nSections > PEA_MAX_SECTIONS || opt > Length || optSize > Length - opt || optSize < 96)
        return PEA_E_FORMAT;

    magic = Rd16(File + opt);
    if (magic == 0x10b) {                       // PE32
        ddOff = opt + 96;
        if (optSize >= 96)
            nDirs = Rd32(File + opt + 92);
    } else if (magic == 0x20b) {                // PE32+
        if (optSize < 112)
            return PEA_E_FORMAT;
        ddOff = opt + 112;
        nDirs = Rd32(File + opt + 108);
    } else {
        return PEA_E_FORMAT;
    }

    checkOff      = opt + 64;                   // CheckSum: the same offset in PE32 and PE32+
    sizeOfHeaders = Rd32(File + opt + 60);
    if (checkOff + 4 > opt + optSize || sizeOfHeaders > Length)
        return PEA_E_FORMAT;

    // The Certificate Table is data directory number 4; a file with fewer directories has none.
    if (nDirs > 4 && ddOff + 5 * 8 <= opt + optSize) {
        certEntry = ddOff + 4 * 8;
        certOff   = Rd32(File + certEntry);
        certSize  = Rd32(File + certEntry + 4);
        haveCertEntry = 1;
    }

    // The three skipped pieces must lie inside the headers, in this order.
    if (checkOff + 4 > sizeOfHeaders)
        return PEA_E_FORMAT;
    if (haveCertEntry && (certEntry < checkOff + 4 || certEntry + 8 > sizeOfHeaders))
        return PEA_E_FORMAT;

    // ---- section table --------------------------------------------------------------------
    secTab = opt + optSize;
    if (secTab > Length || (PEA_U64)nSections * 40 > Length - secTab)
        return PEA_E_FORMAT;
    for (i = 0; i < nSections; i++) {
        const PEA_U8 *s = File + secTab + (PEA_U64)i * 40;
        PEA_SECTION cur;

        cur.Size   = Rd32(s + 16);              // SizeOfRawData
        cur.Offset = Rd32(s + 20);              // PointerToRawData
        // Insertion sort by file offset, stable, at most 96 entries: no allocation, no recursion.
        for (j = i; j > 0 && sec[j - 1].Offset > cur.Offset; j--)
            sec[j] = sec[j - 1];
        sec[j] = cur;
    }

    // ---- 1-3: the headers, minus CheckSum and the certificate entry ------------------------
    rc = HashRange(File, 0, checkOff, Update, Ctx);
    if (rc)
        return rc;
    if (haveCertEntry) {
        rc = HashRange(File, checkOff + 4, certEntry - (checkOff + 4), Update, Ctx);
        if (!rc)
            rc = HashRange(File, certEntry + 8, sizeOfHeaders - (certEntry + 8), Update, Ctx);
    } else {
        rc = HashRange(File, checkOff + 4, sizeOfHeaders - (checkOff + 4), Update, Ctx);
    }
    if (rc)
        return rc;
    sum = sizeOfHeaders;

    // ---- 4: sections in file order ---------------------------------------------------------
    // A real image never overlaps its own sections, so the running total never passes the file
    // length; insisting on that also bounds the work a crafted section table can ask for.
    for (i = 0; i < nSections; i++) {
        if (!sec[i].Size)
            continue;
        if ((PEA_U64)sec[i].Offset + sec[i].Size > Length || sum + sec[i].Size > Length)
            return PEA_E_FORMAT;
        rc = HashRange(File, sec[i].Offset, sec[i].Size, Update, Ctx);
        if (rc)
            return rc;
        sum += sec[i].Size;
    }

    // ---- 5: anything after the last section, without the certificate blob -----------------
    if (Length > sum) {
        extra = Length - sum;
        if (certSize) {
            if ((PEA_U64)certOff + certSize > Length || certSize > extra)
                return PEA_E_FORMAT;
            extra -= certSize;
        }
        rc = HashRange(File, sum, extra, Update, Ctx);
        if (rc)
            return rc;
    }
    return PEA_OK;
}
