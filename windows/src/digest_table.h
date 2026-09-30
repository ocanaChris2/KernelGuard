// digest_table.h
// The parts of the driver-load guard that do not need the kernel: reading a SHA-256 digest from hexadecimal
// text and finding a digest in a table.  They are what decides whether a driver's digest is on a deny list, so
// a bug here is a silent miss; that is why they live in a file of their own, with fixed-width types only, and
// are also built on Linux and tested against the real generated table (tools/test_digest_table.py).

#pragma once

typedef unsigned char  DT_U8;
typedef unsigned short DT_U16;      // a Windows WCHAR
typedef unsigned int   DT_U32;

typedef struct _DT_DIGEST {
    DT_U8 B[32];
} DT_DIGEST;

// Exactly 64 hexadecimal digits, either case, into 32 bytes.  Text is DT_U16 characters when Wide is nonzero and
// bytes otherwise.  Returns 1, or 0 when the text is not exactly 64 hexadecimal digits.
int DtParseHex64(const void *Text, int Wide, DT_U32 Chars, DT_U8 Out[32]);

// Bytewise, unsigned: negative, zero or positive like memcmp.
int DtCompare(const DT_U8 A[32], const DT_U8 B[32]);

// 1 when the table is strictly ascending (sorted, no duplicates), else 0.  A table of fewer than two is ascending.
int DtIsAscending(const DT_DIGEST *Table, DT_U32 Count);

// Index of Digest in Table, or -1.  A binary search when Sorted is nonzero (the caller has checked with
// DtIsAscending), a scan otherwise, so a table in the wrong order can only be slow, never blind.
int DtFind(const DT_DIGEST *Table, DT_U32 Count, int Sorted, const DT_U8 Digest[32]);
