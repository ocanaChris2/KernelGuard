// pe_authenticode.h
// The Authenticode message digest of a PE image: what a signing tool signs and what Code Integrity
// re-computes.  It is the file with three things left out, so signing (or re-signing) does not change it:
// the CheckSum field, the Certificate Table entry of the data directory, and the certificate blob itself.
// Two files with the same digest are the same program for every purpose the loader cares about, whatever
// their names and whatever has been appended to the certificate; that is why a driver deny list can match
// on it and not on a file name or an ordinary file hash.
//
// This file and pe_authenticode.c use no kernel or Windows types, only the fixed-width ones below, so the
// very same code is compiled into the driver and, on a developer machine, into a test that checks it against
// real signed binaries (tools/test_pe_authenticode.py).  The caller supplies the hash: the driver passes
// BCrypt SHA-256, the test passes hashlib.
//
// The input is untrusted (it is the file of a driver somebody just loaded), so every offset and size read
// from it is checked against the length before it is used, and the work is bounded by the file length.

#pragma once

typedef unsigned char       PEA_U8;
typedef unsigned short      PEA_U16;
typedef unsigned int        PEA_U32;      // 32 bits on every platform, unlike ULONG/unsigned long
typedef unsigned long long  PEA_U64;

// Feeds Length bytes at Data to the hash.  Returns 0 on success, anything else aborts the walk.
typedef int (*PEA_UPDATE)(void *Context, const PEA_U8 *Data, PEA_U32 Length);

#define PEA_OK         0
#define PEA_E_FORMAT   1   // not a well-formed PE image (or one that could not have been signed)
#define PEA_E_HASH     2   // the caller's Update routine failed

// Walks the byte ranges of File[0..Length) that the digest covers, in order, through Update.  The caller
// creates the hash before the call and finishes it afterwards.
int PeaAuthenticodeHash(const PEA_U8 *File, PEA_U64 Length, PEA_UPDATE Update, void *Context);

// The Authenticode digest is only defined for images the loader would accept; this is the cap on the
// number of sections it does (PE_MAX_SECTIONS in the loader).
#define PEA_MAX_SECTIONS 96
