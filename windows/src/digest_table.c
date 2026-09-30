// digest_table.c
// See digest_table.h.

#include "digest_table.h"

static int HexVal(DT_U32 c)
{
    if (c >= '0' && c <= '9') return (int)(c - '0');
    if (c >= 'a' && c <= 'f') return (int)(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return (int)(c - 'A' + 10);
    return -1;
}

int DtParseHex64(const void *Text, int Wide, DT_U32 Chars, DT_U8 Out[32])
{
    DT_U32 i;
    DT_U8  tmp[32];

    if (Chars != 64)
        return 0;
    for (i = 0; i < 32; i++) {
        DT_U32 c0 = Wide ? ((const DT_U16 *)Text)[2 * i]     : ((const DT_U8 *)Text)[2 * i];
        DT_U32 c1 = Wide ? ((const DT_U16 *)Text)[2 * i + 1] : ((const DT_U8 *)Text)[2 * i + 1];
        int    h  = HexVal(c0);
        int    l  = HexVal(c1);

        if (h < 0 || l < 0)
            return 0;
        tmp[i] = (DT_U8)((h << 4) | l);
    }
    for (i = 0; i < 32; i++)            // Out is written only for a well-formed digest
        Out[i] = tmp[i];
    return 1;
}

int DtCompare(const DT_U8 A[32], const DT_U8 B[32])
{
    DT_U32 i;

    for (i = 0; i < 32; i++)
        if (A[i] != B[i])
            return A[i] < B[i] ? -1 : 1;
    return 0;
}

int DtIsAscending(const DT_DIGEST *Table, DT_U32 Count)
{
    DT_U32 i;

    for (i = 1; i < Count; i++)
        if (DtCompare(Table[i - 1].B, Table[i].B) >= 0)
            return 0;
    return 1;
}

int DtFind(const DT_DIGEST *Table, DT_U32 Count, int Sorted, const DT_U8 Digest[32])
{
    DT_U32 i;

    if (!Table || !Count)
        return -1;
    if (Sorted) {
        DT_U32 lo = 0, hi = Count;      // the candidates are [lo, hi)

        while (lo < hi) {
            DT_U32 mid = lo + (hi - lo) / 2;
            int    c   = DtCompare(Table[mid].B, Digest);

            if (c == 0)
                return (int)mid;
            if (c < 0)
                lo = mid + 1;
            else
                hi = mid;
        }
        return -1;
    }
    for (i = 0; i < Count; i++)
        if (!DtCompare(Table[i].B, Digest))
            return (int)i;
    return -1;
}
