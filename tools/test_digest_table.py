#!/usr/bin/env python3
"""
test_digest_table.py - check windows/src/digest_table.c, the code that decides whether a driver's digest is on a
deny list, against the real generated table windows/src/vuln_driver_hashes.h.

A bug in "read a digest from hex" or "find it in the table" is a silent miss: the guard would see a vulnerable driver
and say nothing.  The driver cannot run here, but this file has no kernel dependencies: it is built into a shared
library and called through ctypes.  Checked:

  1. the generated table is strictly ascending, has the count the header claims, and every digest in it is read back
     by DtParseHex64 exactly (narrow text, upper case, and 16-bit wide characters as the registry gives them);
  2. every one of the table's digests is found, at its own index, by the binary search and by the fallback scan; a
     digest with one bit flipped is not found; the ends of the table and values below and above it behave;
  3. malformed text is refused and leaves the output alone (63 and 65 characters, a non-hex digit, an embedded NUL,
     a leading space);
  4. a table that is out of order or has a duplicate is noticed by DtIsAscending, and the scan still finds
     everything in it, so a bad table can only be slow, never blind;
  5. thousands of random tables and queries agree with Python's bisect.

  tools/test_digest_table.py               build and run
  tools/test_digest_table.py --sanitize    build with AddressSanitizer and UBSan (needs libasan)

Exit status: 0 all checks passed, 1 a check failed, 2 the environment is not usable.
"""
import argparse
import bisect
import ctypes
import os
import pathlib
import random
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
import import_loldrivers as gen          # noqa: E402  to read the generated header the way the tool wrote it

HEADER = ROOT / 'windows' / 'src' / 'vuln_driver_hashes.h'


class Results:
    def __init__(self):
        self.passed = self.failed = 0

    def check(self, ok, what, detail=''):
        if ok:
            self.passed += 1
            print('  [PASS] %s' % what)
        else:
            self.failed += 1
            print('  [FAIL] %s%s' % (what, ('  -- ' + detail) if detail else ''))
        return ok


class Lib:
    def __init__(self, sanitize):
        self.tmp = tempfile.TemporaryDirectory(prefix='dt.')
        so = pathlib.Path(self.tmp.name) / 'libdt.so'
        cmd = [os.environ.get('CC', 'cc'), '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
               '-I', str(ROOT / 'windows' / 'src'), str(ROOT / 'windows' / 'src' / 'digest_table.c'), '-o', str(so)]
        if sanitize:
            cmd[1:1] = ['-fsanitize=address,undefined', '-fno-sanitize-recover=undefined']
        subprocess.run(cmd, check=True)
        self.lib = ctypes.CDLL(str(so))
        c = self.lib
        c.DtParseHex64.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32, ctypes.c_char_p]
        c.DtParseHex64.restype = ctypes.c_int
        c.DtCompare.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        c.DtCompare.restype = ctypes.c_int
        c.DtIsAscending.argtypes = [ctypes.c_char_p, ctypes.c_uint32]
        c.DtIsAscending.restype = ctypes.c_int
        c.DtFind.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_char_p]
        c.DtFind.restype = ctypes.c_int

    def parse(self, text, wide=False, chars=None, fill=b'\xaa' * 32):
        """(1 or 0, the output buffer after the call)."""
        out = ctypes.create_string_buffer(fill, 32)
        if wide:
            arr = (ctypes.c_uint16 * len(text))(*[ord(ch) for ch in text])
            n = len(text) if chars is None else chars
            rc = self.lib.DtParseHex64(ctypes.cast(arr, ctypes.c_void_p), 1, n, out)
        else:
            raw = ctypes.create_string_buffer(text.encode('latin-1'), len(text))
            n = len(text) if chars is None else chars
            rc = self.lib.DtParseHex64(ctypes.cast(raw, ctypes.c_void_p), 0, n, out)
        return rc, out.raw

    def find(self, table, digest, sorted_):
        return self.lib.DtFind(table, len(table) // 32, 1 if sorted_ else 0, digest)


def flip(digest, bit):
    b = bytearray(digest)
    b[bit // 8] ^= 1 << (bit % 8)
    return bytes(b)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--sanitize', action='store_true')
    ap.add_argument('--seed', type=int, default=20260929)
    a = ap.parse_args()

    if not shutil.which(os.environ.get('CC', 'cc')):
        print('test_digest_table: no C compiler (set CC)', file=sys.stderr)
        return 2
    if a.sanitize and 'KG_DT_ASAN' not in os.environ:
        lib = subprocess.run([os.environ.get('CC', 'cc'), '-print-file-name=libasan.so'],
                             capture_output=True, text=True).stdout.strip()
        if not lib or not os.path.isabs(lib):
            print('test_digest_table: libasan not found; run without --sanitize', file=sys.stderr)
            return 2
        env = dict(os.environ, KG_DT_ASAN='1', LD_PRELOAD=lib, ASAN_OPTIONS='detect_leaks=0')
        return subprocess.call([sys.executable] + sys.argv, env=env)

    text = HEADER.read_text()
    have = gen.parse_existing(text)
    strings = list(have)
    count_line = [ln for ln in text.splitlines() if ln.startswith('#define KG_VULN_HASH_COUNT')]
    declared = int(count_line[0].split()[2])
    table = b''.join(bytes.fromhex(d) for d in strings)

    L = Lib(a.sanitize)
    rng = random.Random(a.seed)
    res = Results()

    print('-- the generated table (%d digests)' % len(strings))
    res.check(declared == len(strings) and len(strings) > 1000, 'the count in the header matches the digests in it (%d)' % declared)
    res.check(strings == sorted(strings) and len(set(strings)) == len(strings), 'the table is sorted and has no duplicates (Python)')
    res.check(L.lib.DtIsAscending(table, len(strings)) == 1, 'DtIsAscending agrees')
    bad = [d for d in strings if L.parse(d)[0] != 1 or L.parse(d)[1] != bytes.fromhex(d)]
    res.check(not bad, 'DtParseHex64 reads every digest back exactly (narrow)', str(bad[:2]))
    bad = [d for d in strings if L.parse(d.upper())[1] != bytes.fromhex(d)]
    res.check(not bad, 'the same in upper case')
    bad = [d for d in strings if L.parse(d, wide=True)[1] != bytes.fromhex(d)]
    res.check(not bad, 'the same with 16-bit wide characters, as the registry lists give them')

    print('-- finding digests')
    wrong = [i for i, d in enumerate(strings) if L.find(table, bytes.fromhex(d), True) != i]
    res.check(not wrong, 'the binary search finds every digest at its own index', str(wrong[:3]))
    wrong = [i for i, d in enumerate(strings) if L.find(table, bytes.fromhex(d), False) != i]
    res.check(not wrong, 'the fallback scan does too', str(wrong[:3]))
    known = set(strings)
    miss = []
    for d in strings:
        f = flip(bytes.fromhex(d), rng.randrange(256))
        if f.hex() not in known and (L.find(table, f, True) != -1 or L.find(table, f, False) != -1):
            miss.append(f.hex())
    res.check(not miss, 'a digest with one bit flipped is not found', str(miss[:2]))
    res.check(L.find(table, b'\x00' * 32, True) == -1 and L.find(table, b'\xff' * 32, True) == -1,
              'values below and above the whole table are not found')
    res.check(L.find(table, bytes.fromhex(strings[0]), True) == 0 and
              L.find(table, bytes.fromhex(strings[-1]), True) == len(strings) - 1, 'the first and the last digest are found')
    res.check(L.lib.DtFind(None, 0, 1, b'\x01' * 32) == -1 and L.lib.DtFind(table, 0, 1, b'\x01' * 32) == -1,
              'an empty or missing table finds nothing')
    one = bytes.fromhex(strings[7])
    res.check(L.find(one, one, True) == 0 and L.find(one, bytes.fromhex(strings[8]), True) == -1,
              'a table of one digest works')

    print('-- malformed text')
    d = strings[0]
    for label, txt, wide in [('63 characters', d[:63], False), ('65 characters', d + '0', False),
                             ('a non-hex digit', 'g' + d[1:], False), ('a leading space', ' ' + d[:63], False),
                             ('63 wide characters', d[:63], True)]:
        rc, out = L.parse(txt, wide=wide)
        res.check(rc == 0 and out == b'\xaa' * 32, '%s: refused, output untouched' % label)
    nul = d[:10] + '\0' + d[11:]
    res.check(L.parse(nul)[0] == 0, 'an embedded NUL is refused')
    res.check(L.parse(d, chars=63)[0] == 0 and L.parse(d, chars=65)[0] == 0,
              'the length is the caller-supplied count, not the text (no read past 64 characters)')

    print('-- a table in the wrong order')
    swapped = bytearray(table)
    swapped[0:32], swapped[32:64] = table[32:64], table[0:32]
    res.check(L.lib.DtIsAscending(bytes(swapped), len(strings)) == 0, 'two digests swapped: not ascending')
    dup = table[:64] + table[32:64] + table[64:]
    res.check(L.lib.DtIsAscending(dup, len(strings) + 1) == 0, 'a duplicate: not ascending')
    res.check(all(L.find(bytes(swapped), bytes.fromhex(d), False) >= 0 for d in strings[:200]),
              'the scan still finds every digest of an unsorted table')

    print('-- random tables against bisect')
    disagreements = []
    for _ in range(4000):
        n = rng.randrange(0, 60)
        items = sorted({rng.randbytes(32) for _ in range(n)})
        blob = b''.join(items)
        for q in [rng.choice(items) if items else rng.randbytes(32), rng.randbytes(32),
                  flip(rng.choice(items), rng.randrange(256)) if items else rng.randbytes(32)]:
            i = bisect.bisect_left(items, q)
            want = i if i < len(items) and items[i] == q else -1
            got_sorted = L.find(blob, q, True) if items else L.lib.DtFind(None, 0, 1, q)
            got_scan = L.find(blob, q, False) if items else -1
            if got_sorted != want or got_scan != want:
                disagreements.append((n, q.hex(), want, got_sorted, got_scan))
    res.check(not disagreements, '12000 random lookups agree with bisect', str(disagreements[:2]))

    print('\n%d passed, %d failed%s' % (res.passed, res.failed, ' (AddressSanitizer + UBSan)' if a.sanitize else ''))
    return 1 if res.failed else 0


if __name__ == '__main__':
    sys.exit(main())
