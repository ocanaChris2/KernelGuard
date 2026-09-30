#!/usr/bin/env python3
"""
test_pe_authenticode.py - check windows/src/pe_authenticode.c, the Authenticode digest the Windows driver-load
guard identifies drivers by, on this machine.

The driver cannot run here, but this file has no kernel dependencies: it is built into a shared library and
called through ctypes, with hashlib standing in for the driver's BCrypt.  What it is checked against:

  1. the digest recorded inside real Microsoft signatures (PE32, PE32+ and ARM64 files taken from the Windows
     SDK/WDK NuGet packages): the signer's own answer, not ours;
  2. tools/pe_authentihash.py, an independent Python implementation of the same specification;
  3. properties the digest must have: the same with the signature stripped, unchanged by the CheckSum field or
     by anything inside the certificate blob, changed by a byte of code or of the headers;
  4. hostile input: every truncation of a real header, thousands of random header mutations (the C code and
     the Python one must agree on "rejected" versus "accepted, with this digest"), overlapping sections that
     would make the hash do the work twice, more sections than the loader allows;
  5. plumbing: a failing hash aborts the walk with its own error, and a multi-megabyte section is fed to the
     hash in pieces of at most 1 MiB.

  tools/test_pe_authenticode.py                 fetch the samples once (about 100 KB) into .wdk-cache/, then test
  tools/test_pe_authenticode.py --sanitize      build the C code with AddressSanitizer and UBSan (needs libasan)
  tools/test_pe_authenticode.py --samples DIR   use the PE files in DIR instead of downloading
  tools/test_pe_authenticode.py --fuzz N        random mutations per sample (default 3000)

Needs: a C compiler, and for the download the Python package remotezip; the signature check also needs
asn1crypto.  Exit status: 0 all checks passed, 1 a check failed, 2 the environment is not usable.
"""
import argparse
import ctypes
import hashlib
import os
import pathlib
import random
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
import pe_authentihash as ref            # noqa: E402  the independent implementation
import wdk_syntax_check as wdk           # noqa: E402  only for the package URLs

SAMPLES = [
    ('PE32 x86 (signed)',       wdk.SDK_URL, f'c/Redist/{wdk.KIT}/ucrt/DLLs/x86/api-ms-win-core-fibers-l1-1-1.dll'),
    ('PE32+ x64 (signed)',      wdk.WDK_URL, f'c/bin/{wdk.KIT}/x64/api-ms-win-core-sysinfo-l1-2-0.dll'),
    ('PE32+ ARM64 (signed)',    wdk.WDK_URL, f'c/bin/{wdk.KIT}/ARM64/api-ms-win-core-file-l1-2-0.dll'),
    ('PE32+ x64 (not signed)',  wdk.WDK_URL, f'c/tools//{wdk.KIT}/x64/looksgood.exe'),
]

PEA_OK, PEA_E_FORMAT, PEA_E_HASH = 0, 1, 2
UPDATE = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte), ctypes.c_uint32)


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


class CImpl:
    """windows/src/pe_authenticode.c behind ctypes."""

    def __init__(self, sanitize):
        self.tmp = tempfile.TemporaryDirectory(prefix='pea.')
        lib = pathlib.Path(self.tmp.name) / 'libpea.so'
        cmd = [os.environ.get('CC', 'cc'), '-O2', '-g', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
               '-I', str(ROOT / 'windows' / 'src'), str(ROOT / 'windows' / 'src' / 'pe_authenticode.c'),
               '-o', str(lib)]
        if sanitize:
            cmd[1:1] = ['-fsanitize=address,undefined', '-fno-sanitize-recover=undefined']
        subprocess.run(cmd, check=True)
        self.lib = ctypes.CDLL(str(lib))
        self.lib.PeaAuthenticodeHash.restype = ctypes.c_int
        self.lib.PeaAuthenticodeHash.argtypes = [ctypes.c_void_p, ctypes.c_uint64, UPDATE, ctypes.c_void_p]

    def run(self, data, algorithm='sha256', fail_at=None):
        """(return code, hex digest or None, list of chunk sizes handed to the hash)."""
        h = hashlib.new(algorithm)
        chunks = []

        def cb(_ctx, ptr, n):
            if fail_at is not None and len(chunks) + 1 == fail_at:
                chunks.append(n)
                return 1
            chunks.append(n)
            h.update(ctypes.string_at(ptr, n))
            return 0

        callback = UPDATE(cb)
        # A block of exactly len(data) bytes, so a read past the end is visible to AddressSanitizer.
        buf = (ctypes.c_ubyte * max(len(data), 1)).from_buffer_copy(data or b'\0')
        rc = self.lib.PeaAuthenticodeHash(buf, len(data), callback, None)
        return rc, (h.hexdigest() if rc == PEA_OK else None), chunks


def ref_digest(data, algorithm='sha256'):
    """The Python reference's answer: a hex digest, or None where it rejects the file."""
    try:
        return ref.authenticode_digest(bytes(data), algorithm).hex()
    except (ref.PEFormatError, struct.error, IndexError):
        return None


def put32(data, off, value):
    struct.pack_into('<I', data, off, value & 0xffffffff)


# ---------------------------------------------------------------------------------------------------
# A minimal, well-formed PE image
# ---------------------------------------------------------------------------------------------------
def make_pe(sections, cert=b'', pe32plus=True, checksum=0, tail=b''):
    opt_size = 240 if pe32plus else 224
    lfanew = 0x80
    headers_end = lfanew + 24 + opt_size + len(sections) * 40
    size_of_headers = (headers_end + 0x1ff) & ~0x1ff
    hdr = bytearray(size_of_headers)
    hdr[0:2] = b'MZ'
    put32(hdr, 0x3c, lfanew)
    hdr[lfanew:lfanew + 4] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', hdr, lfanew + 4, 0x8664 if pe32plus else 0x14c, len(sections),
                     0x5f5e1000, 0, 0, opt_size, 0x22)
    opt = lfanew + 24
    struct.pack_into('<H', hdr, opt, 0x20b if pe32plus else 0x10b)
    put32(hdr, opt + 60, size_of_headers)
    put32(hdr, opt + 64, checksum)
    put32(hdr, opt + (108 if pe32plus else 92), 16)
    dd = opt + (112 if pe32plus else 96)

    body = bytearray()
    raw_ptr = size_of_headers
    for i, payload in enumerate(sections):
        padded = payload + b'\0' * (-len(payload) % 0x200)
        base = opt + opt_size + i * 40
        hdr[base:base + 8] = ('.s%d' % i).encode().ljust(8, b'\0')
        struct.pack_into('<II', hdr, base + 8, len(payload), 0x1000 * (i + 1))
        struct.pack_into('<II', hdr, base + 16, len(padded), raw_ptr)
        raw_ptr += len(padded)
        body += padded

    out = bytearray(hdr) + body + tail
    if cert:
        pad = cert + b'\0' * (-len(cert) % 8)
        blob = struct.pack('<IHH', len(pad) + 8, 0x200, 2) + pad
        struct.pack_into('<II', out, dd + 4 * 8, len(out), len(blob))
        out += blob
    return bytes(out), {'dd': dd, 'checksum': opt + 64, 'opt': opt, 'sectab': opt + opt_size,
                        'lfanew': lfanew, 'headers': size_of_headers}


# ---------------------------------------------------------------------------------------------------
def fetch_samples(cache):
    """{label: bytes} for the samples; downloads what is not cached."""
    out = {}
    folder = cache / 'pe-samples'
    folder.mkdir(parents=True, exist_ok=True)
    for label, url, member in SAMPLES:
        path = folder / pathlib.PurePosixPath(member).name
        if not path.exists():
            try:
                from remotezip import RemoteZip
            except ImportError:
                sys.exit('test_pe_authenticode: remotezip is missing (pip install remotezip), '
                         'or point --samples at a directory of PE files')
            print('fetching %s ...' % path.name, flush=True)
            with RemoteZip(url) as z:
                path.write_bytes(z.read(member))
        out[label] = path.read_bytes()
    return out


def load_dir(directory):
    out = {}
    for p in sorted(directory.iterdir()):
        if p.is_file():
            out['%s' % p.name] = p.read_bytes()
    return out


def signed_facts(data):
    """(layout, embedded (algorithm, digest) or None) for a sample, without judging the C code."""
    lay = ref.parse_layout(data)
    try:
        emb = ref.embedded_digest(data)
    except ImportError:
        emb = 'no-asn1crypto'
    return lay, emb


def test_sample(res, c, label, data, fuzz_n, rng):
    print('-- %s (%d bytes)' % (label, len(data)))
    lay, emb = signed_facts(data)
    rc, dig, _ = c.run(data)
    res.check(rc == PEA_OK, 'accepted as a well-formed image')
    res.check(dig == ref_digest(data), 'C digest equals the independent Python implementation')

    if emb == 'no-asn1crypto':
        print('  [SKIP] embedded-signature comparison needs asn1crypto (pip install asn1crypto)')
    elif emb is None:
        res.check(lay['cert_size'] == 0, 'the file carries no signature (nothing to compare with)')
    else:
        algo, recorded = emb
        rc2, dig2, _ = c.run(data, algo)
        res.check(rc2 == PEA_OK and dig2 == recorded.hex(),
                  'C %s digest equals the digest recorded inside the signature' % algo,
                  'C %s / signature %s' % (dig2, recorded.hex()))

        # Signing and un-signing must not change the digest: strip the blob and the directory entry.
        if lay['cert_off'] + lay['cert_size'] == len(data):
            bare = bytearray(data[:lay['cert_off']])
            put32(bare, lay['cert_entry'], 0)
            put32(bare, lay['cert_entry'] + 4, 0)
            res.check(c.run(bytes(bare), algo)[1] == recorded.hex(),
                      'the digest of the stripped, unsigned file is the same')
        # Anything inside the certificate blob is outside the digest.
        noisy = bytearray(data)
        noisy[lay['cert_off'] + lay['cert_size'] - 1] ^= 0xff
        noisy[lay['cert_off'] + 12] ^= 0x55
        res.check(c.run(bytes(noisy), algo)[1] == recorded.hex(), 'a changed byte inside the certificate blob does not matter')

    # The CheckSum field is outside the digest.
    tweaked = bytearray(data)
    put32(tweaked, lay['checksum'], 0xdeadbeef)
    res.check(c.run(bytes(tweaked))[1] == dig, 'the CheckSum field does not matter')

    # A byte of a section, and a byte of the headers outside the skipped fields, do.
    secs = [(struct.unpack_from('<I', data, lay['sectab'] + i * 40 + 20)[0],
             struct.unpack_from('<I', data, lay['sectab'] + i * 40 + 16)[0]) for i in range(lay['nsec'])]
    ptr, size = next(s for s in secs if s[1])
    flipped = bytearray(data)
    flipped[ptr + size // 2] ^= 1
    fd = c.run(bytes(flipped))[1]
    res.check(fd is not None and fd != dig and fd == ref_digest(flipped), 'one flipped bit of section data changes the digest')
    stamp = bytearray(data)
    stamp[struct.unpack_from('<I', data, 0x3c)[0] + 8] ^= 1
    sd = c.run(bytes(stamp))[1]
    res.check(sd is not None and sd != dig and sd == ref_digest(stamp), 'the file-header TimeDateStamp is covered')

    # Differential runs: the two implementations must give the same verdict, and the same digest.
    span = min(len(data), 0x400)
    bad = []
    for n in list(range(0, span)) + [rng.randrange(span, len(data) + 1) for _ in range(100)]:
        got, want = c.run(data[:n])[1], ref_digest(data[:n])
        if got != want:
            bad.append(('truncated to %d' % n, got, want))
    res.check(not bad, 'every truncation of the headers is judged the same by both implementations (no crash)',
              str(bad[:3]))
    bad = []
    for _ in range(fuzz_n):
        m = bytearray(data)
        muts = []
        for _ in range(rng.randint(1, 3)):
            pos, val = rng.randrange(span), rng.randrange(256)
            m[pos] = val
            muts.append((hex(pos), hex(val)))
        got, want = c.run(bytes(m))[1], ref_digest(m)
        if got != want:
            bad.append((muts, got, want))
            if len(bad) >= 3:
                break
    res.check(not bad, '%d random header mutations are judged the same by both implementations (no crash)' % fuzz_n,
              str(bad[:3]))


def test_synthetic(res, c, rng):
    print('-- synthetic images')
    cases = [
        ('PE32+, 3 sections',                    dict(sections=[b'A' * 700, b'B' * 1500, b'C' * 30])),
        ('PE32, 2 sections',                     dict(sections=[b'x' * 4000, b'y' * 10], pe32plus=False)),
        ('PE32+ with a certificate blob',        dict(sections=[b'code' * 300], cert=b'\x30\x82' + b'S' * 500)),
        ('PE32 with a certificate and a tail',   dict(sections=[b'q' * 900], cert=b'sig' * 40, pe32plus=False)),
        ('PE32+ with data after the last section', dict(sections=[b'p' * 512], tail=b'overlay-data' * 20)),
        ('no sections at all',                   dict(sections=[])),
        ('96 sections (the loader limit)',       dict(sections=[bytes([i]) * (50 + i) for i in range(96)])),
    ]
    for label, kw in cases:
        img, _ = make_pe(**kw)
        rc, dig, _ = c.run(img)
        res.check(rc == PEA_OK and dig == ref_digest(img), '%s: accepted, and both implementations agree' % label)

    img, _ = make_pe([b'z' * 100] * 97)
    res.check(c.run(img)[0] == PEA_E_FORMAT and ref_digest(img) is None, '97 sections are refused by both')

    # A section table that lists sections out of file order: the data is still hashed in file order.  (The
    # table itself is part of the headers, so this is not the digest of the unswapped image; what it must
    # equal is the headers minus the two skipped fields, then the raw data exactly as it lies in the file.)
    img, info = make_pe([b'first' * 200, b'second' * 200])
    swapped = bytearray(img)
    a, b = info['sectab'], info['sectab'] + 40
    swapped[a:a + 40], swapped[b:b + 40] = img[b:b + 40], img[a:a + 40]
    lay = ref.parse_layout(bytes(swapped))
    by_hand = hashlib.sha256(bytes(swapped[:lay['checksum']]) +
                             bytes(swapped[lay['checksum'] + 4:lay['cert_entry']]) +
                             bytes(swapped[lay['cert_entry'] + 8:])).hexdigest()
    res.check(c.run(bytes(swapped))[1] == by_hand == ref_digest(swapped),
              'sections listed out of file order are hashed in file order (checked against a hand-built digest)')

    # Two sections over the same bytes would make the hash walk them twice: a real image never does this.
    img, info = make_pe([b'k' * 4096, b'\0' * 16])
    dup = bytearray(img)
    ptr0 = struct.unpack_from('<I', dup, info['sectab'] + 20)[0]
    size0 = struct.unpack_from('<I', dup, info['sectab'] + 16)[0]
    struct.pack_into('<II', dup, info['sectab'] + 40 + 16, size0, ptr0)      # section 2 = section 1's bytes
    res.check(c.run(bytes(dup))[0] == PEA_E_FORMAT and ref_digest(dup) is None,
              'overlapping sections are refused, so the work is bounded by the file size')

    # A failing hash aborts the walk with its own code.
    img, _ = make_pe([b'm' * 5000, b'n' * 5000])
    rc, dig, chunks = c.run(img, fail_at=2)
    res.check(rc == PEA_E_HASH and dig is None and len(chunks) == 2, 'a hash that fails stops the walk with PEA_E_HASH')

    # Big sections are handed to the hash in pieces of at most 1 MiB.
    img, _ = make_pe([bytes(rng.getrandbits(8) for _ in range(4096)) * 768])       # 3 MiB
    rc, dig, chunks = c.run(img)
    res.check(rc == PEA_OK and dig == ref_digest(img) and max(chunks) <= 1 << 20 and len(chunks) >= 3,
              'a 3 MiB section is fed in pieces of at most 1 MiB (%d pieces, largest %d)' % (len(chunks), max(chunks)))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--cache', type=pathlib.Path, default=ROOT / '.wdk-cache')
    ap.add_argument('--samples', type=pathlib.Path)
    ap.add_argument('--fuzz', type=int, default=3000)
    ap.add_argument('--seed', type=int, default=20260929)
    ap.add_argument('--sanitize', action='store_true')
    a = ap.parse_args()

    if not shutil.which(os.environ.get('CC', 'cc')):
        print('test_pe_authenticode: no C compiler (set CC)', file=sys.stderr)
        return 2
    if a.sanitize and 'KG_PEA_ASAN' not in os.environ:
        lib = subprocess.run([os.environ.get('CC', 'cc'), '-print-file-name=libasan.so'],
                             capture_output=True, text=True).stdout.strip()
        if not lib or not os.path.isabs(lib):
            print('test_pe_authenticode: libasan not found; run without --sanitize', file=sys.stderr)
            return 2
        env = dict(os.environ, KG_PEA_ASAN='1', LD_PRELOAD=lib, ASAN_OPTIONS='detect_leaks=0')
        return subprocess.call([sys.executable] + sys.argv, env=env)

    samples = load_dir(a.samples) if a.samples else fetch_samples(a.cache)
    if not samples:
        print('test_pe_authenticode: no sample PE files', file=sys.stderr)
        return 2

    c = CImpl(a.sanitize)
    rng = random.Random(a.seed)
    res = Results()
    for label, data in samples.items():
        test_sample(res, c, label, data, a.fuzz, rng)
    test_synthetic(res, c, rng)
    print('\n%d passed, %d failed%s' % (res.passed, res.failed, ' (AddressSanitizer + UBSan)' if a.sanitize else ''))
    return 1 if res.failed else 0


if __name__ == '__main__':
    sys.exit(main())
