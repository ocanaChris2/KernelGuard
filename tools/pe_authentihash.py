#!/usr/bin/env python3
"""
pe_authentihash.py - print the Authenticode digest of a driver (or any PE file).

The Windows driver-load guard (windows/src/driver_load_guard.c) recognises a vulnerable driver by this digest,
not by its file name or an ordinary file hash: the name is not signed, and the file hash changes when a
signature is re-encoded, but the Authenticode digest is what Code Integrity itself verifies (the LOLDrivers
project publishes it as "Authentihash").  Use this tool to get the value to put in
Parameters\\DriverDenyHashes / DriverAllowHashes (Deploy-KernelGuard.ps1 -DenyDriverHash / -AllowDriverHash).

  tools/pe_authentihash.py FILE...                 sha256sum-style lines: DIGEST  FILE
  tools/pe_authentihash.py --sha1 FILE...          the SHA-1 digest instead (older LOLDrivers entries)
  tools/pe_authentihash.py --embedded FILE...      also the digest the signer recorded in the file, and
                                                   whether it matches (needs the asn1crypto package)

What the digest covers ("Windows Authenticode Portable Executable Signature Format"): the file with the
CheckSum field, the Certificate Table entry of the data directory, and the certificate blob left out, taking
the headers, then each section's raw data in ascending file-offset order, then whatever follows.  Re-signing a
file, or appending to its certificate, does not change it.

This is an independent implementation of the same algorithm as windows/src/pe_authenticode.c, on purpose:
tools/test_pe_authenticode.py compares the two, and both with the digests inside real signatures.

Exit status: 0 all files hashed (and, with --embedded, every signed file matched), 1 a file was not a PE image
or did not match, 2 usage or environment error.
"""
import argparse
import hashlib
import struct
import sys


class PEFormatError(ValueError):
    """The file is not a well-formed PE image, or one that could not have been signed."""


MAX_SECTIONS = 96       # the loader's limit, and the C implementation's


def _u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def _u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def parse_layout(data):
    """Where the pieces the digest skips or walks are.  Returns a dict of offsets and sizes."""
    n = len(data)
    if n < 0x40 or data[:2] != b'MZ':
        raise PEFormatError('not a PE file (no MZ header)')
    lfanew = _u32(data, 0x3c)
    if lfanew < 0x40 or lfanew + 24 > n or data[lfanew:lfanew + 4] != b'PE\0\0':
        raise PEFormatError('bad PE signature')

    nsec = _u16(data, lfanew + 6)
    opt_size = _u16(data, lfanew + 20)
    opt = lfanew + 24
    if nsec > MAX_SECTIONS or opt + opt_size > n or opt_size < 96:
        raise PEFormatError('bad file header')

    magic = _u16(data, opt)
    if magic == 0x10b:
        dd, ndirs_off = opt + 96, opt + 92
    elif magic == 0x20b:
        if opt_size < 112:
            raise PEFormatError('optional header too small for PE32+')
        dd, ndirs_off = opt + 112, opt + 108
    else:
        raise PEFormatError('unknown optional header magic 0x%x' % magic)

    ndirs = _u32(data, ndirs_off)
    lay = {
        'checksum': opt + 64,
        'headers': _u32(data, opt + 60),
        'nsec': nsec,
        'sectab': opt + opt_size,
        'cert_entry': None,
        'cert_off': 0,
        'cert_size': 0,
    }
    if ndirs > 4 and dd + 5 * 8 <= opt + opt_size:
        lay['cert_entry'] = dd + 4 * 8
        lay['cert_off'] = _u32(data, dd + 4 * 8)
        lay['cert_size'] = _u32(data, dd + 4 * 8 + 4)

    if lay['headers'] > n or lay['checksum'] + 4 > lay['headers']:
        raise PEFormatError('SizeOfHeaders is inconsistent')
    ce = lay['cert_entry']
    if ce is not None and (ce < lay['checksum'] + 4 or ce + 8 > lay['headers']):
        raise PEFormatError('certificate entry outside the headers')
    if lay['sectab'] + nsec * 40 > n:
        raise PEFormatError('section table runs past the end of the file')
    return lay


def authenticode_pieces(data):
    """The byte ranges of `data` the digest covers, in order, as (start, end) pairs."""
    lay = parse_layout(data)
    n = len(data)
    pieces = []

    # Headers, minus the CheckSum field and the certificate-table entry.
    skips = [(lay['checksum'], lay['checksum'] + 4)]
    if lay['cert_entry'] is not None:
        skips.append((lay['cert_entry'], lay['cert_entry'] + 8))
    pos = 0
    for a, b in skips:
        pieces.append((pos, a))
        pos = b
    pieces.append((pos, lay['headers']))
    hashed = lay['headers']

    # Sections, ordered by where their raw data sits in the file.
    secs = []
    for i in range(lay['nsec']):
        base = lay['sectab'] + i * 40
        size, ptr = _u32(data, base + 16), _u32(data, base + 20)
        if size:
            secs.append((ptr, size))
    for ptr, size in sorted(secs, key=lambda s: s[0]):
        if ptr + size > n or hashed + size > n:
            raise PEFormatError('a section runs past the end of the file (or overlaps another)')
        pieces.append((ptr, ptr + size))
        hashed += size

    # Whatever is left after the sections, minus the certificate blob.
    if n > hashed:
        extra = n - hashed
        if lay['cert_size']:
            if lay['cert_off'] + lay['cert_size'] > n or lay['cert_size'] > extra:
                raise PEFormatError('certificate blob does not fit')
            extra -= lay['cert_size']
        pieces.append((hashed, hashed + extra))
    return [(a, b) for a, b in pieces if b > a]


def authenticode_digest(data, algorithm='sha256'):
    h = hashlib.new(algorithm)
    for a, b in authenticode_pieces(data):
        h.update(data[a:b])
    return h.digest()


def _der_children(contents):
    """The DER elements (header included) that make up the contents of a SEQUENCE."""
    from asn1crypto import parser

    out, pos = [], 0
    while pos < len(contents):
        _cls, _form, _tag, header, body, trailer = parser.parse(contents[pos:])
        end = pos + len(header) + len(body) + len(trailer)
        out.append(contents[pos:end])
        pos = end
    return out


def embedded_digest(data):
    """(algorithm name, digest) recorded in the file's Authenticode signature, or None when unsigned.

    The signature is a PKCS#7 SignedData whose content is an SpcIndirectDataContent, a SEQUENCE of the
    data being signed and a DigestInfo; the digest is in that second element.  Needs asn1crypto.
    """
    from asn1crypto import algos, cms, core

    lay = parse_layout(data)
    if not lay['cert_size']:
        return None
    blob = data[lay['cert_off']:lay['cert_off'] + lay['cert_size']]
    length, _revision, _type = struct.unpack_from('<IHH', blob, 0)       # WIN_CERTIFICATE header
    signed = cms.ContentInfo.load(blob[8:length])['content']
    # Authenticode's content is not wrapped in the OCTET STRING RFC 5652 asks for, so asn1crypto hands back
    # the contents of the SEQUENCE; be ready for a version that hands back the SEQUENCE whole.
    parts = _der_children(signed['encap_content_info']['content'].contents)
    if len(parts) == 1:
        parts = _der_children(core.Sequence.load(parts[0]).contents)
    if len(parts) < 2:
        raise ValueError('SpcIndirectDataContent has no digest')
    info = algos.DigestInfo.load(parts[1])
    return info['digest_algorithm']['algorithm'].native, info['digest'].native


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('files', nargs='+', metavar='FILE')
    ap.add_argument('--sha1', action='store_true', help='print the SHA-1 digest instead of SHA-256')
    ap.add_argument('--embedded', action='store_true',
                    help='also print the digest recorded in the signature and whether it matches')
    args = ap.parse_args(argv)
    algorithm = 'sha1' if args.sha1 else 'sha256'

    status = 0
    for path in args.files:
        try:
            with open(path, 'rb') as fh:
                data = fh.read()
            digest = authenticode_digest(data, algorithm).hex()
        except OSError as exc:
            print('%s: %s' % (path, exc.strerror or exc), file=sys.stderr)
            status = 1
            continue
        except PEFormatError as exc:
            print('%s: %s' % (path, exc), file=sys.stderr)
            status = 1
            continue
        print('%s  %s' % (digest, path))
        if args.embedded:
            try:
                emb = embedded_digest(data)
            except ImportError:
                print('  --embedded needs the asn1crypto package (pip install asn1crypto)', file=sys.stderr)
                return 2
            except Exception as exc:                                       # a damaged signature is a result
                print('  signature unreadable: %s' % exc)
                status = 1
                continue
            if emb is None:
                print('  not signed')
            else:
                name, value = emb
                mine = authenticode_digest(data, name).hex() if name in hashlib.algorithms_available else None
                verdict = 'matches' if mine == value.hex() else 'DOES NOT MATCH (%s)' % mine
                print('  signature records %s %s: %s' % (name, value.hex(), verdict))
                if mine != value.hex():
                    status = 1
    return status


if __name__ == '__main__':
    sys.exit(main())
