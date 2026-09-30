#!/usr/bin/env python3
"""
version.py - keep the single VERSION file and the places that embed it in step.

  tools/version.py            check that every embedded version matches VERSION (exit 1 if not)
  tools/version.py --set X.Y.Z   write X.Y.Z to VERSION and to every place below

Embedded in:
  linux/module/kg.h            #define KG_VERSION     "X.Y.Z-linux"
  linux/monitor/kgmon.c        #define KGMON_VERSION  "X.Y.Z-linux"
  windows/KernelGuard.inf      DriverVer = MM/DD/YYYY,X.Y.Z.0     (date refreshed by --set)
"""
import argparse
import datetime
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SEMVER = re.compile(r'\d+\.\d+\.\d+')

# (file, regex with one group around the version, replacement template using {v})
TARGETS = [
    ('linux/module/kg.h',
     re.compile(r'(#define\s+KG_VERSION\s+")(\d+\.\d+\.\d+)(-linux")'), r'\g<1>{v}\g<3>'),
    ('linux/monitor/kgmon.c',
     re.compile(r'(#define\s+KGMON_VERSION\s+")(\d+\.\d+\.\d+)(-linux")'), r'\g<1>{v}\g<3>'),
    ('windows/KernelGuard.inf',
     re.compile(r'(DriverVer\s*=\s*\d\d/\d\d/\d{4},)(\d+\.\d+\.\d+)(\.0)'), r'\g<1>{v}\g<3>'),
]


def read_version():
    v = (ROOT / 'VERSION').read_text().strip()
    if not SEMVER.fullmatch(v):
        sys.exit(f'VERSION: "{v}" is not MAJOR.MINOR.PATCH')
    return v


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--set', metavar='X.Y.Z', help='set a new version everywhere')
    args = ap.parse_args()

    if args.set:
        if not SEMVER.fullmatch(args.set):
            sys.exit(f'--set: "{args.set}" is not MAJOR.MINOR.PATCH')
        (ROOT / 'VERSION').write_text(args.set + '\n')

    want = read_version()
    bad = 0
    for rel, rx, repl in TARGETS:
        path = ROOT / rel
        raw = path.read_bytes()
        bom = raw.startswith(b'\xef\xbb\xbf')
        text = raw.decode('utf-8-sig')
        m = rx.search(text)
        if not m:
            print(f'FAIL  {rel}: version pattern not found')
            bad += 1
            continue
        if args.set:
            text = rx.sub(repl.format(v=want), text, count=1)
            if rel.endswith('.inf'):
                today = datetime.date.today().strftime('%m/%d/%Y')
                text = re.sub(r'(DriverVer\s*=\s*)\d\d/\d\d/\d{4}', r'\g<1>' + today, text, count=1)
            path.write_bytes((b'\xef\xbb\xbf' if bom else b'') + text.encode('utf-8'))
            print(f'set   {rel}: {want}')
        elif m.group(2) != want:
            print(f'FAIL  {rel}: {m.group(2)} != VERSION {want}')
            bad += 1
        else:
            print(f'ok    {rel}: {want}')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
