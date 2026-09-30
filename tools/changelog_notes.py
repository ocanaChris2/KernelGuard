#!/usr/bin/env python3
"""
changelog_notes.py - print the CHANGELOG.md section for one version (used for release notes).

  tools/changelog_notes.py 1.0.0      print the body of "## [1.0.0]"
  tools/changelog_notes.py --check X  exit 1 if there is no such section (or it is empty)
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def section(version):
    text = (ROOT / 'CHANGELOG.md').read_text(encoding='utf-8')
    m = re.search(rf'^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)', text, re.S | re.M)
    return m.group(1).strip() if m else ''


def main(argv):
    check = argv[:1] == ['--check']
    args = argv[1:] if check else argv
    if len(args) != 1:
        sys.exit(__doc__)
    body = section(args[0])
    if not body:
        print(f'CHANGELOG.md has no (or an empty) section for {args[0]}', file=sys.stderr)
        return 1
    if not check:
        print(body)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
