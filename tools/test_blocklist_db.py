#!/usr/bin/env python3
"""
test_blocklist_db.py - build the blocklist database from a small synthetic dataset and check what comes out:
class folding, flat/nested Authentihash keys, string/list CVE fields, lookup, export, and that a failed build
leaves the previous database untouched.  No network.  Exit status: 0 passed, 1 a check failed.
"""
import contextlib
import io
import json
import pathlib
import sys
import tempfile
import types

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import blocklist_db as b  # noqa: E402

H = lambda c, n=64: c * n  # noqa: E731
DATA = [
    {'Id': 'a', 'Tags': ['bad.sys'], 'Category': 'malicious', 'CVE': 'CVE-1', 'Commands': {}, 'Resources': ['u'],
     'KnownVulnerableSamples': [{'SHA256': H('1'), 'MD5': H('2', 32), 'Authentihash': {'SHA256': H('3')}}]},
    {'Id': 'b', 'Tags': ['weak.sys'], 'Category': 'vulnerable driver', 'CVEs': ['CVE-2', 'CVE-3'],
     'KnownVulnerableSamples': [{'SHA256': H('4'), 'AuthentihashSHA256': H('5'), 'Authentihash': {'SHA256': H('3')}},
                                {'SHA256': 'nothex'}, {}]},
]
failed = 0


def check(name, ok):
    global failed
    print(('ok   ' if ok else 'FAIL ') + name)
    failed += not ok


def run(fn, *args):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = fn(types.SimpleNamespace(**args[0]))
    return rc, out.getvalue()


with tempfile.TemporaryDirectory() as d:
    d = pathlib.Path(d)
    (d / 'drivers.json').write_text(json.dumps(DATA))
    db = d / 'x.db'
    ns = dict(db=db, input=str(d / 'drivers.json'), offline=False, retrieved='2026-01-01', header=d / 'none.h')
    rc, _ = run(b.cmd_build, ns)
    check('build succeeds', rc == 0 and db.is_file())
    c = b.connect(db)
    q = lambda sql: c.execute(sql).fetchall()  # noqa: E731
    check('digest in both categories folds to malicious',
          q("SELECT class, sources FROM blocklist WHERE value='%s' AND kind='authentihash'" % H('3'))[0][:] == ('malicious', 1))
    check('flat AuthentihashSHA256 key is read', len(q("SELECT 1 FROM blocklist WHERE value='%s'" % H('5'))) == 1)
    check('malformed hashes are skipped', not q("SELECT 1 FROM signatures WHERE value='nothex'"))
    check('string and list CVE fields', [r[0] for r in q('SELECT cves FROM drivers ORDER BY ext_id')] == ['CVE-1', 'CVE-2, CVE-3'])
    rc, out = run(b.cmd_lookup, dict(db=db, values=[H('4').upper(), H('9')]))
    check('lookup is case-insensitive and exits 1 on a miss', rc == 1 and 'VULNERABLE' in out and 'not listed' in out)
    rc, out = run(b.cmd_export, dict(db=db, what='sha256', min_class='malicious'))
    check('export --min-class malicious', out.split() == sorted([H('1'), H('3')]))
    c.close()
    before = db.read_bytes()
    ns['input'] = str(d / 'missing.json')
    try:
        run(b.cmd_build, ns)
    except BaseException:
        pass
    check('failed build leaves the old database intact', db.read_bytes() == before and not (d / 'x.db.tmp').exists())
sys.exit(1 if failed else 0)
