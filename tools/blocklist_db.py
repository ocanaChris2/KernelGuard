#!/usr/bin/env python3
"""
blocklist_db.py - build and query a SQLite database of known-bad driver signatures for KernelGuard.

Sources, all read-only inputs; the database is rebuilt from scratch each time, so it never drifts:

  loldrivers   the public LOLDrivers dataset (https://www.loldrivers.io, Apache License 2.0): per driver its
               category, CVEs and references; per sample the Authentihash and the file hashes (SHA-256/SHA-1/MD5)
  header       windows/src/vuln_driver_hashes.h, the digest table already built into the Windows guard
               (keeps digests the shipped table has even if LOLDrivers later drops them)
  local        usb/blocklist/sha256.deny and modules.deny, the operator's own lists (Windows/Linux hashes and
               Linux module entries NAME[@SRCVERSION] as printed by `kgmon modid`)

  tools/blocklist_db.py build                  download LOLDrivers, write blocklist/kernelguard-blocklist.db
  tools/blocklist_db.py build --input f.json   use a saved drivers.json; --offline skips LOLDrivers altogether
  tools/blocklist_db.py update                 refresh in place; reports what changed; keeps the old file if the
                                               download fails (what the timer in tools/systemd/ runs)
  tools/blocklist_db.py stats                  counts per source, platform and class
  tools/blocklist_db.py lookup VALUE...        which list(s) name a hash (any algorithm) or a module entry
  tools/blocklist_db.py export sha256          every SHA-256 (file and Authentihash), one per line, for
                                               usb/blocklist/sha256.deny
  tools/blocklist_db.py export modules         Linux module entries, for usb/blocklist/modules.deny
  tools/blocklist_db.py check                  is every digest in the Windows header also in the database?

Tables: sources, drivers (one per LOLDrivers entry), signatures (one per source/kind/algorithm/value).
View `blocklist` folds duplicates: one row per (platform, kind, algo, value) with the worst class seen
('malicious' > 'vulnerable' > 'deny') and how many sources name it.

Nothing here decides what is worth blocking: LOLDrivers also lists drivers legitimate software installs, so a
hit is evidence, not a verdict (see the notes in import_loldrivers.py).

Daily refresh: tools/systemd/install.sh installs a per-user systemd timer that runs `update` (--remove undoes it).
It refreshes only this database, not the Windows header or the USB deny lists.

Exit status: 0 done / found, 1 lookup found nothing or check failed, 2 an input could not be read (update: the
download or parse failed and the old database was kept).
"""
import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import sqlite3
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import import_loldrivers as lol  # noqa: E402  (shares the URL, the header parser and the digest pattern)

DEFAULT_DB = ROOT / 'blocklist' / 'kernelguard-blocklist.db'
HEADER = lol.OUTPUT
LOCAL_DIR = ROOT / 'usb' / 'blocklist'
RANK = {'malicious': 3, 'vulnerable': 2, 'deny': 1}
MODULE = re.compile(r'^[A-Za-z0-9_.\-]+(@[A-Za-z0-9]+)?$')

SCHEMA = """
PRAGMA user_version = 1;
CREATE TABLE sources (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, url TEXT, license TEXT,
    retrieved TEXT NOT NULL, dataset_sha256 TEXT);
CREATE TABLE drivers (
    id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL REFERENCES sources(id),
    ext_id TEXT NOT NULL, name TEXT, category TEXT NOT NULL, cves TEXT, description TEXT, refs TEXT,
    UNIQUE (source_id, ext_id));
CREATE TABLE signatures (
    id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL REFERENCES sources(id),
    driver_id INTEGER REFERENCES drivers(id),
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'linux')),
    kind TEXT NOT NULL CHECK (kind IN ('authentihash', 'file', 'module')),
    algo TEXT NOT NULL CHECK (algo IN ('sha256', 'sha1', 'md5', 'modid')),
    value TEXT NOT NULL,
    class TEXT NOT NULL CHECK (class IN ('malicious', 'vulnerable', 'deny')),
    filename TEXT, company TEXT, product TEXT, version TEXT, loads_despite_hvci TEXT,
    UNIQUE (source_id, kind, algo, value));
CREATE INDEX signatures_value ON signatures(value);
CREATE VIEW blocklist AS
    SELECT platform, kind, algo, value,
           CASE MAX(CASE class WHEN 'malicious' THEN 3 WHEN 'vulnerable' THEN 2 ELSE 1 END)
                WHEN 3 THEN 'malicious' WHEN 2 THEN 'vulnerable' ELSE 'deny' END AS class,
           COUNT(DISTINCT source_id) AS sources
    FROM signatures GROUP BY platform, kind, algo, value;
"""


def clean(v):
    return v.strip().lower() if isinstance(v, str) else ''


def add_source(db, name, url, license_, retrieved, sha=None):
    return db.execute('INSERT INTO sources(name, url, license, retrieved, dataset_sha256) VALUES (?,?,?,?,?)',
                      (name, url, license_, retrieved, sha)).lastrowid


def add_sig(db, sid, did, platform, kind, algo, value, klass, s=None):
    s = s or {}
    db.execute('INSERT OR IGNORE INTO signatures(source_id, driver_id, platform, kind, algo, value, class, filename,'
               ' company, product, version, loads_despite_hvci) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
               (sid, did, platform, kind, algo, value, klass,
                s.get('Filename') or s.get('OriginalFilename') or None, s.get('Company') or None,
                s.get('Product') or None, s.get('FileVersion') or None,
                str(s['LoadsDespiteHVCI']) if s.get('LoadsDespiteHVCI') not in (None, '') else None))


def import_loldrivers(db, path, url, retrieved):
    raw, entries = lol.load_dataset(path, url)
    sid = add_source(db, 'loldrivers', url if not path else lol.URL, 'Apache-2.0', retrieved,
                     hashlib.sha256(raw).hexdigest())
    n = 0
    for e in entries:
        klass = 'malicious' if (e.get('Category') or '').strip().lower() == 'malicious' else 'vulnerable'
        cves = set()
        for field in (e.get('CVE'), e.get('CVEs')):
            cves.update([field] if isinstance(field, str) else field or [])
        cves = sorted(c.strip() for c in cves if c and c.strip())
        cmd = e.get('Commands') or {}
        did = db.execute('INSERT INTO drivers(source_id, ext_id, name, category, cves, description, refs)'
                         ' VALUES (?,?,?,?,?,?,?)',
                         (sid, e['Id'], (e.get('Tags') or [None])[0], klass, ', '.join(cves) or None,
                          cmd.get('Description') or None, '\n'.join(e.get('Resources') or []) or None)).lastrowid
        for s in e.get('KnownVulnerableSamples') or []:
            auth = s.get('Authentihash') or {}
            # a few samples use flat AuthentihashSHA256 / AuthentihashSHA1 / AuthentihashMD5 keys instead
            for algo, size in (('sha256', 64), ('sha1', 40), ('md5', 32)):
                for kind, raw_value in (('authentihash', auth.get(algo.upper())),
                                        ('authentihash', s.get('Authentihash' + algo.upper())),
                                        ('file', s.get(algo.upper()))):
                    d = clean(raw_value)
                    if re.fullmatch(r'[0-9a-f]{%d}' % size, d):
                        add_sig(db, sid, did, 'windows', kind, algo, d, klass, s)
                        n += 1
    return n


def import_header(db, path, retrieved):
    text = path.read_text()
    table = lol.parse_existing(text)
    m = re.search(r'^// Retrieved\s*:\s*(\S+)', text, re.M)
    sid = add_source(db, 'header', str(path.relative_to(ROOT)), 'Apache-2.0', m.group(1) if m else retrieved,
                     hashlib.sha256(text.encode()).hexdigest())
    for d, k in table.items():
        add_sig(db, sid, None, 'windows', 'authentihash', 'sha256', d, 'malicious' if k == '1' else 'vulnerable')
    return len(table)


def import_local(db, directory, retrieved):
    n = 0
    sid = None
    for fname in ('sha256.deny', 'modules.deny'):
        p = directory / fname
        if not p.is_file():
            continue
        if sid is None:
            sid = add_source(db, 'local', str(directory.relative_to(ROOT)), None, retrieved)
        for line in p.read_text().splitlines():
            word = line.split('#', 1)[0].split()
            if not word:
                continue
            v = word[0]
            if fname == 'sha256.deny':
                if re.fullmatch(r'[0-9A-Fa-f]{64}', v):
                    # a bare hash says nothing about platform: the usb scan applies it to modules and .sys alike
                    add_sig(db, sid, None, 'windows', 'file', 'sha256', v.lower(), 'deny')
                    n += 1
            elif MODULE.match(v):
                add_sig(db, sid, None, 'linux', 'module', 'modid', v, 'deny')
                n += 1
    return n


def connect(path):
    if not path.is_file():
        sys.exit('blocklist_db: %s does not exist; run `blocklist_db.py build` first' % path)
    db = sqlite3.connect('file:%s?mode=ro' % path, uri=True)
    db.row_factory = sqlite3.Row
    return db


def build_to(a, target):
    """Build a fresh database at `target` (atomically: a failure leaves no file behind)."""
    tmp = target.with_name(target.name + '.tmp')
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp.unlink(missing_ok=True)
    db = sqlite3.connect(tmp)
    try:
        db.executescript(SCHEMA)
        counts = {}
        if not a.offline:
            counts['loldrivers'] = import_loldrivers(db, a.input, lol.URL, a.retrieved)
        if a.header.is_file():
            counts['header'] = import_header(db, a.header, a.retrieved)
        counts['local'] = import_local(db, LOCAL_DIR, a.retrieved)
        db.commit()
        db.execute('VACUUM')
    except BaseException:
        db.close()
        tmp.unlink(missing_ok=True)
        raise
    db.close()
    os.replace(tmp, target)
    return counts


def cmd_build(a):
    counts = build_to(a, a.db)
    print('wrote %s' % a.db)
    print('signatures read: ' + ', '.join('%s %d' % kv for kv in counts.items()))
    return cmd_stats(a)


def folded(path):
    db = sqlite3.connect('file:%s?mode=ro' % path, uri=True)
    try:
        return {(r[0], r[1], r[2], r[3]): r[4] for r in db.execute('SELECT platform, kind, algo, value, class FROM blocklist')}
    finally:
        db.close()


def cmd_update(a):
    """Rebuild next to the live database, report what changed, and swap it in only if the download worked.
    A network or parse failure leaves the current database in place (exit 2), so a timer can run this blindly."""
    new = a.db.with_name(a.db.name + '.new')
    try:
        build_to(a, new)
    except (OSError, SystemExit, ValueError, sqlite3.Error) as exc:
        new.unlink(missing_ok=True)
        print('blocklist_db: update failed, keeping the current database: %s' % exc, file=sys.stderr)
        return 2
    old = folded(a.db) if a.db.is_file() else {}
    cur = folded(new)
    added = cur.keys() - old.keys()
    removed = old.keys() - cur.keys()
    changed = [k for k in cur.keys() & old.keys() if cur[k] != old[k]]
    if a.db.is_file() and not (added or removed or changed):
        new.unlink()
        print('%s is up to date: %d signatures' % (a.db.name, len(cur)))
        return 0
    os.replace(new, a.db)
    sha = sum(1 for k in added if k[2] == 'sha256')
    print('%s updated: %d added (%d SHA-256), %d removed, %d reclassified; %d signatures now'
          % (a.db.name, len(added), sha, len(removed), len(changed), len(cur)))
    return 0


def cmd_stats(a):
    db = connect(a.db)
    print('sources:')
    for r in db.execute('SELECT s.name, s.retrieved, s.license, COUNT(g.id) n FROM sources s'
                        ' LEFT JOIN signatures g ON g.source_id = s.id GROUP BY s.id'):
        print('  %-11s retrieved %s  license %-10s %6d signatures' % (r['name'], r['retrieved'], r['license'] or '-', r['n']))
    print('distinct entries (after folding duplicates):')
    for r in db.execute('SELECT platform, kind, algo, class, COUNT(*) n FROM blocklist GROUP BY 1,2,3,4 ORDER BY 1,2,3,4'):
        print('  %-8s %-12s %-7s %-10s %6d' % (r['platform'], r['kind'], r['algo'], r['class'], r['n']))
    r = db.execute('SELECT COUNT(*) n, (SELECT COUNT(*) FROM drivers WHERE cves IS NOT NULL) c FROM drivers').fetchone()
    print('drivers: %d (%d with CVEs)' % (r['n'], r['c']))
    return 0


def cmd_lookup(a):
    db = connect(a.db)
    found = 0
    for v in a.values:
        v = v.strip()
        q = v.lower() if re.fullmatch(r'[0-9A-Fa-f]{32,64}', v) else v
        rows = db.execute('SELECT g.kind, g.algo, g.class, s.name source, d.name driver, d.cves, g.filename, g.company'
                          ' FROM signatures g JOIN sources s ON s.id = g.source_id'
                          ' LEFT JOIN drivers d ON d.id = g.driver_id WHERE g.value = ? ORDER BY g.class', (q,)).fetchall()
        if not rows:
            print('%s: not listed' % v)
            continue
        found += 1
        for r in rows:
            extra = '  '.join(x for x in (r['driver'] and 'driver=' + r['driver'], r['cves'] and 'cve=' + r['cves'],
                                          r['filename'] and 'file=' + r['filename'], r['company']) if x)
            print('%s: %s %s %s [%s]  %s' % (v, r['class'].upper(), r['kind'], r['algo'], r['source'], extra))
    return 0 if found == len(a.values) else 1


def cmd_export(a):
    db = connect(a.db)
    if a.what == 'sha256':
        rows = db.execute("SELECT value FROM blocklist WHERE algo = 'sha256' AND (? = 'all' OR class = ?)"
                          ' ORDER BY value', (a.min_class, a.min_class)).fetchall()
    else:
        rows = db.execute("SELECT value FROM blocklist WHERE kind = 'module' ORDER BY value").fetchall()
    sys.stdout.write(''.join(r['value'] + '\n' for r in rows))
    return 0


def cmd_check(a):
    want = set(lol.parse_existing(a.header.read_text()))
    db = connect(a.db)
    have = {r[0] for r in db.execute("SELECT value FROM blocklist WHERE kind = 'authentihash' AND algo = 'sha256'")}
    missing = sorted(want - have)
    print('%d header digests, %d in the database (%d Authentihash SHA-256 in all); %d missing'
          % (len(want), len(want & have), len(have), len(missing)))
    for d in missing[:10]:
        print('  missing ' + d)
    return 1 if missing else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    ap.add_argument('--db', type=pathlib.Path, default=DEFAULT_DB)
    ap.add_argument('--header', type=pathlib.Path, default=HEADER)
    sub = ap.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build')
    b.add_argument('--input', help='a saved drivers.json instead of downloading')
    b.add_argument('--offline', action='store_true', help='skip LOLDrivers: header and local lists only')
    b.add_argument('--retrieved', default=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d'))
    u = sub.add_parser('update', help='rebuild, report the differences, keep the old database if the download fails')
    u.add_argument('--input', help=argparse.SUPPRESS)
    u.add_argument('--offline', action='store_true', help=argparse.SUPPRESS)
    u.add_argument('--retrieved', default=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d'),
                   help=argparse.SUPPRESS)
    sub.add_parser('stats')
    lk = sub.add_parser('lookup')
    lk.add_argument('values', nargs='+')
    ex = sub.add_parser('export')
    ex.add_argument('what', choices=('sha256', 'modules'))
    ex.add_argument('--min-class', choices=('all', 'malicious'), default='all',
                    help='sha256 only: "malicious" leaves out the merely vulnerable drivers')
    sub.add_parser('check')
    a = ap.parse_args()
    return {'build': cmd_build, 'update': cmd_update, 'stats': cmd_stats, 'lookup': cmd_lookup, 'export': cmd_export, 'check': cmd_check}[a.cmd](a)


if __name__ == '__main__':
    sys.exit(main())
