# Copyright (C) 2026 Chris Gough
# SPDX-License-Identifier: GPL-3.0-or-later
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""Saved-byte archive integrity. No Org interpretation, Git, or editor access.

One writer. Each outermost archives/ has a ledger of additive, hash-chained
events in archive-integrity/ledger/ beside it, and checkpoints of ledger heads
in archive-integrity/checkpoints/; a legacy ledger inside the archive, in
archives/.archive-integrity/, is still read. Nested historical archives,
ledgers included, are ordinary preserved bytes, so a retired scope's archive
moves unchanged into its parent's.

check and verify-existing read either ledger schema. preview, apply, seal and
write-new write schema 1 events, which a ledger converted to schema 2 refuses;
seal a converted archive with poslib.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import uuid

import cid

INTEGRITY = 'archive-integrity'  # beside an archive: ledger/ and checkpoints/
META = '.archive-integrity'  # legacy: the ledger inside an archive
ANCHORS = '.archive-integrity-anchors'  # legacy: checkpoints beside a root
DECLARATION = b'#+COLLECTION: t'


class Refused(ValueError):
    """A refusal of a kind poslib's doc/formats.org names."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe(relative):
    p = PurePosixPath(relative)
    if (not relative or p.is_absolute() or str(p) != relative
            or any(x in ('', '.', '..') for x in relative.split('/')) or '\\' in relative):
        raise Refused('entry', f'Unsafe relative path: {relative}')
    return relative


def checked(path):
    """Reject link traversal, including symlinked ancestors; normalise macOS /tmp."""
    path = Path(os.path.abspath(path))
    # The OS supplies /tmp and /var aliases on macOS. Resolve the caller's root
    # before descending; all descendants are checked independently below.
    for part in [path, *path.parents]:
        if part.is_symlink() and str(part) not in ('/tmp', '/var'):
            raise Refused('link', f'Symlink: {part}')
    return path


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Refused('link', f'Expected a regular file with one link: {path}')
    return info


def record(path):
    before = regular(path)
    data = path.read_bytes()
    after = regular(path)
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise Refused('changed', f'File changed while reading: {path}')
    return dict(sha256=sha(data), size=len(data), mode=stat.S_IMODE(after.st_mode) & ~0o222)


def roots(root):
    """Discover outermost archive trees; ignore disposable/hidden active trees."""
    root = checked(root).resolve()
    if not root.is_dir():
        raise Refused('root', 'Root must be an existing directory')
    if root.name == 'archives':
        return [root]
    found = []
    for here, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not d.startswith(('.', '_')))
        for name in list(dirs):
            p = Path(here) / name
            if p.is_symlink():
                raise Refused('link', f'Symlink in discovery: {p}')
            if name == 'archives':
                found.append(p)
                dirs.remove(name)
    return sorted(found)


def inventory(archive):
    result = {}
    for here, dirs, files in os.walk(archive, followlinks=False):
        if Path(here) == archive:
            dirs[:] = [d for d in dirs if d != META]
        for name in dirs:
            if (Path(here) / name).is_symlink():
                raise Refused('link', f'Symlink in archive: {Path(here) / name}')
        for name in files:
            path = Path(here) / name
            if Path(here) == archive and name == META:
                raise Refused('ledger', 'Integrity metadata must be a directory')
            result[path.relative_to(archive).as_posix()] = record(path)
    return dict(sorted(result.items()))


def canonical_uuid(value):
    try:
        return isinstance(value, str) and str(uuid.UUID(value)) == value
    except ValueError:
        return False


def ledger_folder(archive):
    """The archive's ledger folder: beside it, else the legacy one inside."""
    beside, inside = archive.parent / INTEGRITY / 'ledger', archive / META
    present = [f for f in (beside, inside) if f.exists() or f.is_symlink()]
    if len(present) > 1:
        raise Refused('ledger', f'Two ledgers for one archive: {archive}')
    return present[0] if present else inside


def is_cid(value):
    return isinstance(value, str) and re.fullmatch('b[a-z2-7]+', value) is not None


def valid_entry(entry, schema):
    fields = {'sha256', 'size', 'mode', 'cid'} if schema == 2 else {'sha256', 'size', 'mode'}
    return (isinstance(entry, dict) and set(entry) == fields
            and (schema != 2 or is_cid(entry['cid']))
            and isinstance(entry['sha256'], str) and re.fullmatch('[0-9a-f]{64}', entry['sha256']) is not None
            and isinstance(entry['size'], int) and entry['size'] >= 0
            and isinstance(entry['mode'], int) and not entry['mode'] & 0o222)


def convert_entries(entries, event, path):
    """entries after the conversion event in path; refused unless it removes,
    renames or converts every legacy entry, each from its fingerprint, and adds
    only new paths."""
    def bad():
        raise Refused('entry', f'Invalid conversion: {path}')

    def is_safe(name):
        try:
            safe(name)
            return True
        except Refused:
            return False
    legacy = {p: e for p, e in entries.items() if 'cid' not in e}
    remove, rename, convert, add = event['remove'], event['rename'], event['convert'], event['add']
    if not (isinstance(remove, list) and isinstance(rename, dict) and isinstance(convert, dict)
            and isinstance(add, dict)):
        bad()
    if not all(p in legacy for p in remove):
        bad()
    if not all(p in legacy and p not in remove and isinstance(n, str) and is_safe(n)
               for p, n in rename.items()):
        bad()
    kept = {p: e for p, e in entries.items() if p not in remove}
    moved = {rename.get(p, p): e for p, e in kept.items()}
    if len(moved) != len(kept):
        bad()
    for new_path, old in moved.items():
        if 'cid' not in old:
            new = convert.get(new_path)
            if not (isinstance(new, dict) and new.get('from') == old['sha256']
                    and valid_entry({k: v for k, v in new.items() if k != 'from'}, 2)):
                bad()
    if not all(p in moved and 'cid' not in moved[p] for p in convert):
        bad()
    result = {p: ({k: v for k, v in convert[p].items() if k != 'from'} if p in convert else e)
              for p, e in moved.items()}
    for name, entry in add.items():
        if not (is_safe(name) and name not in result and valid_entry(entry, 2)):
            bad()
        result[name] = entry
    return result


def history(archive):
    """entries, head, events, files, recorded root, collections, items."""
    folder = ledger_folder(archive)
    if not folder.exists() and not folder.is_symlink():
        return {}, None, 0, [], None, [], []
    if folder.is_symlink() or not folder.is_dir():
        raise Refused('ledger', f'Invalid ledger: {folder}')
    entries, previous, files, ledger_id = {}, None, [], None
    schema, root, collections, items, converted = None, None, set(), [], False
    for number, path in enumerate(sorted(folder.iterdir()), 1):
        regular(path)
        data = path.read_bytes()
        match = re.fullmatch(r'(\d{8})-([0-9a-f]{64})\.json', path.name)
        if not match or int(match[1]) != number or sha(data) != match[2]:
            raise Refused('sequence', f'Ledger sequence/hash failure: {path}')
        event = json.loads(data)
        keys = set(event) if isinstance(event, dict) else set()
        conversion = (event.get('schema') == 2 and event.get('kind') == 'conversion'
                      and keys == {'schema', 'kind', 'previous', 'ledger_id', 'remove', 'rename',
                                   'convert', 'add', 'collections', 'root'}
                      and not converted and any('cid' not in e for e in entries.values()))
        if not ((event.get('schema') == 1 and schema != 2
                 and keys in ({'schema', 'previous', 'add'}, {'schema', 'previous', 'add', 'ledger_id'}))
                or (event.get('schema') == 2
                    and keys == {'schema', 'previous', 'add', 'ledger_id', 'root', 'collections', 'item'})
                or conversion) \
                or event['previous'] != previous:
            raise Refused('chain', f'Ledger chain failure: {path}')
        schema = event['schema']
        root = event.get('root')
        if schema == 2 and not conversion:
            listed, item = event['collections'], event['item']

            def within(p):
                return p == item or p.startswith(item + '/')
            if (not is_cid(root) or not isinstance(listed, list) or not isinstance(item, str)
                    or not all(isinstance(c, str) for c in listed)
                    or listed != sorted(set(listed))
                    or not isinstance(event['add'], dict)
                    or not all(within(c) for c in listed) or not all(within(n) for n in event['add'])):
                raise Refused('entry', f'Invalid root, item or collections: {path}')
            for name in [item, *listed]:
                try:
                    safe(name)
                except Refused:
                    raise Refused('entry', f'Invalid root, item or collections: {path}')
            collections.update(listed)
            items.append(item)
        # The first deployed hook wrote a v1 prefix before ledger UUIDs existed.
        # Preserve those events; the next event binds an identity additively.
        event_id = event.get('ledger_id')
        if event_id is not None:
            if not canonical_uuid(event_id) or (ledger_id is not None and event_id != ledger_id):
                raise Refused('identity', 'Ledger identity changed')
            ledger_id = event_id
        elif ledger_id is not None:
            raise Refused('identity', 'Ledger identity removed')
        if conversion:
            entries = convert_entries(entries, event, path)
            converted = True
            listed = event['collections']
            if (not is_cid(root) or not isinstance(listed, list)
                    or not all(isinstance(c, str) for c in listed) or listed != sorted(set(listed))):
                raise Refused('entry', f'Invalid root or collections: {path}')
            for name in listed:
                try:
                    safe(name)
                except Refused:
                    raise Refused('entry', f'Invalid root or collections: {path}')
            collections.update(listed)
            previous = sha(data)
            files.append(path)
            continue
        if not isinstance(event['add'], dict):
            raise Refused('entry', 'Invalid ledger additions')
        for name, entry in event['add'].items():
            safe(name)
            if name.split('/')[0] == META or name in entries:
                raise Refused('entry', 'Ledger cannot replace an earlier entry or index itself')
            fields = {'sha256', 'size', 'mode', 'cid'} if schema == 2 else {'sha256', 'size', 'mode'}
            if (not isinstance(entry, dict) or set(entry) != fields
                    or (schema == 2 and not is_cid(entry['cid']))
                    or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])
                    or not isinstance(entry['size'], int) or entry['size'] < 0
                    or not isinstance(entry['mode'], int) or entry['mode'] & 0o222):
                raise Refused('entry', 'Invalid ledger entry')
            entries[name] = entry
        previous = sha(data)
        files.append(path)
    if not files:
        raise Refused('empty', f'Empty ledger needs investigation: {folder}')
    return entries, previous, len(files), files, root, sorted(collections), sorted(items)


def differences(known, actual):
    return dict(missing=sorted(set(known) - set(actual)),
                changed=sorted(k for k in known.keys() & actual.keys() if known[k] != actual[k]),
                new=sorted(set(actual) - set(known)))


def anchor_base(root):
    root = checked(root).resolve()
    return root.parent if root.name == 'archives' else root


def anchor_home(root):
    """Where new checkpoints for root go: beside it, else the legacy folder."""
    base = anchor_base(root)
    return base / INTEGRITY / 'checkpoints' if (base / INTEGRITY).is_dir() else base / ANCHORS


def anchor_homes(root):
    base = anchor_base(root)
    return {base / ANCHORS, base / INTEGRITY / 'checkpoints'}


def checkpoint_files(root, archives):
    folders = set(anchor_homes(root)).union(*(anchor_homes(a) for a in archives))
    files = []
    for folder in sorted(folders):
        if not folder.exists() and not folder.is_symlink():
            continue
        if folder.is_symlink() or not folder.is_dir():
            raise Refused('checkpoint', 'Invalid checkpoint directory')
        files.extend(sorted(folder.iterdir()))
    return files


def check_anchors(root, archives):
    required = set()
    for path in checkpoint_files(root, archives):
        regular(path)
        data = path.read_bytes()
        if path.name != sha(data) + '.json':
            raise Refused('checkpoint', f'Checkpoint hash failure: {path}')
        value = json.loads(data)
        if (set(value) != {'schema', 'heads', 'coverage'} or value['schema'] != 1
                or value['coverage'] not in ('archive', 'tree')
                or not isinstance(value['heads'], list)
                or any(not isinstance(h, str) or not re.fullmatch('[0-9a-f]{64}', h) for h in value['heads'])):
            raise Refused('checkpoint', 'Invalid checkpoint')
        if Path(root).name != 'archives' or value['coverage'] == 'archive':
            required.update(value['heads'])
    present = set()
    for archive in archives:
        # Its own ledger, and the unchanged ledgers carried inside retired projects.
        folder = ledger_folder(archive)
        own = list(folder.glob('*.json')) if folder.is_dir() else []
        for path in own + list(archive.rglob('*.json')):
            if path in own or path.parent.name == META or (
                    path.parent.name == 'ledger' and path.parent.parent.name == INTEGRITY):
                regular(path)
                present.add(sha(path.read_bytes()))
    if required - present:
        raise Refused('anchor', 'Missing anchored ledger (archive removed or history truncated): ' +
                         ', '.join(sorted(required - present)))


def checkpoint_heads(root):
    """Retain observed ledger heads outside archives to detect a vanished tree."""
    archives = roots(root)
    check_anchors(root, archives)
    heads = sorted({history(a)[1] for a in archives if history(a)[1]})
    if heads:
        data = encoded(dict(schema=1, heads=heads,
                            coverage='archive' if Path(root).name == 'archives' else 'tree'))
        path = anchor_home(root) / (sha(data) + '.json')
        if not path.exists():
            new_file(path, data)
        elif path.read_bytes() != data:
            raise ValueError('Checkpoint conflict')


def report(root):
    reports = []
    archives = roots(root)
    check_anchors(root, archives)
    writable_checkpoints = [str(p) for p in checkpoint_files(root, archives) if regular(p).st_mode & 0o222]
    for archive in archives:
        known, head, count, metadata, recorded, collections, _ = history(archive)
        actual = inventory(archive)
        try:
            cids = cid.cid_tree(archive)
        except cid.ShardingUnsupported:
            cids = None
        compared = {n: dict(e, cid=cids.get(n)) if cids is not None and 'cid' in known.get(n, {}) else e
                    for n, e in actual.items()}
        diff = differences(known, compared)
        writable = [os.path.relpath(p, archive) for p in [*(archive / n for n in actual), *metadata]
                    if regular(p).st_mode & 0o222]
        hidden = [n for n in actual if any(part.startswith('.') for part in n.split('/'))
                  and not any(part in (META, ANCHORS) for part in n.split('/'))]
        undeclared = [c for c in collections if not declared(archive / c)]
        reports.append(dict(archive=str(archive), head=head, events=count, files=len(actual),
                            writable=sorted(writable), checkpoint_writable=writable_checkpoints if not reports else [],
                            root=cids['.'] if cids is not None else None, recorded_root=recorded,
                            hidden=sorted(hidden), undeclared=undeclared, **diff))
    return reports


def findings(report):
    """Whether an archive's report has any finding."""
    return bool(not report['head'] or report['changed'] or report['missing'] or report['new']
                or report['writable'] or report['checkpoint_writable'] or report['hidden']
                or report['undeclared']
                or (report['recorded_root'] is not None and report['recorded_root'] != report['root']))


def capsule(directory):
    """Whether directory holds a capsule's manifest: schema_version 1, entries, entrypoint."""
    manifest = directory / 'manifest.json'
    try:
        value = json.loads(manifest.read_bytes()) if manifest.is_file() else None
    except ValueError:
        return False
    return (isinstance(value, dict) and value.get('schema_version') == 1
            and 'entries' in value and 'entrypoint' in value)


def declared(directory):
    """Whether directory declares itself a collection: its README.org has the
    declaration line, or it is a capsule."""
    readme = directory / 'README.org'
    return (readme.is_file() and DECLARATION in readme.read_bytes().split(b'\n')) or capsule(directory)


def preview(root, target=None):
    root = checked(root).resolve()
    check_anchors(root, roots(root))
    plan = dict(schema=1, root=str(root), archives=[])
    for archive in roots(root):
        known, head, count, metadata = history(archive)[:4]
        prior_id = json.loads(metadata[-1].read_bytes()).get('ledger_id') if metadata else None
        ledger_id = prior_id or str(uuid.uuid4())
        actual = inventory(archive)
        diff = differences(known, actual)
        if diff['missing'] or diff['changed']:
            raise ValueError(f'Existing evidence differs in {archive}: {diff}')
        selected = {n: actual[n] for n in diff['new']
                    if target is None or (archive / n) == target or target in (archive / n).parents}
        # Empty archives also acquire a baseline, so missing metadata is observable.
        if selected or head is None or prior_id is None:
            plan['archives'].append(dict(path=str(archive.relative_to(root)) if archive != root else '.',
                                         previous=head, number=count + 1, add=selected, ledger_id=ledger_id,
                                         inventory_sha256=sha(encoded(actual))))
    return plan


def new_file(path, data, mode=0o444):
    """Publish bytes without replacing an existing name, then remove write bits."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='_integrity-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode & ~0o222)
        os.link(temp, path)  # exclusive publication, including a concurrent name
    finally:
        os.unlink(temp)


def apply_plan(plan, expected, checkpoint=lambda phase: None):
    if sha(encoded(plan)) != expected or plan.get('schema') != 1:
        raise ValueError('Reviewed plan hash/schema mismatch')
    root = checked(plan['root']).resolve()
    check_anchors(root, roots(root))
    prepared = []
    seen = set()
    for item in plan['archives']:
        relative = item['path']
        archive = root if relative == '.' else root / safe(relative)
        # Check every descendant before os.walk can follow an ancestor link.
        for p in [archive, *archive.parents]:
            if p == root.parent:
                break
            if p.is_symlink():
                raise ValueError(f'Symlink in planned archive: {p}')
        if archive.name != 'archives' or not archive.is_dir() or archive in seen:
            raise ValueError('Invalid or repeated archive boundary')
        seen.add(archive)
        known, head, count, metadata = history(archive)[:4]
        actual = inventory(archive)
        diff = differences(known, actual)
        if sha(encoded(actual)) != item['inventory_sha256']:
            raise ValueError(f'Archive inventory changed since review: {archive}')
        if diff['missing'] or diff['changed']:
            raise ValueError(f'Existing evidence differs: {archive}: {diff}')
        event = dict(schema=1, previous=item['previous'], add=item['add'], ledger_id=item['ledger_id'])
        if str(uuid.UUID(item['ledger_id'])) != item['ledger_id']:
            raise ValueError('Invalid ledger identity')
        prior_id = json.loads(metadata[-1].read_bytes()).get('ledger_id') if metadata else None
        if prior_id is not None and prior_id != item['ledger_id']:
            raise ValueError('Ledger identity changed since review')
        data = encoded(event)
        event_hash = sha(data)
        filename = f"{item['number']:08}-{event_hash}.json"
        done = head == event_hash and count == item['number']
        if not done and (head != item['previous'] or count + 1 != item['number']):
            raise ValueError('Ledger changed since review')
        for name, entry in item['add'].items():
            safe(name)
            if name.split('/')[0] == META or actual.get(name) != entry or (not done and name in known):
                raise ValueError(f'Planned bytes/mode changed: {archive / name}')
        prepared.append((archive, item, data, filename, done))
    checkpoint('validated')
    for archive, item, data, filename, done in prepared:
        if not done:
            new_file(ledger_folder(archive) / filename, data)
        checkpoint('after-ledger')
        # Only protect the records selected by this operation and ledger files.
        for name in item['add']:
            path = archive / name
            if record(path) != item['add'][name]:
                raise ValueError(f'File changed during enrolment: {path}')
            path.chmod(stat.S_IMODE(regular(path).st_mode) & ~0o222)
        for path in ledger_folder(archive).iterdir():
            path.chmod(stat.S_IMODE(regular(path).st_mode) & ~0o222)
        checkpoint('after-protection')
    checkpoint_heads(root)
    return {'plan_sha256': expected, 'archives': len(prepared),
            'enrolled': sum(len(item['add']) for _, item, _, _, _ in prepared)}


def verify_existing(root):
    """Check all enrolled evidence; unknown files remain explicitly unregistered."""
    checks = report(root)
    if any(r['changed'] or r['missing'] for r in checks):
        raise ValueError('Existing archive evidence changed or is missing')
    return checks


def repair(root):
    """Protect only verified enrolled files; never enrol or accept changed bytes."""
    checks = report(root)
    if any(r['changed'] or r['missing'] for r in checks):
        raise ValueError('Integrity discrepancy: permission repair refused; retain evidence')
    count = 0
    for item in checks:
        archive = Path(item['archive'])
        known, _, _, metadata = history(archive)[:4]
        for path in [*(archive / name for name in known), *metadata]:
            mode = stat.S_IMODE(regular(path).st_mode)
            if mode & 0o222:
                path.chmod(mode & ~0o222)
                count += 1
    for path in checkpoint_files(root, roots(root)):
        mode = stat.S_IMODE(regular(path).st_mode)
        if mode & 0o222:
            path.chmod(mode & ~0o222)
            count += 1
    return dict(repaired=count, unregistered=sum(len(r['new']) for r in checks))


def archive_for(path):
    path = checked(path)
    for parent in reversed([path, *path.parents]):
        if parent.is_symlink():
            # Permit system aliases above the garden, never descendant links.
            if str(parent) not in ('/tmp', '/var'):
                raise ValueError(f'Symlink in archive path: {parent}')
        if parent.name == 'archives':
            return parent.resolve()
    return None


def seal_archive(path):
    """Writer hook: enrol only this published output, then protect its bytes.

A standalone capsule outside archives uses its existing manifest for integrity;
only permissions are changed there. Call with the final published path.
"""
    path = checked(path)
    archive = archive_for(path)
    if path.is_dir():
        verify_existing(path)
    if archive:
        # Validate all path components, even those beneath the archive boundary.
        current = path
        while current.resolve() != archive and current != current.parent:
            if current.is_symlink():
                raise ValueError(f'Symlink in publication: {current}')
            current = current.parent
        plan = preview(archive, path.resolve())
        apply_plan(plan, sha(encoded(plan)))
        # A retry after permission drift must also protect existing selected files.
        known = history(archive)[0]
        for name in known:
            file = archive / name
            if file == path.resolve() or path.resolve() in file.parents:
                file.chmod(stat.S_IMODE(regular(file).st_mode) & ~0o222)
    else:
        files = [path] if path.is_file() else list(path.rglob('*'))
        if any(p.is_symlink() for p in files):
            raise ValueError('Symlink in standalone publication')
        for file in files:
            if file.is_file():
                file.chmod(stat.S_IMODE(regular(file).st_mode) & ~0o222)


def main():
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        'Exit 0: success/clean; 1: findings; 2: invalid input or conflict. '
        'No Git, network or editor writes. Keep preview output outside archives, and retain '
        'the plan hash independently. One writer; stop concurrent archive writers.'),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    for name, text in (
            ('check', 'report changed, missing, unregistered and writable files under ROOT'),
            ('preview', 'print a plan enrolling unregistered files under ROOT; writes nothing'),
            ('repair', 'remove write bits from verified enrolled files only; never enrols'),
            ('verify-existing', 'refuse if any enrolled file under ROOT changed or is missing'),
            ('checkpoint', 'record ledger heads beside ROOT, once it is clean')):
        command = sub.add_parser(name, help=text)
        command.add_argument('root')
    command = sub.add_parser('apply', help='apply a reviewed plan: ledger events, then write bits removed')
    command.add_argument('plan')
    command.add_argument('--expect', required=True, help="the plan's reviewed SHA-256")
    command = sub.add_parser('seal', help='writer hook: enrol one output already published in an archive')
    command.add_argument('path')
    command = sub.add_parser('write-new', help='publish a new archive file from stdin; refuse replacement')
    command.add_argument('path')
    args = parser.parse_args()
    try:
        if args.command == 'check':
            result = report(args.root)
            print(json.dumps(result, indent=2))
            return int(any(findings(r) for r in result))
        if args.command == 'preview':
            print(encoded(preview(args.root)).decode(), end='')
            return 0
        if args.command == 'apply':
            result = apply_plan(json.loads(Path(args.plan).read_bytes()), args.expect)
        elif args.command == 'checkpoint':
            checks = report(args.root)
            if any(r['new'] or r['writable'] or r['checkpoint_writable'] for r in checks):
                raise ValueError('Enrol new records and restore permissions before checkpointing')
            verify_existing(args.root)
            checkpoint_heads(args.root)
            result = dict(checkpointed=str(anchor_home(args.root)))
        elif args.command == 'verify-existing':
            result = verify_existing(args.root)
        elif args.command == 'repair':
            result = repair(args.root)
        elif args.command == 'write-new':
            path = checked(args.path)
            archive = archive_for(path)
            if archive is None:
                raise ValueError('write-new requires an archives/ destination')
            # Reject ancestor links before creating anything.
            for parent in [path, *path.parents]:
                if parent.resolve() == archive.parent:
                    break
                if parent.is_symlink():
                    raise ValueError('Symlink in publication path')
            new_file(path, sys.stdin.buffer.read())
            seal_archive(path)
            result = dict(path=str(path), sha256=record(path)['sha256'])
        else:
            seal_archive(args.path)
            result = dict(sealed=args.path)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
