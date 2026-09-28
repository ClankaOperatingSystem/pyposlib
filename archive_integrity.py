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

One writer. Each outermost archives/ keeps additive hash-chained event files.
Nested historical archives (including their ledgers) are ordinary preserved bytes.
Thus a project's existing archive ledger moves unchanged when its parent retires it.
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

META = '.archive-integrity'
ANCHORS = '.archive-integrity-anchors'


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe(relative):
    p = PurePosixPath(relative)
    if (not relative or p.is_absolute() or str(p) != relative
            or any(x in ('', '.', '..') for x in relative.split('/')) or '\\' in relative):
        raise ValueError(f'Unsafe relative path: {relative}')
    return relative


def checked(path):
    """Reject link traversal, including symlinked ancestors; normalise macOS /tmp."""
    path = Path(os.path.abspath(path))
    # The OS supplies /tmp and /var aliases on macOS. Resolve the caller's root
    # before descending; all descendants are checked independently below.
    for part in [path, *path.parents]:
        if part.is_symlink() and str(part) not in ('/tmp', '/var'):
            raise ValueError(f'Symlink: {part}')
    return path


def regular(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError(f'Expected a regular file with one link: {path}')
    return info


def record(path):
    before = regular(path)
    data = path.read_bytes()
    after = regular(path)
    if (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError(f'File changed while reading: {path}')
    return dict(sha256=sha(data), size=len(data), mode=stat.S_IMODE(after.st_mode) & ~0o222)


def roots(root):
    """Discover outermost archive trees; ignore disposable/hidden active trees."""
    root = checked(root).resolve()
    if not root.is_dir():
        raise ValueError('Root must be an existing directory')
    if root.name == 'archives':
        return [root]
    found = []
    for here, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not d.startswith(('.', '_')))
        for name in list(dirs):
            p = Path(here) / name
            if p.is_symlink():
                raise ValueError(f'Symlink in discovery: {p}')
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
                raise ValueError(f'Symlink in archive: {Path(here) / name}')
        for name in files:
            path = Path(here) / name
            if Path(here) == archive and name == META:
                raise ValueError('Integrity metadata must be a directory')
            result[path.relative_to(archive).as_posix()] = record(path)
    return dict(sorted(result.items()))


def history(archive):
    folder = archive / META
    if not folder.exists() and not folder.is_symlink():
        return {}, None, 0, []
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError(f'Invalid ledger: {folder}')
    entries, previous, files, ledger_id = {}, None, [], None
    for number, path in enumerate(sorted(folder.iterdir()), 1):
        regular(path)
        data = path.read_bytes()
        match = re.fullmatch(r'(\d{8})-([0-9a-f]{64})\.json', path.name)
        if not match or int(match[1]) != number or sha(data) != match[2]:
            raise ValueError(f'Ledger sequence/hash failure: {path}')
        event = json.loads(data)
        if (set(event) not in ({'schema', 'previous', 'add'}, {'schema', 'previous', 'add', 'ledger_id'})
                or event['schema'] != 1 or event['previous'] != previous):
            raise ValueError(f'Ledger chain failure: {path}')
        # The first deployed hook wrote a v1 prefix before ledger UUIDs existed.
        # Preserve those events; the next event binds an identity additively.
        event_id = event.get('ledger_id')
        if event_id is not None:
            if str(uuid.UUID(event_id)) != event_id or (ledger_id is not None and event_id != ledger_id):
                raise ValueError('Ledger identity changed')
            ledger_id = event_id
        elif ledger_id is not None:
            raise ValueError('Ledger identity removed')
        if not isinstance(event['add'], dict):
            raise ValueError('Invalid ledger additions')
        for name, entry in event['add'].items():
            safe(name)
            if name.split('/')[0] == META or name in entries:
                raise ValueError('Ledger cannot replace an earlier entry or index itself')
            if (set(entry) != {'sha256', 'size', 'mode'} or not re.fullmatch('[0-9a-f]{64}', entry['sha256'])
                    or not isinstance(entry['size'], int) or entry['size'] < 0
                    or not isinstance(entry['mode'], int) or entry['mode'] & 0o222):
                raise ValueError('Invalid ledger entry')
            entries[name] = entry
        previous = sha(data)
        files.append(path)
    if not files:
        raise ValueError(f'Empty ledger needs investigation: {folder}')
    return entries, previous, len(files), files


def differences(known, actual):
    return dict(missing=sorted(set(known) - set(actual)),
                changed=sorted(k for k in known.keys() & actual.keys() if known[k] != actual[k]),
                new=sorted(set(actual) - set(known)))


def anchor_home(root):
    root = checked(root).resolve()
    return (root.parent if root.name == 'archives' else root) / ANCHORS


def checkpoint_files(root, archives):
    folders = {anchor_home(root), *(anchor_home(a) for a in archives)}
    files = []
    for folder in sorted(folders):
        if not folder.exists() and not folder.is_symlink():
            continue
        if folder.is_symlink() or not folder.is_dir():
            raise ValueError('Invalid checkpoint directory')
        files.extend(sorted(folder.iterdir()))
    return files


def check_anchors(root, archives):
    required = set()
    for path in checkpoint_files(root, archives):
        regular(path)
        data = path.read_bytes()
        if path.name != sha(data) + '.json':
            raise ValueError(f'Checkpoint hash failure: {path}')
        value = json.loads(data)
        if (set(value) != {'schema', 'heads', 'coverage'} or value['schema'] != 1
                or value['coverage'] not in ('archive', 'tree')
                or not isinstance(value['heads'], list)
                or any(not isinstance(h, str) or not re.fullmatch('[0-9a-f]{64}', h) for h in value['heads'])):
            raise ValueError('Invalid checkpoint')
        if Path(root).name != 'archives' or value['coverage'] == 'archive':
            required.update(value['heads'])
    present = set()
    for archive in archives:
        # Includes the unchanged ledgers carried inside retired projects.
        for path in archive.rglob('*.json'):
            if path.parent.name == META:
                regular(path)
                present.add(sha(path.read_bytes()))
    if required - present:
        raise ValueError('Missing anchored ledger (archive removed or history truncated): ' +
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
        known, head, count, metadata = history(archive)
        actual = inventory(archive)
        diff = differences(known, actual)
        writable = [str(p.relative_to(archive)) for p in [*(archive / n for n in actual), *metadata]
                    if regular(p).st_mode & 0o222]
        reports.append(dict(archive=str(archive), head=head, events=count, files=len(actual),
                            writable=sorted(writable), checkpoint_writable=writable_checkpoints if not reports else [], **diff))
    return reports


def preview(root, target=None):
    root = checked(root).resolve()
    check_anchors(root, roots(root))
    plan = dict(schema=1, root=str(root), archives=[])
    for archive in roots(root):
        known, head, count, metadata = history(archive)
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
        known, head, count, metadata = history(archive)
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
            new_file(archive / META / filename, data)
        checkpoint('after-ledger')
        # Only protect the records selected by this operation and ledger files.
        for name in item['add']:
            path = archive / name
            if record(path) != item['add'][name]:
                raise ValueError(f'File changed during enrolment: {path}')
            path.chmod(stat.S_IMODE(regular(path).st_mode) & ~0o222)
        for path in (archive / META).iterdir():
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
        known, _, _, metadata = history(archive)
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
        known, _, _, _ = history(archive)
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
        'preview/check read saved bytes; apply adds immutable ledger events and removes write bits; '
        'repair removes write bits only from verified enrolled files. No Git/network/editor writes. '
        'Keep preview output outside archives. Retain the returned plan hash independently. '
        'One writer; stop concurrent archive writers. No live-editor counterpart is installed.'))
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ('check', 'preview', 'repair', 'verify-existing', 'checkpoint'):
        command = sub.add_parser(name)
        command.add_argument('root')
    command = sub.add_parser('apply')
    command.add_argument('plan')
    command.add_argument('--expect', required=True)
    command = sub.add_parser('seal', help='publication hook for existing archive writers')
    command.add_argument('path')
    command = sub.add_parser('write-new', help='publish a new archive file from stdin; refuse replacement')
    command.add_argument('path')
    args = parser.parse_args()
    try:
        if args.command == 'check':
            result = report(args.root)
            print(json.dumps(result, indent=2))
            return int(any(not r['head'] or r['changed'] or r['missing'] or r['new'] or r['writable'] or r['checkpoint_writable'] for r in result))
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
