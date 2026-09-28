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
"""Seal items into archives, as poslib's doc/formats.org specifies, in lockstep with pos-seal.

Two steps: a plan, reviewed, then its application, named by the plan's hash.

    python3 seal.py seal SOURCE DESTINATION   prints a plan
    python3 seal.py write-new DESTINATION     stages stdin, prints a plan
    python3 seal.py write-new DESTINATION --apply
                                              for a program writing records itself:
                                              plans, applies at once, prints both
    python3 seal.py apply PLAN HASH           applies it

Exit 0 done, 2 refused.
"""
import json
import os
from pathlib import Path
import sys
import tempfile
import uuid

import archive_integrity as ai
from archive_integrity import Refused, encoded, sha
import cid


def outermost_archive(path):
    """The outermost directory named archives above path, or None."""
    found = None
    for parent in Path(path).parents:
        if parent.name == 'archives':
            found = parent
    return found


def item_files(source, rel):
    """source's files as {path within the archive: file}; hidden and special ones refused."""
    if source.name.startswith('.'):
        raise Refused('hidden', f'Hidden files are not sealed: {source}')
    if source.is_symlink():
        raise Refused('link', f'Symlink in item: {source}')
    if source.is_dir():
        files = {}
        for name in sorted(os.listdir(source)):
            files.update(item_files(source / name, rel + '/' + name))
        return files
    ai.regular(source)
    return {rel: source}


def collections(source, rel):
    if not source.is_dir():
        return []
    return ([rel] if ai.declared(source) else []) + [
        c for name in sorted(os.listdir(source)) for c in collections(source / name, rel + '/' + name)]


def entry(path):
    return dict(ai.record(path), cid=cid.cid_file(path))


def ledger_folder(archive):
    """Where the archive's ledger is, or for a new one, beside the archive."""
    folder = ai.ledger_folder(archive)
    return folder if folder.exists() or folder.is_symlink() else archive.parent / ai.INTEGRITY / 'ledger'


def last_id(files):
    for path in reversed(files):
        found = json.loads(path.read_bytes()).get('ledger_id')
        if found:
            return found
    return None


def entries_of(files):
    return dict(sorted((path, entry(file)) for path, file in files.items()))


def plan(source, destination, ledger_id=None):
    """The plan to seal source at destination, inside an archive."""
    source = ai.checked(source).resolve()
    destination = Path(os.path.abspath(destination))
    ai.checked(destination.parent)
    archive = outermost_archive(destination)
    if archive is None:
        raise Refused('destination', f'Destination is not in an archive: {destination}')
    rel = os.path.relpath(destination, archive)
    archive = archive.resolve()
    destination = archive / rel
    if outermost_archive(source) is not None:
        raise Refused('source', f'Source is already archived: {source}')
    if not source.exists() and not source.is_symlink():
        raise Refused('source', f'No such item: {source}')
    if destination.exists() or destination.is_symlink():
        raise Refused('destination', f'Destination exists: {destination}')
    try:
        ai.safe(rel)
    except Refused:
        raise Refused('destination', f'Unsafe destination: {rel}')
    if any(part.startswith('.') for part in rel.split('/')):
        raise Refused('hidden', f'Hidden files are not sealed: {rel}')
    known, head, events, files = ai.history(archive)[:4]
    actual = ai.inventory(archive)
    try:
        cids = cid.cid_tree(archive)
    except cid.ShardingUnsupported:
        cids = None
    compared = {n: dict(e, cid=cids.get(n)) if cids is not None and 'cid' in known.get(n, {}) else e
                for n, e in actual.items()}
    diff = ai.differences(known, compared)
    if diff['missing'] or diff['changed']:
        raise Refused('differs', f"Existing evidence differs in {archive}: {diff['missing']} {diff['changed']}")
    return dict(schema=1, operation='seal', source=str(source), destination=str(destination),
                archive=str(archive), ledger=str(ledger_folder(archive)), number=events + 1,
                previous=head, ledger_id=last_id(files) or ledger_id or str(uuid.uuid4()),
                add=entries_of(item_files(source, rel)), collections=sorted(collections(source, rel)),
                inventory_sha256=sha(encoded(actual)))


def stage(data, destination, ledger_id=None):
    """Stage data, a new record, beside the archive in _seal/, and plan to seal it."""
    archive = outermost_archive(Path(os.path.abspath(destination)))
    if archive is None:
        raise Refused('destination', f'Destination is not in an archive: {destination}')
    folder = archive.parent / '_seal'
    folder.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='new-', dir=folder)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
    os.chmod(name, 0o644)
    return plan(name, destination, ledger_id)


def protect(path):
    path.chmod(path.stat().st_mode & 0o7777 & ~0o222)


def checkpoint(archive, head):
    data = encoded(dict(schema=1, heads=[head], coverage='archive'))
    base = archive.parent
    folder = base / ai.INTEGRITY / 'checkpoints' if (base / ai.INTEGRITY).is_dir() else base / ai.ANCHORS
    path = folder / (sha(data) + '.json')
    if not path.exists():
        ai.new_file(path, data)


def apply(plan, expected):
    """Apply plan, whose canonical JSON has the SHA-256 expected; return (event, root)."""
    if sha(encoded(plan)) != expected:
        raise Refused('plan', 'Reviewed plan hash mismatch')
    if plan.get('schema') != 1 or plan.get('operation') != 'seal':
        raise Refused('plan', 'Not a seal plan')
    source, destination = Path(plan['source']), Path(plan['destination'])
    archive, ledger = Path(plan['archive']), Path(plan['ledger'])
    moved = not source.exists() and destination.exists()
    if not moved:
        if not (source.exists() and not destination.exists()):
            raise Refused('plan', f'Neither before nor after the move: {source}')
        if sha(encoded(ai.inventory(archive))) != plan['inventory_sha256']:
            raise Refused('plan', f'Archive changed since review: {archive}')
        rel = os.path.relpath(destination, archive)
        if encoded(plan['add']) != encoded(entries_of(item_files(source, rel))):
            raise Refused('plan', f'Item changed since review: {source}')
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.rename(source, destination)
    now = entries_of({path: archive / path for path in plan['add']})
    if encoded(plan['add']) != encoded(now):
        raise Refused('plan', f'Item changed after the move: {destination}')
    root = cid.cid_directory(archive)
    data = encoded(dict(schema=2, previous=plan['previous'], ledger_id=plan['ledger_id'],
                        add=plan['add'], root=root, collections=plan['collections']))
    event = ledger / f"{plan['number']:08}-{sha(data)}.json"
    head, events = ai.history(archive)[1:3]
    if not (head == sha(data) and events == plan['number']):
        if head != plan['previous'] or events + 1 != plan['number']:
            raise Refused('plan', f'Ledger changed since review: {archive}')
        ai.new_file(event, data)
    for path in plan['add']:
        protect(archive / path)
    checkpoint(archive, sha(data))
    return event, root


def main(args):
    try:
        if len(args) == 3 and args[0] == 'seal':
            sys.stdout.buffer.write(encoded(plan(args[1], args[2])))
        elif args[:1] == ['write-new'] and (len(args) == 2 or args[2:] == ['--apply']):
            planned = stage(sys.stdin.buffer.read(), args[1])
            if len(args) == 2:
                sys.stdout.buffer.write(encoded(planned))
            else:
                digest = sha(encoded(planned))
                event, root = apply(planned, digest)
                sys.stdout.buffer.write(encoded(dict(plan=planned, hash=digest, event=str(event), root=root)))
        elif len(args) == 3 and args[0] == 'apply':
            event, root = apply(json.loads(Path(args[1]).read_bytes()), args[2])
            sys.stdout.buffer.write(encoded(dict(event=str(event), root=root)))
        else:
            print('Usage: seal SOURCE DESTINATION | write-new DESTINATION [--apply] | apply PLAN HASH',
                  file=sys.stderr)
            return 2
        return 0
    except Refused as refused:
        print(f'{refused.kind}: {refused}', file=sys.stderr)
        return 2
    except json.JSONDecodeError:
        print('plan: Not a readable plan', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
