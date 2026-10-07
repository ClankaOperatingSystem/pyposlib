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
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

from . import archive_integrity as ai
from .archive_integrity import Refused, encoded, sha
from . import cid
from . import remote
from . import signin


def outermost_archive(path):
    """The outermost directory named archives above path, or None."""
    found = None
    for parent in Path(path).parents:
        if parent.name == 'archives':
            found = parent
    return found


def link(path):
    """The ipfs:// link to path, a sealed path in an archive, as poslib's
    pos-links-link gives it: the CID of the sealed item holding it, else of
    the collection, else of the enrolled file, then the path within it.
    Refuses 'unsealed' for a path never sealed or in no archive."""
    target = Path(os.path.abspath(path))
    archive = outermost_archive(target)
    if archive is None:
        raise Refused('unsealed', f'Not a path in an archive: {target}')
    rel = target.relative_to(archive).as_posix()
    entries, _, _, _, _, sealed_collections, items, _ = ai.history(archive)
    item = next((i for i in [*items, *sealed_collections] if rel == i or rel.startswith(i + '/')),
                rel if rel in entries else None)
    if item is None:
        raise Refused('unsealed', f'Link to an archived path not sealed: {target}')
    if ai.kept(archive):
        found = ai.fold_cids(archive)[item]
    elif (archive / item).is_dir():
        found = cid.cid_directory(archive / item)
    else:
        found = cid.cid_file(archive / item)
    return f'ipfs://{found}{rel[len(item):]}'


LINK = re.compile(r'ipfs://([^/?#:]+)(?:/([^?#]*))?')


def fetch(uri, start=None, keeper_for=None):
    """The bytes of the archived file uri names, ipfs://CID or ipfs://CID/PATH,
    as poslib's pos-index-bytes gives them. PATH ends where an Org search
    begins, at '::'.

    Each scope above start, by default the current directory, is tried,
    nearest first: the file is the one at PATH beneath whatever the scope's
    archives hold under CID, or that itself. A file on disk is read as it
    lies. A file a keeper keeps is read from the keeper by the CID its ledger
    enrols, and refused 'entry' if the bytes are not that CID's. Refuses
    'absent' if uri is no such link or no scope has such a file; a directory
    is not a file. keeper_for makes a remote.RemoteArchive of a URL, by
    default ai.keeper_of."""
    match = LINK.match(str(uri))
    if not match:
        raise Refused('absent', f'Not an ipfs:// link: {uri}')
    wanted, path = match[1], (match[2] or '').split('::')[0]
    here = Path(os.path.abspath(start or '.'))
    scopes = [d for d in [here, *here.parents]
              if d.name != 'archives' and ((d / 'archives').is_dir() or ai.kept_here(d))]

    def places(scope, kept):
        """Each (archive, path within it) the link may name in scope's
        archives, those a keeper keeps or those on disk."""
        for archive in ai.roots(scope):
            if bool(ai.kept(archive)) != kept:
                continue
            try:
                cids = ai.fold_cids(archive) if kept else cid.cid_tree(archive)
            except cid.ShardingUnsupported:
                continue
            for base in sorted(b for b, found in cids.items() if found == wanted):
                yield archive, '/'.join(part for part in (base, path) if part not in ('', '.'))

    for scope in scopes:
        try:
            for archive, rel in places(scope, False):
                if rel and (archive / rel).is_file():
                    return (archive / rel).read_bytes()
        except Refused:
            continue
    for scope in scopes:
        for archive, rel in places(scope, True):
            entry = ai.history(archive)[0].get(rel)
            if entry:
                data = (keeper_for or ai.keeper_of)(ai.kept(archive)).read(entry['cid'])
                if cid.cid_bytes(data) != entry['cid']:
                    raise Refused('entry', f'The keeper\'s bytes are not those of {entry["cid"]}')
                return data
    raise Refused('absent', f'No archived file for {uri}')


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
    return ai.identity(files)


def entries_of(files):
    return dict(sorted((path, entry(file)) for path, file in files.items()))


def plan(source, destination, ledger_id=None):
    """The plan to seal source at destination, inside an archive. ledger_id
    names a new ledger; by default it takes the id its scope's entry names,
    else one made at random."""
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
    known, head, events, files, _, sealed_collections, items, _ = ai.history(archive)
    within = next((i for i in [*items, *sealed_collections] if rel == i or rel.startswith(i + '/')), None)
    if within:
        raise Refused('sealed', f'Destination is within sealed {within}: {rel}')
    named = ai.named(archive)
    ai.as_named(archive, files)
    if named and ledger_id and named != ledger_id:
        raise Refused('identity', f'Not the ledger its entry names, {named}: {archive}')
    keeper = ai.kept(archive)
    if keeper:
        # Nothing of it is on disk to compare: what it holds is what its ledger enrols.
        if head is not None and not ai.is_event_cid(head):
            raise Refused('kept', f'A keeper keeps a ledger of schema 3; convert this one first: {archive}')
        actual = ai.kept_entries(archive, known)
    else:
        actual = ai.inventory(archive)
        try:
            cids = cid.cid_tree(archive) if archive.exists() else {}
        except cid.ShardingUnsupported:
            cids = None
        compared = {n: dict(e, cid=cids.get(n)) if cids is not None and 'cid' in known.get(n, {}) else e
                    for n, e in actual.items()}
        diff = ai.differences(known, compared)
        if diff['missing'] or diff['changed']:
            raise Refused('differs', f"Existing evidence differs in {archive}: {diff['missing']} {diff['changed']}")
    held = item_files(source, rel)
    if any(p.endswith(('.org', '.md')) for p in held):
        raise Refused('interpretation', f'Links in Org and Markdown are poslib\'s to resolve: {source}')
    return dict(schema=2, operation='seal', source=str(source), destination=str(destination),
                archive=str(archive), ledger=str(ledger_folder(archive)), number=events + 1,
                previous=head, ledger_id=last_id(files) or named or ledger_id or str(uuid.uuid4()),
                add=entries_of(held), collections=sorted(collections(source, rel)),
                links=[], originals={}, rumours=[], inventory_sha256=sha(encoded(actual)),
                **(dict(kept=keeper) if keeper else {}))


def stage(data, destination, ledger_id=None):
    """Stage data, a new record, beside the archive in _seal/, with destination's
    extension, and plan to seal it. If planning fails, nothing is left staged."""
    archive = outermost_archive(Path(os.path.abspath(destination)))
    if archive is None:
        raise Refused('destination', f'Destination is not in an archive: {destination}')
    folder = archive.parent / '_seal'
    folder.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='new-', suffix=Path(destination).suffix, dir=folder)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
    os.chmod(name, 0o644)
    try:
        return plan(name, destination, ledger_id)
    except Exception:
        os.remove(name)
        if not any(folder.iterdir()):
            folder.rmdir()
        raise


def protect(path):
    path.chmod(path.stat().st_mode & 0o7777 & ~0o222)


def checkpoint(archive, head):
    data = encoded(dict(schema=1, heads=[head], coverage='archive'))
    base = archive.parent
    folder = base / ai.INTEGRITY / 'checkpoints' if (base / ai.INTEGRITY).is_dir() else base / ai.ANCHORS
    path = folder / (sha(data) + '.json')
    if not path.exists():
        ai.new_file(path, data)


def rewrite(data, rewrites):
    """data with each (offset, from, to) of rewrites applied; from must be at offset."""
    for offset, old, new in sorted(rewrites, reverse=True):
        old, new = old.encode(), new.encode()
        if data[offset:offset + len(old)] != old:
            raise Refused('plan', f'Link not where it was planned, at byte {offset}')
        data = data[:offset] + new + data[offset + len(old):]
    return data


def empty_directories(top, rel):
    """The directories at or under top that hold nothing IPFS would add, as
    paths from rel for top. Hidden entries count for nothing and hidden
    directories are not entered, as IPFS leaves both out."""
    if not top.is_dir() or top.is_symlink():
        return []
    names = sorted(n for n in os.listdir(top) if not n.startswith('.'))
    if not names:
        return [rel] if rel else []
    return [p for name in names
            for p in empty_directories(top / name, f'{rel}/{name}' if rel else name)]


def is_staging(path):
    """Whether path is a staging directory left empty: _seal, holding nothing."""
    return path.name == '_seal' and path.is_dir() and not path.is_symlink() and not os.listdir(path)


def leave_stage(source):
    """Remove the directory source lay in, if a staging directory left
    empty. A record staged by write-new leaves it so."""
    if is_staging(source.parent):
        source.parent.rmdir()


def drop_staging(top):
    """Remove each staging directory left empty under top, an item. Hidden
    directories and nested archives are not entered, nor links followed."""
    if not top.is_dir() or top.is_symlink():
        return
    for name in sorted(os.listdir(top)):
        if name.startswith('.') or name == 'archives':
            continue
        if is_staging(top / name):
            (top / name).rmdir()
        else:
            drop_staging(top / name)


def event_of(plan, item, add, collections, empty):
    """The event sealing add as item, with its empty directories: its ledger
    file's name, what names it, and its bytes.

    A ledger with no event yet, or one whose head is a block, takes a schema 3
    event: a DAG-JSON block named by its CID, its root the fold of what the
    ledger enrols. A schema 1 or 2 ledger takes a schema 2 event until it is
    converted."""
    archive = Path(plan['archive'])
    entries, head, events, _, _, _, _, empties = ai.history(archive)
    if head is None or ai.is_event_cid(head):
        root = ai.fold({**entries, **add}, [*empties, *empty])['.']
        data = ai.block(dict(schema=3, previous=ai.link(head) if head else None,
                             ledger_id=plan['ledger_id'], item=item, add=add, root=root,
                             collections=collections, empty=empty))
        name = ai.event_cid(data)
    else:
        data = encoded(dict(schema=2, previous=head, ledger_id=plan['ledger_id'],
                            item=item, add=add,
                            root=cid.cid_directory(archive), collections=collections))
        name = sha(data)
    return f'{events + 1:08}-{name}.json', name, data


def write_event(plan, destination, add, collections):
    """Write the event sealing add at destination; its hash or, in schema 3, its CID."""
    item = os.path.relpath(destination, plan['archive'])
    file, name, data = event_of(plan, item, add, collections, empty_directories(destination, item))
    ai.new_file(Path(plan['ledger']) / file, data)
    return name


def convert(root):
    """Bring each schema 2 ledger under root to schema 3, by one event.

    The event links the head as a block, names the hash it had, and enrols
    the empty directories the archive holds, so that the fold of the ledger
    is the archive's CID. Refused unless every archive is as its ledger says,
    before any event is written.
    {converted: [{archive, event, head}], skipped: [{archive, reason}]}."""
    converted, skipped, pending = [], [], []
    for archive in ai.roots(root):
        entries, head, events, files, recorded, _, _, _ = ai.history(archive)
        reason = ('no ledger' if head is None else 'schema 3' if ai.is_event_cid(head)
                  else 'legacy entries' if any('cid' not in e for e in entries.values()) else None)
        if reason:
            skipped.append(dict(archive=str(archive), reason=reason))
            continue
        try:
            cids = cid.cid_tree(archive)
        except cid.ShardingUnsupported as unsupported:
            raise Refused('sharding-unsupported', str(unsupported))
        actual = {n: dict(e, cid=cids.get(n)) for n, e in ai.inventory(archive).items()}
        diff = ai.differences(entries, actual)
        if diff['missing'] or diff['changed'] or diff['new'] or recorded != cids['.']:
            raise Refused('unclean', f'The archive is not as its ledger says; check it first: {archive}')
        empty = empty_directories(archive, '')
        folded = ai.fold(entries, empty)['.']
        if folded != recorded:
            raise Refused('root', f'The ledger does not account for the archive\'s CID: {archive}')
        data = ai.block({'schema': 3, 'kind': 'conversion', 'from': head,
                         'previous': ai.link(ai.event_cid(ai.as_block(files[-1].read_bytes()))),
                         'ledger_id': last_id(files), 'empty': empty, 'root': folded})
        name = ai.event_cid(data)
        path = Path(files[-1]).parent / f'{events + 1:08}-{name}.json'
        pending.append((archive, path, data, name))
    for archive, path, data, name in pending:
        ai.new_file(path, data)
        checkpoint(archive, name)
        converted.append(dict(archive=str(archive), event=str(path), head=name))
    return dict(converted=converted, skipped=skipped)


def sealed_so_far(plan):
    """The items plan's events have sealed so far; a stranger's is refused."""
    archive = Path(plan['archive'])
    files = ai.history(archive)[3]
    hashes = [f.name[9:-5] for f in files]
    if plan['previous'] is None:
        since = files
    elif plan['previous'] in hashes:
        since = files[hashes.index(plan['previous']) + 1:]
    else:
        raise Refused('plan', f'Ledger changed since review: {archive}')
    expected = [r['destination'] for r in plan['rumours']] + [
        os.path.relpath(plan['destination'], archive)]
    sealed = [json.loads(f.read_bytes()).get('item') for f in since]
    if sealed != expected[:len(sealed)]:
        raise Refused('plan', f'Ledger changed since review: {archive}')
    return sealed


def rewrite_source(plan):
    """Rewrite the links in the plan's item where it lies, unless done already."""
    source, archive = Path(plan['source']), Path(plan['archive'])
    rel = os.path.relpath(plan['destination'], archive)
    for path, original in plan['originals'].items():
        file = source if path == rel else source / path[len(rel) + 1:]
        data = file.read_bytes()
        if sha(data) == original:
            mode = file.stat().st_mode & 0o7777
            file.write_bytes(rewrite(data, [(l['offset'], l['from'], l['to']) for l in plan['links']
                                            if l['file'] == path and l['from'] != l['to']]))
            file.chmod(mode)
        elif sha(data) != plan['add'][path]['sha256']:
            raise Refused('plan', f'Item changed since review: {file}')


# Where this library is installed: the parent of its package. Its COMMIT
# file, or the repository git reads there, says which commit the tool is at.
TOOL_DIRECTORY = Path(__file__).resolve().parent.parent


def tool_commit(directory=None):
    """The commit the tool installed in DIRECTORY (TOOL_DIRECTORY by default)
    is at, or None: read from the COMMIT file an image writes beside the
    package, else asked of git where DIRECTORY is a repository."""
    directory = Path(directory or TOOL_DIRECTORY)
    file = directory / 'COMMIT'
    if file.is_file():
        commit = file.read_text().strip()
        return commit if re.fullmatch(r'[0-9a-f]+', commit) else None
    if not (directory / '.git').is_dir():
        return None
    try:
        done = subprocess.run(['git', '-C', str(directory), 'rev-parse', '--verify', '-q', 'HEAD'],
                              capture_output=True, text=True, timeout=60,
                              env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(directory.parent)))
    except (OSError, subprocess.SubprocessError):
        return None
    commit = done.stdout.rstrip('\n')
    return commit if done.returncode == 0 and commit else None


def claims_of(plan, expected):
    """What this client says of where a seal came from, for its keeper to
    record: the plan's hash, where there was a plan, the tool and the commit
    it is at, where it knows it, and of the scope's repository, where there
    is one and git reads it, the scope's path, the commit and branch it is
    at, whether its working tree is dirty, and each remote's URL less any
    user and password. Strings by name."""
    claims = dict(tool='pyposlib', **(dict(plan=expected) if expected else {}))
    if commit := tool_commit():
        claims['tool_commit'] = commit
    scope = Path(plan['archive']).parent
    root = next((part for part in [scope, *scope.parents] if (part / '.git').exists()), None)
    if root is None:
        return claims
    claims['scope'] = scope.relative_to(root).as_posix()

    def git(*args):
        try:
            # The ceiling keeps git to this repository: one it cannot read is not
            # answered for by whatever repository lies above it.
            done = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True, timeout=60,
                                  env=dict(os.environ, GIT_CEILING_DIRECTORIES=str(root.parent)))
        except (OSError, subprocess.SubprocessError):
            return None
        return done.stdout.rstrip('\n') if done.returncode == 0 else None

    commit, branch = git('rev-parse', '--verify', '-q', 'HEAD'), git('symbolic-ref', '--short', '-q', 'HEAD')
    status = git('status', '--porcelain')
    if commit:
        claims['commit'] = commit
    if branch:
        claims['branch'] = branch
    if status is not None:
        claims['dirty'] = 'true' if status else 'false'
    for line in (git('config', '--get-regexp', r'^remote\..*\.url$') or '').splitlines():
        key, _, url = line.partition(' ')
        claims[key[:-len('.url')]] = re.sub(r'^([a-z][a-z0-9+.-]*://)[^/@]*@', r'\1', url)
    return claims


def catch_up(archive, ledger, keeper):
    """Bring the ledger to what its keeper holds, writing the events it lacks.

    A seal interrupted between the keeper's answer and the ledger's file
    leaves the keeper one event ahead. Refuses 'chain', with the ledger as it
    was, unless the keeper's events continue this ledger's and end at the
    keeper's head."""
    described = keeper.describe()
    head, events = ai.history(archive)[1:3]
    written = []
    try:
        for number in range(events + 1, described['events'] + 1):
            data = keeper.event(number)
            path = ledger / f'{number:08}-{ai.event_cid(data)}.json'
            ai.new_file(path, data)
            written.append(path)
        try:
            caught = ai.history(archive)[1:3]
        except Refused:
            caught = None
        if caught != (described['head'], described['events']):
            raise Refused('chain', f'The keeper holds another ledger than this one: {archive}')
    except Refused:
        for path in written:
            path.unlink()
        if events == 0 and ledger.is_dir() and not any(ledger.iterdir()):
            ledger.rmdir()
        raise


def apply_kept(plan, expected, keeper, claims):
    """Apply plan to an archive a keeper keeps: each event is sent with its
    files, written to the ledger once the keeper has it, and the item is
    then removed from where it lay. Interrupted, it resumes."""
    source, destination = Path(plan['source']), Path(plan['destination'])
    archive, ledger = Path(plan['archive']), Path(plan['ledger'])
    rel = os.path.relpath(destination, archive)
    if ai.kept(archive) != plan['kept']:
        raise Refused('plan', f'The archive is not kept as planned: {archive}')
    if keeper is None:
        keeper = ai.keeper_of(plan['kept'])
    if claims is None:
        claims = claims_of(plan, expected)
    catch_up(archive, ledger, keeper)
    sealed = sealed_so_far(plan)
    if not sealed and sha(encoded(ai.kept_entries(archive, ai.history(archive)[0]))) != plan['inventory_sha256']:
        raise Refused('plan', f'Archive changed since review: {archive}')

    def send(item, add, collections, empty, files):
        file, _, data = event_of(plan, item, add, collections, empty)
        keeper.append(file, data, files, claims)
        ai.new_file(ledger / file, data)

    for rumour in plan['rumours']:
        if rumour['destination'] in sealed:
            continue
        data = rumour['text'].encode()
        added = dict(cid=cid.cid_bytes(data), mode=0o444, sha256=sha(data), size=len(data))
        send(rumour['destination'], {rumour['destination']: added}, [], [], {added['cid']: data})
    if rel not in sealed:
        if not source.exists():
            raise Refused('plan', f'The item is not where it was planned: {source}')
        rewrite_source(plan)
        drop_staging(source)
        held = item_files(source, rel)
        if encoded(plan['add']) != encoded(entries_of(held)):
            raise Refused('plan', f'Item changed since review: {source}')
        send(rel, plan['add'], plan['collections'], empty_directories(source, rel),
             {plan['add'][path]['cid']: file.read_bytes() for path, file in held.items()})
    # The keeper has the item and the ledger says so: the copy here goes.
    if source.exists() or source.is_symlink():
        if encoded(plan['add']) != encoded(entries_of(item_files(source, rel))):
            raise Refused('plan', f'Item changed since it was sealed: {source}')
        if source.is_dir():
            shutil.rmtree(source)
        else:
            source.unlink()
    leave_stage(source)
    head, _, files = ai.history(archive)[1:4]
    checkpoint(archive, head)
    return files[-1], json.loads(files[-1].read_bytes())['root']


def apply(plan, expected, keeper=None, claims=None):
    """Apply plan, whose canonical JSON has the SHA-256 expected: its rumours, then
    its item, links rewritten; return (event, root).

    A plan for an archive a keeper keeps is sent to it: keeper is the
    remote.RemoteArchive to send to, by default the plan's over HTTP with the
    token keeper_of gives it, and claims what to say of the seal, by default
    claims_of."""
    if sha(encoded(plan)) != expected:
        raise Refused('plan', 'Reviewed plan hash mismatch')
    if plan.get('schema') != 2 or plan.get('operation') != 'seal':
        raise Refused('plan', 'Not a seal plan')
    if plan.get('kept'):
        return apply_kept(plan, expected, keeper, claims)
    if ai.kept(plan['archive']):
        raise Refused('plan', f"The archive is not kept as planned: {plan['archive']}")
    source, destination = Path(plan['source']), Path(plan['destination'])
    archive = Path(plan['archive'])
    rel = os.path.relpath(destination, archive)
    sealed = sealed_so_far(plan)
    if not sealed and not destination.exists():
        if sha(encoded(ai.inventory(archive))) != plan['inventory_sha256']:
            raise Refused('plan', f'Archive changed since review: {archive}')
    for rumour in plan['rumours']:
        there = archive / rumour['destination']
        if rumour['destination'] in sealed:
            continue
        if not there.exists():
            ai.new_file(there, rumour['text'].encode())
        if there.read_bytes() != rumour['text'].encode():
            raise Refused('plan', f'Rumour differs from its plan: {there}')
        write_event(plan, there, entries_of({rumour['destination']: there}), [])
    if not destination.exists():
        if not source.exists():
            raise Refused('plan', f'Neither before nor after the move: {source}')
        rewrite_source(plan)
        drop_staging(source)
        if encoded(plan['add']) != encoded(entries_of(item_files(source, rel))):
            raise Refused('plan', f'Item changed since review: {source}')
        destination.parent.mkdir(parents=True, exist_ok=True)
        os.rename(source, destination)
    leave_stage(source)
    if encoded(plan['add']) != encoded(entries_of({p: archive / p for p in plan['add']})):
        raise Refused('plan', f'Item changed after the move: {destination}')
    if rel not in sealed:
        write_event(plan, destination, plan['add'], plan['collections'])
    for path in [*plan['add'], *(r['destination'] for r in plan['rumours'])]:
        protect(archive / path)
    head, _, files = ai.history(archive)[1:4]
    checkpoint(archive, head)
    return files[-1], json.loads(files[-1].read_bytes())['root']


def added_paths(files, entries):
    """For each of a ledger's event files in order, the paths it enrolled as
    the ledger now has them, in entries: an event before a schema 2
    conversion enrolled paths that conversion may have renamed or removed."""
    values = [json.loads(path.read_bytes()) for path in files]
    conversion = next((i for i, v in enumerate(values)
                       if v.get('schema') == 2 and v.get('kind') == 'conversion'), None)
    rename = values[conversion]['rename'] if conversion is not None else {}
    added = []
    for i, value in enumerate(values):
        paths = list(value.get('add', {}))
        if conversion is not None and i < conversion:
            paths = [rename.get(path, path) for path in paths]
        added.append([path for path in paths if path in entries])
    return added, next((i for i, v in enumerate(values) if v.get('schema') == 3), None)


def keep(root, keeper_for=None, claims=None):
    """Move to its keeper each archive under root that its scope's entry says a
    keeper keeps and whose files are still on disk.

    The keeper is sent the events it lacks, in order, each with the files it
    enrolled. A keeper that holds earlier events is taken to hold their
    files; if it refuses the first schema 3 event for want of them, that
    event is sent again with every file enrolled before it, since it is where
    a keeper requires them. A first event that names no ledger, as those of a
    ledger begun before events carried a ledger_id, is sent with the events
    after it up to the first that names one, by which the keeper knows whose
    it is (remote.following). Once the keeper holds the ledger's head and its root, the archive
    is removed from disk. Refused unless every such archive is as its ledger
    says, with a ledger of schema 3 beside it and nothing hidden, before
    anything is sent. Interrupted, it resumes.
    {kept: [{archive, keeper, events, files}], skipped: [{archive, reason}]}:
    events and files are those sent.
    keeper_for makes a remote.RemoteArchive of a URL, by default ai.keeper_of;
    claims is what to say of each event, by default claims_of."""
    kept, skipped, pending = [], [], []
    for archive in ai.roots(root):
        url = ai.kept(archive)
        entries, head, events, files, recorded, _, _, empty = ai.history(archive)
        reason = ('on disk' if not url else 'no ledger' if head is None
                  else 'kept' if not (archive.exists() and ai.inventory(archive)) else None)
        if reason:
            skipped.append(dict(archive=str(archive), reason=reason))
            continue
        ai.as_named(archive, files)
        if not ai.is_event_cid(head):
            raise Refused('kept', f'A keeper keeps a ledger of schema 3; convert this one first: {archive}')
        if files[0].parent.parent.parent != archive.parent:
            raise Refused('ledger', f'A kept archive\'s ledger lies beside it, not inside: {archive}')
        try:
            cids = cid.cid_tree(archive)
        except cid.ShardingUnsupported as unsupported:
            raise Refused('sharding-unsupported', str(unsupported))
        actual = {n: dict(e, cid=cids.get(n)) for n, e in ai.inventory(archive).items()}
        diff = ai.differences(entries, actual)
        if (diff['missing'] or diff['changed'] or diff['new'] or recorded != cids['.']
                or ai.fold(entries, empty)['.'] != recorded):
            raise Refused('unclean', f'The archive is not as its ledger says; check it first: {archive}')
        if any(part.startswith('.') for path in entries for part in path.split('/')):
            raise Refused('hidden', f'A keeper holds no hidden file, and this ledger enrols one: {archive}')
        pending.append((archive, url, entries, head, files, recorded))
    for archive, url, entries, head, files, recorded in pending:
        keeper = (keeper_for or ai.keeper_of)(url)
        said = claims_of(dict(archive=str(archive)), None) if claims is None else claims
        described = keeper.describe()
        held = described['events']
        if held > len(files) or (held and described['head'] != files[held - 1].name[9:-5]):
            raise Refused('chain', f'The keeper holds another ledger than this one: {archive}')
        added, first = added_paths(files, entries)
        events = [(file.name, file.read_bytes()) for file in files]
        sent = {}

        def batch_of(paths):
            batch = {}
            for path in paths:
                given = entries[path]['cid']
                if given not in sent and given not in batch:
                    batch[given] = (archive / path).read_bytes()
            return batch

        for i in range(held, len(files)):
            batch = batch_of(added[i])
            vouching = remote.following(events, i + 1)
            try:
                keeper.append(*events[i], batch, said, vouching)
            except Refused as refused:
                # The keeper took an earlier event without its files: they
                # go with the event at which it requires them.
                if not (refused.kind == 'entry' and i == first and held):
                    raise
                batch = batch_of(path for j in range(i + 1) for path in added[j])
                keeper.append(*events[i], batch, said, vouching)
            sent.update(batch)
        described = keeper.describe()
        if (described['head'], described['events'], described['root']) != (head, len(files), recorded):
            raise Refused('chain', f'The keeper does not hold this ledger as it is: {archive}')
        shutil.rmtree(archive)
        kept.append(dict(archive=str(archive), keeper=url, events=len(files) - held, files=len(sent)))
    return dict(kept=kept, skipped=skipped)


def recall(root, keeper_for=None):
    """Bring back from its keeper each archive under root that its scope's
    entry says a keeper keeps: the reverse of keep.

    Every file the ledger enrols and the disk lacks is read from the keeper,
    by the CID the ledger enrols it under, held to that CID, and written at
    its path with its recorded mode; the empty directories the ledger records
    are made. Refused before anything is asked unless the ledger is of schema
    3 and folds to its recorded root, and what is on disk already is enrolled
    and unchanged. The keeper must hold the ledger as it is. Interrupted, it
    resumes. The archive is then on disk as its ledger says, and still its
    keeper's by its entry, the state keep begins from.
    {recalled: [{archive, keeper, files}], skipped: [{archive, reason}]}:
    files are those read.
    keeper_for makes a remote.RemoteArchive of a URL, by default ai.keeper_of."""
    recalled, skipped, pending = [], [], []
    for archive in ai.roots(root):
        url = ai.kept(archive)
        entries, head, _, files, recorded, _, _, empty = ai.history(archive)
        reason = 'on disk' if not url else 'no ledger' if head is None else None
        if reason:
            skipped.append(dict(archive=str(archive), reason=reason))
            continue
        ai.as_named(archive, files)
        if not ai.is_event_cid(head):
            raise Refused('kept', f'A keeper keeps a ledger of schema 3: {archive}')
        if ai.fold(entries, empty)['.'] != recorded:
            raise Refused('root', f'The ledger does not fold to its recorded root: {archive}')
        actual = {}
        if archive.exists():
            try:
                cids = cid.cid_tree(archive)
            except cid.ShardingUnsupported as unsupported:
                raise Refused('sharding-unsupported', str(unsupported))
            actual = {n: dict(e, cid=cids.get(n)) for n, e in ai.inventory(archive).items()}
        diff = ai.differences(entries, actual)
        if diff['changed'] or diff['new']:
            raise Refused('differs', f'What is on disk is not what the ledger enrols: {archive}')
        pending.append((archive, url, entries, head, files, recorded, empty, diff['missing']))
    for archive, url, entries, head, files, recorded, empty, missing in pending:
        keeper = (keeper_for or ai.keeper_of)(url)
        described = keeper.describe()
        if (described['head'], described['events'], described['root']) != (head, len(files), recorded):
            raise Refused('chain', f'The keeper does not hold this ledger as it is: {archive}')
        read = {}
        for path in missing:
            given = entries[path]['cid']
            if given not in read:
                read[given] = keeper.read(given)
                if cid.cid_bytes(read[given]) != given:
                    raise Refused('entry', f'The keeper\'s bytes are not those of {given}')
            ai.new_file(archive / path, read[given], entries[path]['mode'])
        for path in empty:
            (archive / path).mkdir(parents=True, exist_ok=True)
        archive.mkdir(parents=True, exist_ok=True)
        if cid.cid_tree(archive)['.'] != recorded:
            raise Refused('root', f'The archive brought back is not its recorded root: {archive}')
        recalled.append(dict(archive=str(archive), keeper=url, files=len(read)))
    return dict(recalled=recalled, skipped=skipped)


def main(args):
    try:
        if args[:1] == ['seal'] and (len(args) == 3 or args[3:] == ['--apply'] and len(args) == 4):
            planned = plan(args[1], args[2])
            if len(args) == 3:
                sys.stdout.buffer.write(encoded(planned))
            else:
                digest = sha(encoded(planned))
                event, root = apply(planned, digest)
                sys.stdout.buffer.write(encoded(dict(plan=planned, hash=digest, event=str(event), root=root)))
        elif args[:1] == ['write-new'] and (len(args) == 2 or args[2:] == ['--apply']):
            planned = stage(sys.stdin.buffer.read(), args[1])
            if len(args) == 2:
                sys.stdout.buffer.write(encoded(planned))
            else:
                digest = sha(encoded(planned))
                event, root = apply(planned, digest)
                sys.stdout.buffer.write(encoded(dict(plan=planned, hash=digest, event=str(event), root=root)))
        elif len(args) == 2 and args[0] == 'convert':
            sys.stdout.buffer.write(encoded(convert(args[1])))
        elif len(args) == 2 and args[0] == 'keep':
            sys.stdout.buffer.write(encoded(keep(args[1])))
        elif len(args) == 2 and args[0] == 'recall':
            sys.stdout.buffer.write(encoded(recall(args[1])))
        elif len(args) == 2 and args[0] == 'link':
            print(link(args[1]))
        elif len(args) == 2 and args[0] == 'fetch':
            sys.stdout.buffer.write(fetch(args[1]))
        elif len(args) == 2 and args[0] == 'sign-in':
            sys.stdout.buffer.write(encoded(signin.sign_in(args[1])))
        elif len(args) == 3 and args[0] == 'apply':
            event, root = apply(json.loads(Path(args[1]).read_bytes()), args[2])
            sys.stdout.buffer.write(encoded(dict(event=str(event), root=root)))
        else:
            sys.stderr.write(ai.USAGE)
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
