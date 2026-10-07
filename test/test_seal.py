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
"""Sealing against the fixtures shared with poslib, and its requirements."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock

from fixtures import Tape, fixtures, write, writable
from test_formats import Built
from pyposlib import archive_integrity as ai
from pyposlib import cid
from pyposlib import remote
from pyposlib import seal


def relative_plan(plan, root):
    base = str(root.resolve())
    return {k: os.path.relpath(v, base) if k in ('source', 'destination', 'archive', 'ledger') else v
            for k, v in plan.items()}


def relative_report(report, root):
    base = root.resolve()
    for item in report:
        item['archive'] = Path(item['archive']).relative_to(base).as_posix()
    return report


def absolute_plan(plan, root):
    base = root.resolve()
    return {k: str(base / v) if k in ('source', 'destination', 'archive', 'ledger') else v
            for k, v in plan.items()}


def run(fixture, root):
    """Seal fixture, built in root; what happened, relative to root.
    An item holding Org or Markdown is poslib's to plan: its plan comes from
    the fixture, and only the application is ours. A fixture with a keeper is
    sealed to its recording, with the claims it gives."""
    tape = Tape(fixture['keeper']) if 'keeper' in fixture else None
    try:
        try:
            plan = seal.plan(root / fixture['source'], root / fixture['destination'],
                             fixture.get('ledger_id'))
        except ai.Refused as refused:
            if refused.kind != 'interpretation' or 'plan' not in fixture:
                raise
            plan = absolute_plan(fixture['plan'], root)
        if tape:
            event, _ = seal.apply(plan, ai.sha(ai.encoded(plan)), keeper=tape.client(),
                                  claims=fixture['claims'])
            if tape.left or (root / fixture['source']).exists():
                raise AssertionError('The recording was not played out, or the item was left')
        else:
            event, _ = seal.apply(plan, ai.sha(ai.encoded(plan)))
        scope = Path(plan['archive']).parent
        return dict(plan=relative_plan(plan, root),
                    event=dict(name=event.name, encoded=event.read_bytes().decode()),
                    # The recording is of the seal: the report after it asks no keeper.
                    report=relative_report(ai.report(scope, ask=False), root))
    except ai.Refused as refused:
        if tape and tape.left:
            raise AssertionError('Refused before the recording was played out')
        return dict(error=refused.kind)


class Scope:
    """A temporary scope holding archives/ and an item, trial/."""

    def __enter__(self):
        self.dir = Path(tempfile.mkdtemp(prefix='pyposlib-seal-'))
        scope = self.dir / 'scope'
        (scope / 'archives').mkdir(parents=True)
        write(scope / 'trial' / 'result.txt', b'result')
        return scope

    def __exit__(self, *_):
        writable(self.dir)
        shutil.rmtree(self.dir)


def trial_plan(scope):
    return seal.plan(scope / 'trial', scope / 'archives' / 'trial')


class Sealing(unittest.TestCase):
    def test_retirement_preserves_nested_archives(self):
        with Scope() as scope:
            archive = scope / 'trial/archives'
            (archive / 'old/_seal').mkdir(parents=True)
            write(archive / 'old/record.txt', b'recorded')
            before = cid.cid_directory(archive)
            plan = trial_plan(scope)
            seal.apply(plan, ai.sha(ai.encoded(plan)))
            self.assertEqual(before, cid.cid_directory(scope / 'archives/trial/archives'))
            self.assertTrue((scope / 'archives/trial/archives/old/_seal').is_dir())

    def test_repair_restores_recorded_directories_after_a_clone(self):
        with Scope() as scope:
            for name in ('archives/old/_seal', 'ordinary'):
                (scope / 'trial' / name).mkdir(parents=True)
            write(scope / 'trial/archives/old/record.txt', b'recorded')
            (scope / 'trial/result.txt').chmod(0o600)
            plan = trial_plan(scope)
            seal.apply(plan, ai.sha(ai.encoded(plan)))
            metadata = {p.relative_to(scope): p.read_bytes()
                        for p in (scope / 'archive-integrity').rglob('*') if p.is_file()}
            subprocess.run(['git', 'init', '-q', str(scope)], check=True)
            subprocess.run(['git', 'add', '.'], cwd=scope, check=True)
            subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.org',
                            '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Keep the archive'],
                           cwd=scope, check=True)
            clone = scope.parent / 'clone'
            subprocess.run(['git', 'clone', '-q', '--no-local', str(scope), str(clone)], check=True)
            before = ai.report(clone, ask=False)[0]
            self.assertNotEqual(before['root'], before['recorded_root'])
            self.assertEqual(ai.repair(clone)['restored'], 2)
            self.assertEqual((clone / 'archives/trial/result.txt').stat().st_mode & 0o777, 0o400)
            self.assertFalse(any(ai.findings(r) for r in ai.report(clone, ask=False)))
            self.assertEqual(metadata, {p.relative_to(clone): p.read_bytes()
                                       for p in (clone / 'archive-integrity').rglob('*') if p.is_file()})
            self.assertEqual(ai.repair(clone), dict(repaired=0, restored=0, unregistered=0))

    def test_repair_validates_all_directories_before_writing(self):
        for obstruction in ('file', 'symlink', 'changed', 'missing', 'executable'):
            with self.subTest(obstruction), Scope() as scope:
                for name in ('a', 'z/leaf'):
                    (scope / 'trial' / name).mkdir(parents=True)
                plan = trial_plan(scope)
                seal.apply(plan, ai.sha(ai.encoded(plan)))
                item = scope / 'archives/trial'
                (item / 'a').rmdir()
                (item / 'z/leaf').rmdir()
                (item / 'z').rmdir()
                if obstruction == 'file':
                    write(item / 'z', b'obstruction')
                elif obstruction == 'symlink':
                    (scope / 'outside').mkdir()
                    (item / 'z').symlink_to(scope / 'outside', target_is_directory=True)
                elif obstruction == 'changed':
                    (item / 'result.txt').chmod(0o644)
                    (item / 'result.txt').write_bytes(b'changed')
                elif obstruction == 'executable':
                    (item / 'result.txt').chmod(0o744)
                else:
                    (item / 'result.txt').unlink()
                with self.assertRaises(ai.Refused):
                    ai.repair(scope)
                self.assertFalse((item / 'a').exists())
                self.assertFalse((item / 'z/leaf').exists())

    def test_the_ledger_alone_gives_the_archive_s_cids(self):
        """After a seal, the ledger's entries give every CID the archive on
        disk has, root included, without reading the archive."""
        with Scope() as scope:
            plan = trial_plan(scope)
            _, root = seal.apply(plan, ai.sha(ai.encoded(plan)))
            archive = scope / 'archives'
            self.assertEqual(cid.cid_tree(archive), ai.fold_cids(archive))
            self.assertEqual(root, ai.fold_cids(archive)['.'])

    def test_every_shared_fixture_converts_the_same_bytes(self):
        """The conversion events, what was skipped and the report after, or
        the refusal, as fixtures/ledger/ of kind convert."""
        for name, fixture in fixtures('ledger'):
            if fixture['kind'] != 'convert':
                continue
            with self.subTest(name), Built(fixture) as root:
                try:
                    result = seal.convert(root / fixture['root'])
                except ai.Refused as refused:
                    self.assertEqual(fixture.get('error'), refused.kind)
                    continue
                self.assertNotIn('error', fixture)
                base = root.resolve()
                events = [dict(name=Path(c['event']).name, encoded=Path(c['event']).read_bytes().decode())
                          for c in result['converted']]
                skipped = [dict(archive=Path(s['archive']).relative_to(base).as_posix(), reason=s['reason'])
                           for s in result['skipped']]
                self.assertEqual(ai.encoded(fixture['converted']), ai.encoded(events))
                self.assertEqual(ai.encoded(fixture['skipped']), ai.encoded(skipped))
                self.assertEqual(ai.encoded(fixture['report']),
                                 ai.encoded(relative_report(ai.report(root / fixture['root']), root)))

    def test_every_shared_fixture_keeps_the_same_way(self):
        """What was moved to a keeper, what was left with its reason and the
        report after, or the refusal, as fixtures/ledger/ of kind keep: each
        request as its keeper recorded it, and a kept archive gone from disk."""
        for name, fixture in fixtures('ledger'):
            if fixture['kind'] != 'keep':
                continue
            with self.subTest(name), Built(fixture) as root:
                tape = Tape(fixture['keeper'])
                try:
                    got = seal.keep(root / fixture['root'], keeper_for=lambda url: tape.client(),
                                    claims=fixture['claims'])
                except ai.Refused as refused:
                    self.assertEqual(fixture.get('error'), refused.kind)
                    self.assertFalse(tape.left)
                    continue
                self.assertNotIn('error', fixture)
                self.assertFalse(tape.left)
                base = str(root.resolve())
                for item in got['kept']:
                    self.assertFalse(Path(item['archive']).exists())
                for item in got['kept'] + got['skipped']:
                    item['archive'] = os.path.relpath(item['archive'], base)
                self.assertEqual((fixture['kept'], fixture['skipped']), (got['kept'], got['skipped']))
                self.assertEqual(ai.encoded(fixture['report']),
                                 ai.encoded(relative_report(ai.report(root / fixture['root']), root)))

    def test_every_shared_fixture_recalls_the_same_way(self):
        """What was brought back from a keeper, what was left with its reason
        and the archive on disk after, or the refusal, as fixtures/ledger/ of
        kind recall: each request as its keeper recorded it."""
        for name, fixture in fixtures('ledger'):
            if fixture['kind'] != 'recall':
                continue
            with self.subTest(name), Built(fixture) as root:
                tape = Tape(fixture['keeper'])
                try:
                    got = seal.recall(root / fixture['root'], keeper_for=lambda url: tape.client())
                except ai.Refused as refused:
                    self.assertEqual(fixture.get('error'), refused.kind)
                    self.assertFalse(tape.left)
                    continue
                self.assertNotIn('error', fixture)
                self.assertFalse(tape.left)
                base = str(root.resolve())
                for item in got['recalled'] + got['skipped']:
                    item['archive'] = os.path.relpath(item['archive'], base)
                self.assertEqual((fixture['recalled'], fixture['skipped']), (got['recalled'], got['skipped']))
                after = []
                for here, dirs, files in os.walk(root / fixture['root'] / 'archives'):
                    for file in files:
                        path = Path(here) / file
                        after.append(dict(path=os.path.relpath(path, root), text=path.read_bytes().decode(),
                                          mode=path.stat().st_mode & 0o777))
                    if not dirs and not files:
                        after.append(dict(path=os.path.relpath(here, root), directory=True))
                self.assertEqual(fixture['after'], sorted(after, key=lambda entry: entry['path']))

    def test_every_shared_fixture_seals_the_same_bytes(self):
        for name, fixture in fixtures('ledger'):
            if fixture['kind'] != 'seal':
                continue
            with self.subTest(name), Built(fixture) as root:
                got = run(fixture, root)
                if 'error' in fixture:
                    # A refusal found in links is poslib's; pyposlib does not read them.
                    allowed = {fixture['error']} | (
                        {'interpretation'} if fixture['error'] in ('unsealed', 'unresolved', 'loop')
                        else set())
                    self.assertIn(got.get('error'), allowed)
                    continue
                for key in ('plan', 'event', 'report'):
                    self.assertEqual(ai.encoded(fixture[key]), ai.encoded(got[key]), key)

    def test_sealing_removes_write_bits(self):
        with Scope() as scope:
            plan = trial_plan(scope)
            event, _ = seal.apply(plan, ai.sha(ai.encoded(plan)))
            self.assertFalse((scope / 'archives/trial/result.txt').stat().st_mode & 0o222)
            self.assertEqual(event.stat().st_mode & 0o777, 0o444)

    def test_a_plan_is_applied_only_as_reviewed(self):
        with Scope() as scope:
            plan = trial_plan(scope)
            with self.assertRaises(ai.Refused):
                seal.apply(plan, '0' * 64)
            write(scope / 'trial' / 'result.txt', b'changed')
            with self.assertRaises(ai.Refused):
                seal.apply(plan, ai.sha(ai.encoded(plan)))
            self.assertTrue((scope / 'trial/result.txt').exists())
            self.assertFalse((scope / 'archives/trial').exists())

    def test_an_interrupted_seal_resumes(self):
        with Scope() as scope:
            plan = trial_plan(scope)
            expected = ai.sha(ai.encoded(plan))
            os.rename(scope / 'trial', scope / 'archives' / 'trial')
            first = seal.apply(plan, expected)
            self.assertEqual(first, seal.apply(plan, expected))
            self.assertEqual(ai.history(scope / 'archives')[2], 1)

    def test_a_new_record_is_staged_then_sealed(self):
        with Scope() as scope:
            plan = seal.stage(b'handover\n', scope / 'archives' / 'journal' / 'h.txt')
            staged = Path(plan['source'])
            self.assertEqual(staged.parent, (scope / '_seal').resolve())
            self.assertEqual(staged.suffix, '.txt')
            seal.apply(plan, ai.sha(ai.encoded(plan)))
            self.assertFalse(staged.exists())
            self.assertEqual((scope / 'archives/journal/h.txt').read_bytes(), b'handover\n')


    def test_a_new_record_may_start_an_archive(self):
        with Scope() as scope:
            (scope / 'archives').rmdir()
            plan = seal.stage(b'first\n', scope / 'archives' / 'first.txt')
            self.assertEqual(plan['number'], 1)
            seal.apply(plan, ai.sha(ai.encoded(plan)))
            self.assertEqual((scope / 'archives' / 'first.txt').read_bytes(), b'first\n')
            self.assertTrue((scope / 'archive-integrity' / 'ledger').is_dir())

    def test_a_refused_new_record_leaves_nothing_staged(self):
        with Scope() as scope:
            write(scope / 'archives' / 'taken.txt', b'taken')
            with self.assertRaises(ai.Refused):
                seal.stage(b'new\n', scope / 'archives' / 'taken.txt')
            self.assertFalse((scope / '_seal').exists())

    def test_a_program_applies_its_own_plan_explicitly(self):
        import subprocess, sys
        with Scope() as scope:
            target = scope / 'archives' / 'journal' / 'h.txt'
            tool = Path(__file__).resolve().parent.parent / 'archive_integrity.py'
            command = [sys.executable, '-B', str(tool), 'write-new', str(target)]
            self.assertEqual(0, subprocess.run(command, input=b'handover\n', capture_output=True).returncode)
            self.assertFalse(target.exists())
            self.assertEqual(0, subprocess.run(command + ['--apply'], input=b'handover\n',
                                               capture_output=True).returncode)
            self.assertEqual(target.read_bytes(), b'handover\n')

    def test_a_staging_directory_left_empty_is_not_sealed(self):
        """An empty _seal in an item, at any depth, is removed and no event
        records it; one that holds something is sealed as it is, and another
        empty directory is recorded. The check after the seal is clean."""
        with Scope() as scope:
            for name in ('_seal', 'child/_seal', 'kept/_seal', 'hollow'):
                (scope / 'trial' / name).mkdir(parents=True)
            write(scope / 'trial' / 'kept' / '_seal' / 'plan.json', b'{}')
            plan = trial_plan(scope)
            event, _ = seal.apply(plan, ai.sha(ai.encoded(plan)))
            archive = scope / 'archives'
            self.assertEqual(json.loads(event.read_bytes())['empty'], ['trial/child', 'trial/hollow'])
            self.assertFalse((archive / 'trial' / '_seal').exists())
            self.assertFalse((archive / 'trial' / 'child' / '_seal').exists())
            self.assertTrue((archive / 'trial' / 'kept' / '_seal' / 'plan.json').exists())
            self.assertFalse(any(ai.findings(r) for r in ai.report(scope)))

    def test_a_new_record_leaves_no_staging_directory(self):
        """A record staged by write-new is sealed and _seal, left empty, is
        gone; a _seal that holds something else stays."""
        with Scope() as scope:
            def sealed(name):
                plan = seal.stage(b'record\n', scope / 'archives' / name)
                seal.apply(plan, ai.sha(ai.encoded(plan)))
            sealed('first.txt')
            self.assertFalse((scope / '_seal').exists())
            write(scope / '_seal' / 'other.json', b'{}')
            sealed('second.txt')
            self.assertEqual(os.listdir(scope / '_seal'), ['other.json'])

    def test_a_sealed_path_has_a_link(self):
        """A sealed item's link is ipfs:// and its CID; a path within it adds
        the path. A path never sealed, and a path in no archive, are refused."""
        with Scope() as scope:
            plan = trial_plan(scope)
            seal.apply(plan, ai.sha(ai.encoded(plan)))
            archive = scope / 'archives'
            found = ai.fold_cids(archive)['trial']
            self.assertEqual(seal.link(archive / 'trial'), f'ipfs://{found}')
            self.assertEqual(seal.link(f'{archive}/trial/'), f'ipfs://{found}')
            self.assertEqual(seal.link(archive / 'trial' / 'result.txt'), f'ipfs://{found}/result.txt')
            for path in (archive / 'other', scope / 'trial'):
                with self.assertRaises(ai.Refused) as refused:
                    seal.link(path)
                self.assertEqual(refused.exception.kind, 'unsealed')

    def test_a_program_prints_a_sealed_path_s_link(self):
        """link PATH prints the link on one line; a path never sealed exits 2."""
        import subprocess, sys
        with Scope() as scope:
            plan = trial_plan(scope)
            seal.apply(plan, ai.sha(ai.encoded(plan)))
            target = scope / 'archives' / 'trial' / 'result.txt'
            tool = Path(__file__).resolve().parent.parent / 'archive_integrity.py'
            done = subprocess.run([sys.executable, '-B', str(tool), 'link', str(target)], capture_output=True)
            self.assertEqual((done.returncode, done.stdout.decode()), (0, seal.link(target) + '\n'))
            done = subprocess.run([sys.executable, '-B', str(tool), 'link', str(scope / 'archives' / 'other')],
                                  capture_output=True)
            self.assertEqual((done.returncode, done.stdout), (2, b''))

    def test_a_link_s_bytes_are_read_from_disk(self):
        """The bytes of the file a link names, by its item's CID and its path
        or by its own CID, from a directory beneath the scope, an Org search
        after :: left aside. A directory, a CID no archive has and text that
        is no link are refused as absent."""
        with Scope() as scope:
            plan = trial_plan(scope)
            seal.apply(plan, ai.sha(ai.encoded(plan)))
            cids = ai.fold_cids(scope / 'archives')
            item, file = cids['trial'], cids['trial/result.txt']
            (scope / 'canon').mkdir()
            for uri in (f'ipfs://{item}/result.txt', f'ipfs://{item}/result.txt::*A heading',
                        f'ipfs://{file}', f'ipfs://{file}::a search'):
                self.assertEqual(seal.fetch(uri, scope / 'canon'), b'result')
            for uri in (f'ipfs://{item}', 'ipfs://bafkreiaaaa', f'ipfs://{item}/other.txt', 'result.txt'):
                with self.assertRaises(ai.Refused) as refused:
                    seal.fetch(uri, scope / 'canon')
                self.assertEqual(refused.exception.kind, 'absent')

    def test_a_program_prints_a_link_s_bytes(self):
        """fetch LINK prints the file's bytes as they are, whatever they are; a
        link to no archived file exits 2 and prints nothing."""
        import subprocess, sys
        with Scope() as scope:
            data = bytes(range(256)) + b'\r\n\xc3\xa9'
            write(scope / 'trial' / 'bytes.bin', data)
            plan = trial_plan(scope)
            seal.apply(plan, ai.sha(ai.encoded(plan)))
            item = ai.fold_cids(scope / 'archives')['trial']
            tool = Path(__file__).resolve().parent.parent / 'archive_integrity.py'
            done = subprocess.run([sys.executable, '-B', str(tool), 'fetch', f'ipfs://{item}/bytes.bin'],
                                  capture_output=True, cwd=scope)
            self.assertEqual((done.returncode, done.stdout), (0, data))
            done = subprocess.run([sys.executable, '-B', str(tool), 'fetch', f'ipfs://{item}/other.bin'],
                                  capture_output=True, cwd=scope)
            self.assertEqual((done.returncode, done.stdout), (2, b''))


LEDGER = '0f1e2d3c-4b5a-4968-8778-a6b5c4d3e2f1'
KEEPER = 'https://keeper.example/ledgers/' + LEDGER


class KeptScope:
    """A temporary repository whose scope projects/a a keeper keeps, holding
    an item, trial/, and a keeper in memory to send it to."""

    def __enter__(self):
        self.dir = Path(tempfile.mkdtemp(prefix='pyposlib-kept-')).resolve()
        (self.dir / '.git').mkdir()
        write(self.dir / '.pos/config.yaml',
              f'pos: 2\nprojects: projects/\narchives:\n  - scope: projects/a\n    kept: remote\n    url: {KEEPER}\n'.encode())
        self.scope = self.dir / 'projects/a'
        write(self.scope / 'trial/result.txt', b'result')
        self.keeper = remote.Keeper()
        return self

    def __exit__(self, *_):
        writable(self.dir)
        shutil.rmtree(self.dir)

    def client(self, keeper=None):
        keeper = keeper or self.keeper

        def send(method, url, headers, body):
            status, _, answer = remote.handle(keeper, method, url[len(KEEPER):], headers, body)
            return status, answer
        return remote.HttpRemoteArchive(KEEPER, None, send)

    def seal(self, item, keeper=None):
        plan = seal.plan(self.scope / item, self.scope / 'archives' / item, LEDGER)
        return seal.apply(plan, ai.sha(ai.encoded(plan)), keeper=self.client(keeper), claims={})


class SealingToAKeeper(unittest.TestCase):
    def test_a_link_s_bytes_are_read_from_its_keeper(self):
        """The bytes of a file a keeper keeps are read from the keeper by the
        CID the ledger enrols the file under. Bytes that are not that CID's
        are refused as entry."""
        with KeptScope() as kept:
            kept.seal('trial')
            cids = ai.fold_cids(kept.scope / 'archives')
            for uri in (f'ipfs://{cids["trial"]}/result.txt', f'ipfs://{cids["trial/result.txt"]}'):
                self.assertEqual(seal.fetch(uri, kept.scope, keeper_for=lambda url: kept.client()), b'result')
            with self.assertRaises(ai.Refused) as refused:
                seal.fetch(f'ipfs://{cids["trial"]}', kept.scope, keeper_for=lambda url: kept.client())
            self.assertEqual(refused.exception.kind, 'absent')

            class Other:
                def read(self, cid_text, path=''):
                    return b'another'
            with self.assertRaises(ai.Refused) as refused:
                seal.fetch(f'ipfs://{cids["trial/result.txt"]}', kept.scope, keeper_for=lambda url: Other())
            self.assertEqual(refused.exception.kind, 'entry')

    def test_what_is_sealed_is_read_back_from_its_keeper(self):
        """The keeper holds the bytes under the CIDs the ledger enrols, and
        nothing of the item is left on disk."""
        with KeptScope() as kept:
            event, root = kept.seal('trial')
            cids = ai.fold_cids(kept.scope / 'archives')
            self.assertEqual(root, cids['.'])
            self.assertEqual(b'result', kept.keeper.read(cids['trial'], 'result.txt'))
            self.assertEqual(event.read_bytes(), kept.keeper.event(1))
            self.assertFalse((kept.scope / 'trial').exists())
            self.assertFalse((kept.scope / 'archives').exists())

    def test_a_keeper_ahead_with_another_ledger_leaves_this_one_as_it_was(self):
        """Events fetched to catch up that do not continue the ledger are
        removed again, and the item stays."""
        with KeptScope() as kept, KeptScope() as other:
            kept.seal('trial')
            write(other.scope / 'trial/result.txt', b'another result')
            write(other.scope / 'more/m.txt', b'more')
            other.seal('trial')
            other.seal('more')
            write(kept.scope / 'next/n.txt', b'next')
            before = sorted(p.name for p in (kept.scope / 'archive-integrity/ledger').iterdir())
            with self.assertRaises(ai.Refused) as refused:
                kept.seal('next', keeper=other.keeper)
            self.assertEqual('chain', refused.exception.kind)
            self.assertEqual(before, sorted(p.name for p in (kept.scope / 'archive-integrity/ledger').iterdir()))
            self.assertTrue((kept.scope / 'next/n.txt').exists())

    def test_another_client_s_seal_is_fetched_and_the_plan_made_before_it_refused(self):
        """Two clones seal to one keeper. The second finds the keeper an event
        ahead: its ledger is brought up to date, and its plan, reviewed
        against the ledger as it was, is refused for a new one."""
        with KeptScope() as kept, KeptScope() as clone:
            write(clone.scope / 'more/m.txt', b'more')
            plan = seal.plan(clone.scope / 'more', clone.scope / 'archives/more', LEDGER)
            event, _ = kept.seal('trial')
            with self.assertRaises(ai.Refused) as refused:
                seal.apply(plan, ai.sha(ai.encoded(plan)), keeper=clone.client(kept.keeper), claims={})
            self.assertEqual('plan', refused.exception.kind)
            self.assertEqual([event.name], [p.name for p in ai.history(clone.scope / 'archives')[3]])
            self.assertTrue((clone.scope / 'more/m.txt').exists())
            clone.seal('more', keeper=kept.keeper)
            self.assertEqual(2, kept.keeper.describe()['events'])

    def test_an_item_changed_after_its_keeper_took_it_is_not_removed(self):
        """Resumed after the keeper has the event, a seal removes the item
        only if it is still what was sealed."""
        with KeptScope() as kept:
            plan = seal.plan(kept.scope / 'trial', kept.scope / 'archives/trial', LEDGER)
            digest = ai.sha(ai.encoded(plan))
            file, _, data = seal.event_of(plan, 'trial', plan['add'], plan['collections'], [])
            kept.keeper.append(file, data, {plan['add']['trial/result.txt']['cid']: b'result'}, {})
            write(kept.scope / 'trial/result.txt', b'changed')
            with self.assertRaises(ai.Refused) as refused:
                seal.apply(plan, digest, keeper=kept.client(), claims={})
            self.assertEqual('plan', refused.exception.kind)
            self.assertTrue((kept.scope / 'trial/result.txt').exists())

    def test_a_plan_is_applied_only_where_it_was_planned_for(self):
        """A plan says whether its archive is with a keeper, and which: one
        made before the scope's configuration changed is refused."""
        with KeptScope() as kept:
            plan = seal.plan(kept.scope / 'trial', kept.scope / 'archives/trial', LEDGER)
            self.assertEqual(KEEPER, plan['kept'])
            (kept.dir / '.pos/config.yaml').write_text('pos: 2\nprojects: projects/\n')
            with self.assertRaises(ai.Refused) as refused:
                seal.apply(plan, ai.sha(ai.encoded(plan)), keeper=kept.client(), claims={})
            self.assertEqual('plan', refused.exception.kind)
            self.assertTrue((kept.scope / 'trial/result.txt').exists())

    def test_an_archive_moved_to_its_keeper_is_read_back_whole(self):
        """Sealed on disk, then given to a keeper: every file the ledger
        enrols is read from the keeper as it was on disk, the keeper's root
        is the ledger's, and the check that follows is of a kept archive."""
        with KeptScope() as kept:
            (kept.dir / '.pos/config.yaml').write_text('pos: 2\nprojects: projects/\n')
            write(kept.scope / 'more/deep/m.txt', b'more')
            for item in ('trial', 'more'):
                plan = seal.plan(kept.scope / item, kept.scope / 'archives' / item, LEDGER)
                seal.apply(plan, ai.sha(ai.encoded(plan)))
            archive = kept.scope / 'archives'
            before = {path: (archive / path).read_bytes() for path in ai.inventory(archive)}
            write(kept.dir / '.pos/config.yaml',
                  f'pos: 2\nprojects: projects/\narchives:\n  - scope: projects/a\n    kept: remote\n    url: {KEEPER}\n'.encode())
            got = seal.keep(kept.dir, keeper_for=lambda url: kept.client(), claims={})
            self.assertEqual([(2, 2)], [(item['events'], item['files']) for item in got['kept']])
            self.assertFalse(archive.exists())
            cids = ai.fold_cids(archive)
            self.assertEqual(before, {path: kept.keeper.read(cids[path]) for path in before})
            (report,) = ai.report(kept.dir, ask=True, keeper_for=lambda url: kept.client())
            self.assertEqual(report['root'], kept.keeper.describe()['root'])
            self.assertFalse(ai.findings(report))
            self.assertEqual([dict(archive=str(archive), reason='kept')],
                             seal.keep(kept.dir, keeper_for=lambda url: kept.client(), claims={})['skipped'])

    def test_the_tool_commit_is_the_images_else_gits_else_unknown(self):
        """An image writes COMMIT beside the package; a checkout is asked of
        git; a plain copy of the files knows no commit."""
        with tempfile.TemporaryDirectory() as tool:
            tool = Path(tool)
            git = lambda *args: subprocess.run(
                ['git', '-C', str(tool), '-c', 'user.name=A', '-c', 'user.email=a@example.org', *args],
                check=True, capture_output=True, text=True).stdout.strip()
            self.assertIsNone(seal.tool_commit(tool))
            git('init', '-q')
            self.assertIsNone(seal.tool_commit(tool))
            (tool / 'README').write_text('pos\n')
            git('add', 'README')
            git('commit', '-q', '-m', 'Begin')
            self.assertEqual(git('rev-parse', 'HEAD'), seal.tool_commit(tool))
            (tool / 'COMMIT').write_text('eac849ed9d3162cf11017715f771458b1d4e60b5\n')
            self.assertEqual('eac849ed9d3162cf11017715f771458b1d4e60b5', seal.tool_commit(tool))
            (tool / 'COMMIT').write_text('not a commit\n')
            self.assertIsNone(seal.tool_commit(tool))

    def test_the_claims_say_where_a_seal_came_from(self):
        """The plan, the tool and its commit, and of a repository git can
        read: the scope, the commit and branch, whether the tree is dirty,
        and each remote without the user and password its URL may hold."""
        with KeptScope() as kept, tempfile.TemporaryDirectory() as tool, \
                unittest.mock.patch.object(seal, 'TOOL_DIRECTORY', Path(tool)):
            (Path(tool) / 'COMMIT').write_text('eac849ed9d3162cf11017715f771458b1d4e60b5\n')
            shutil.rmtree(kept.dir / '.git')
            git = lambda *args: subprocess.run(
                ['git', '-C', str(kept.dir), '-c', 'user.name=A', '-c', 'user.email=a@example.org', *args],
                check=True, capture_output=True, text=True).stdout.strip()
            git('init', '-q', '-b', 'trunk')
            git('remote', 'add', 'origin', 'https://someone:secret@forge.example/some/one.git')
            git('remote', 'add', 'mirror', 'git@forge.example:some/one.git')
            git('add', '.pos')
            git('commit', '-q', '-m', 'Configure')
            plan = seal.plan(kept.scope / 'trial', kept.scope / 'archives/trial', LEDGER)
            self.assertEqual(
                {'plan': 'the hash', 'tool': 'pyposlib',
                 'tool_commit': 'eac849ed9d3162cf11017715f771458b1d4e60b5', 'scope': 'projects/a',
                 'commit': git('rev-parse', 'HEAD'), 'branch': 'trunk', 'dirty': 'true',
                 'remote.origin': 'https://forge.example/some/one.git',
                 'remote.mirror': 'git@forge.example:some/one.git'},
                seal.claims_of(plan, 'the hash'))

    def test_claims_outside_a_repository_git_reads_say_what_is_known(self):
        with KeptScope() as kept, tempfile.TemporaryDirectory() as tool, \
                unittest.mock.patch.object(seal, 'TOOL_DIRECTORY', Path(tool)):
            plan = seal.plan(kept.scope / 'trial', kept.scope / 'archives/trial', LEDGER)
            self.assertEqual({'plan': 'the hash', 'tool': 'pyposlib', 'scope': 'projects/a'},
                             seal.claims_of(plan, 'the hash'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
