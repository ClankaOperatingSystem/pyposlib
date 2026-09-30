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
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from fixtures import fixtures, write, writable
from test_formats import Built
from pyposlib import archive_integrity as ai
from pyposlib import cid
from pyposlib import seal


def relative_plan(plan, root):
    base = str(root.resolve())
    return {k: os.path.relpath(v, base) if k in ('source', 'destination', 'archive', 'ledger') else v
            for k, v in plan.items()}


def relative_report(report, root):
    base = root.resolve()
    for item in report:
        item['archive'] = Path(item['archive']).relative_to(base).as_posix()
        item['checkpoint_writable'] = [Path(p).relative_to(base).as_posix()
                                       for p in item['checkpoint_writable']]
    return report


def absolute_plan(plan, root):
    base = root.resolve()
    return {k: str(base / v) if k in ('source', 'destination', 'archive', 'ledger') else v
            for k, v in plan.items()}


def run(fixture, root):
    """Seal fixture, built in root; what happened, relative to root.
    An item holding Org or Markdown is poslib's to plan: its plan comes from
    the fixture, and only the application is ours."""
    try:
        try:
            plan = seal.plan(root / fixture['source'], root / fixture['destination'],
                             fixture['ledger_id'])
        except ai.Refused as refused:
            if refused.kind != 'interpretation' or 'plan' not in fixture:
                raise
            plan = absolute_plan(fixture['plan'], root)
        event, _ = seal.apply(plan, ai.sha(ai.encoded(plan)))
        scope = Path(plan['archive']).parent
        return dict(plan=relative_plan(plan, root),
                    event=dict(name=event.name, encoded=event.read_bytes().decode()),
                    report=relative_report(ai.report(scope), root))
    except ai.Refused as refused:
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
    def test_the_ledger_alone_gives_the_archive_s_cids(self):
        """After a seal, the ledger's entries give every CID the archive on
        disk has, root included, without reading the archive."""
        with Scope() as scope:
            plan = trial_plan(scope)
            _, root = seal.apply(plan, ai.sha(ai.encoded(plan)))
            archive = scope / 'archives'
            self.assertEqual(cid.cid_tree(archive), ai.fold_cids(archive))
            self.assertEqual(root, ai.fold_cids(archive)['.'])

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
