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
import archive_integrity as ai
import seal


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


def run(fixture, root):
    """Seal fixture, built in root; what happened, relative to root."""
    try:
        plan = seal.plan(root / fixture['source'], root / fixture['destination'], fixture['ledger_id'])
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
        write(scope / 'trial' / 'result.md', b'result')
        return scope

    def __exit__(self, *_):
        writable(self.dir)
        shutil.rmtree(self.dir)


def trial_plan(scope):
    return seal.plan(scope / 'trial', scope / 'archives' / 'trial')


class Sealing(unittest.TestCase):
    def test_every_shared_fixture_seals_the_same_bytes(self):
        for name, fixture in fixtures('ledger'):
            if fixture['kind'] != 'seal':
                continue
            with self.subTest(name), Built(fixture) as root:
                got = run(fixture, root)
                if 'error' in fixture:
                    self.assertEqual(fixture['error'], got.get('error'))
                    continue
                for key in ('plan', 'event', 'report'):
                    self.assertEqual(ai.encoded(fixture[key]), ai.encoded(got[key]), key)

    def test_sealing_removes_write_bits(self):
        with Scope() as scope:
            plan = trial_plan(scope)
            event, _ = seal.apply(plan, ai.sha(ai.encoded(plan)))
            self.assertFalse((scope / 'archives/trial/result.md').stat().st_mode & 0o222)
            self.assertEqual(event.stat().st_mode & 0o777, 0o444)

    def test_a_plan_is_applied_only_as_reviewed(self):
        with Scope() as scope:
            plan = trial_plan(scope)
            with self.assertRaises(ai.Refused):
                seal.apply(plan, '0' * 64)
            write(scope / 'trial' / 'result.md', b'changed')
            with self.assertRaises(ai.Refused):
                seal.apply(plan, ai.sha(ai.encoded(plan)))
            self.assertTrue((scope / 'trial/result.md').exists())
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
            plan = seal.stage(b'handover\n', scope / 'archives' / 'journal' / 'h.md')
            staged = Path(plan['source'])
            self.assertEqual(staged.parent, (scope / '_seal').resolve())
            seal.apply(plan, ai.sha(ai.encoded(plan)))
            self.assertFalse(staged.exists())
            self.assertEqual((scope / 'archives/journal/h.md').read_bytes(), b'handover\n')


    def test_a_program_applies_its_own_plan_explicitly(self):
        import subprocess, sys
        with Scope() as scope:
            target = scope / 'archives' / 'journal' / 'h.md'
            command = [sys.executable, '-B', str(Path(seal.__file__)), 'write-new', str(target)]
            self.assertEqual(0, subprocess.run(command, input=b'handover\n', capture_output=True).returncode)
            self.assertFalse(target.exists())
            self.assertEqual(0, subprocess.run(command + ['--apply'], input=b'handover\n',
                                               capture_output=True).returncode)
            self.assertEqual(target.read_bytes(), b'handover\n')


if __name__ == '__main__':
    unittest.main(verbosity=2)
