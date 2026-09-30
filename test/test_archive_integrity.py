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
"""Integrity invariants and real worker interruption in disposable directories."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from pyposlib.archive_integrity import (META, apply_plan, encoded, history, inventory,
                               preview, record, repair, report, seal_archive, sha)

HOME = Path(__file__).resolve().parent.parent
RUN = Path(tempfile.mkdtemp(prefix='pyposlib-'))


class IntegrityChecks(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(dir=RUN))
        for project in ('A', 'B'):
            archive = self.root / 'projects' / project / 'archives'
            archive.mkdir(parents=True)
            (archive / 'evidence.md').write_text('Original observation ' + project)
            script = archive / 'reproduce.sh'
            script.write_text('#!/bin/sh\nexit 0\n')
            script.chmod(0o755)

    def enrol(self):
        plan = preview(self.root)
        return plan, apply_plan(plan, sha(encoded(plan)))

    def test_two_archives_baseline_protect_idempotence_and_append_only(self):
        before = {str(p): p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        plan, result = self.enrol()
        self.assertEqual(result['enrolled'], 4)
        self.assertEqual(apply_plan(plan, sha(encoded(plan))), result)
        for name, data in before.items():
            self.assertEqual(Path(name).read_bytes(), data)
            self.assertFalse(Path(name).stat().st_mode & 0o222)
        self.assertEqual((self.root / 'projects/A/archives/reproduce.sh').stat().st_mode & 0o777, 0o555)
        archive = self.root / 'projects/A/archives'
        original = {p.name: p.read_bytes() for p in (archive / META).iterdir()}
        extra = archive / 'correction.md'
        extra.write_text('Later correction; original retained')
        self.assertEqual(repair(self.root)['unregistered'], 1)
        self.assertTrue(extra.stat().st_mode & 0o222)
        seal_archive(extra)
        for name, data in original.items():
            self.assertEqual((archive / META / name).read_bytes(), data)
        self.assertEqual(len(history(archive)[0]), 3)
        self.assertTrue(all(not r['new'] and not r['writable'] for r in report(self.root)))

    def test_tamper_delete_replace_and_refuse_rebaseline(self):
        self.enrol()
        original = self.root / 'projects/A/archives/evidence.md'
        ledger = list((original.parent / META).iterdir())[0].read_bytes()
        original.chmod(0o644)
        original.write_text('Tampered')
        self.assertEqual(report(self.root)[0]['changed'], ['evidence.md'])
        for operation in (lambda: preview(self.root), lambda: repair(self.root), lambda: seal_archive(original)):
            with self.assertRaises(ValueError):
                operation()
        self.assertEqual(list((original.parent / META).iterdir())[0].read_bytes(), ledger)
        original.unlink()
        self.assertEqual(report(self.root)[0]['missing'], ['evidence.md'])
        original.write_text('Replacement at the same path')
        self.assertEqual(report(self.root)[0]['changed'], ['evidence.md'])

    def test_permissions_repaired_but_content_and_executable_bits_preserved(self):
        self.enrol()
        path = self.root / 'projects/B/archives/reproduce.sh'
        before = path.read_bytes()
        path.chmod(0o755)
        anchor = next((self.root / '.archive-integrity-anchors').glob('*.json'))
        anchor.chmod(0o644)
        self.assertTrue(report(self.root)[0]['checkpoint_writable'])
        self.assertEqual(repair(self.root)['repaired'], 2)
        self.assertFalse(anchor.stat().st_mode & 0o222)
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(path.stat().st_mode & 0o777, 0o555)

    def test_stale_plan_validates_all_archives_before_mutation(self):
        plan = preview(self.root)
        (self.root / 'projects/B/archives/evidence.md').write_text('Intervening change')
        with self.assertRaises(ValueError):
            apply_plan(plan, sha(encoded(plan)))
        self.assertFalse(list(self.root.rglob(META)))

    def test_scope_move_preserves_old_ledger_and_capsule_membership(self):
        self.enrol()
        source = self.root / 'projects/A'
        old_ledger = list((source / 'archives' / META).iterdir())[0].read_bytes()
        # Canon evolves while the archived account stays fixed.
        (source / 'concept.org').write_text('Revised understanding')
        (self.root / 'archives').mkdir()
        destination = self.root / 'archives/A'
        source.rename(destination)
        seal_archive(destination)
        self.assertEqual(list((destination / 'archives' / META).iterdir())[0].read_bytes(), old_ledger)
        self.assertFalse((destination / 'concept.org').stat().st_mode & 0o222)
        self.assertTrue(all(not r['new'] and not r['changed'] and not r['missing'] for r in report(self.root)))
        # Moving the whole receiver does not change its relative ledger entries.
        moved = self.root.with_name(self.root.name + '-moved')
        self.root.rename(moved)
        self.assertTrue(all(not r['new'] and not r['missing'] for r in report(moved)))

    def test_initial_deployed_ledger_prefix_is_preserved_during_adoption(self):
        archive = self.root / 'projects/A/archives'
        legacy = encoded(dict(schema=1, previous=None,
                              add=inventory(archive)))
        for file in archive.iterdir():
            file.chmod(file.stat().st_mode & ~0o222)
        folder = archive / META
        folder.mkdir()
        path = folder / ('00000001-' + sha(legacy) + '.json')
        path.write_bytes(legacy)
        path.chmod(0o444)
        plan, _ = self.enrol()
        self.assertEqual(path.read_bytes(), legacy)
        self.assertEqual(len(list(folder.iterdir())), 2)
        self.assertIn('ledger_id', json.loads(sorted(folder.iterdir())[-1].read_bytes()))
        self.assertTrue(all(not r['new'] for r in report(self.root)))
        apply_plan(plan, sha(encoded(plan)))

    def test_whole_archive_loss_and_truncated_ledger_are_detected(self):
        # Identical bytes in two archives must not conceal losing one archive.
        (self.root / 'projects/B/archives/evidence.md').write_bytes(
            (self.root / 'projects/A/archives/evidence.md').read_bytes())
        self.enrol()
        archive = self.root / 'projects/A/archives'
        moved = self.root / 'removed-archive'
        archive.rename(moved)
        with self.assertRaisesRegex(ValueError, 'Missing anchored ledger'):
            report(self.root)
        moved.rename(archive)
        extra = archive / 'addition.md'
        extra.write_text('New evidence')
        seal_archive(extra)
        event = sorted((archive / META).iterdir())[-1]
        event.unlink()
        with self.assertRaisesRegex(ValueError, 'Missing anchored ledger'):
            report(archive)

    def test_links_special_files_and_ledger_rewrite_rejected(self):
        archive = self.root / 'projects/A/archives'
        link = archive / 'link'
        link.symlink_to(self.root / 'projects/B/archives/evidence.md')
        with self.assertRaises(ValueError):
            preview(self.root)
        link.unlink()
        os.link(archive / 'evidence.md', link)
        with self.assertRaises(ValueError):
            preview(self.root)
        link.unlink()
        self.enrol()
        event = list((archive / META).iterdir())[0]
        event.chmod(0o644)
        event.write_bytes(event.read_bytes().replace(b'Original', b'Rewritten') + b' ')
        with self.assertRaises(ValueError):
            report(self.root)

    def test_real_worker_exit_then_same_plan_recovery(self):
        plan = preview(self.root)
        request = self.root / 'plan.json'
        request.write_bytes(encoded(plan))
        program = ("import json,os,sys; from pyposlib.archive_integrity import apply_plan; "
                   "apply_plan(json.load(open(sys.argv[1])), sys.argv[2], "
                   "lambda phase: os._exit(75) if phase == 'after-ledger' else None)")
        result = subprocess.run([sys.executable, '-B', '-c', program, str(request), sha(encoded(plan))],
                                cwd=HOME, capture_output=True)
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertTrue(any(r['writable'] for r in report(self.root)))
        apply_plan(plan, sha(encoded(plan)))
        self.assertTrue(all(not r['new'] and not r['writable'] for r in report(self.root)))

    def test_cli_is_poslib_s(self):
        """The command line is poslib's: a new record sealed at once, never
        replaced; check, checkpoint and repair; help; the old commands gone."""
        tool = [sys.executable, '-B', str(HOME / 'archive_integrity.py')]
        scope = self.root / 'fresh'
        (scope / 'archive-integrity').mkdir(parents=True)
        new = scope / 'archives' / 'new.txt'
        write_new = [*tool, 'write-new', str(new), '--apply']
        result = subprocess.run(write_new, input=b'New record', capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(write_new, input=b'Replacement', capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(new.read_bytes(), b'New record')
        run = lambda *args: subprocess.run([*tool, *args], capture_output=True)
        self.assertEqual(run('check', str(scope)).returncode, 0)
        new.chmod(0o644)
        self.assertEqual(run('check', str(scope)).returncode, 1)
        self.assertEqual(json.loads(run('repair', str(scope)).stdout), dict(repaired=1, unregistered=0))
        checkpointed = json.loads(run('checkpoint', str(scope)).stdout)['checkpointed']
        self.assertEqual(Path(checkpointed), (scope / 'archive-integrity/checkpoints').resolve())
        self.assertIn(b'checkpoint ROOT', run('help').stdout)
        for old in (['preview', str(scope)], ['verify-existing', str(scope)], ['seal', str(new)]):
            self.assertEqual(run(*old).returncode, 2, old)

    def test_new_publication_ignores_active_scratch(self):
        archive = self.root / 'projects/A/archives'
        scratch = self.root / '_fixtures/archives'
        scratch.mkdir(parents=True)
        (scratch / 'untracked').write_text('Disposable')
        self.assertEqual(len(report(self.root)), 2)
        # Nested archived payload named archives gains no metadata of its own.
        nested = archive / 'capsule/evidence/archives'
        nested.mkdir(parents=True)
        (nested / 'original.txt').write_text('Original')
        seal_archive(archive / 'capsule')
        self.assertFalse((nested / META).exists())


if __name__ == '__main__':
    print(f'INTEGRITY_RUN={RUN}', flush=True)
    unittest.main(verbosity=2)
