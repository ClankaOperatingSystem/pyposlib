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
"""pyposlib against poslib on random trees: both must give the same bytes.

Needs Emacs and a poslib checkout (POSLIB); skipped without Emacs.
"""
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest

from fixtures import POSLIB, HERE, writable, write
import archive_integrity as ai
import cid

EMACS = os.environ.get('EMACS', 'emacs')
SEED = int(os.environ.get('DIFFERENTIAL_SEED', '73'))
# No two differ only in case or Unicode normalisation, which some file
# systems, macOS's among them, treat as one name.
NAMES = ['a', 'B', 'z', '_u', '-d', 'a-b', 'a_b', 'Zed', 'zebra', '\u00e9t\u00e9', '\u00c4pfel',
         '\u65e5\u672c', '\U0001f600', 'x' * 60, 'sp ace', 'q"uote', '.hidden']


def poslib(tasks):
    """poslib's answers to tasks, by running Emacs once."""
    with tempfile.TemporaryDirectory() as work:
        request, answer = Path(work) / 'tasks.json', Path(work) / 'answers.json'
        request.write_text(json.dumps(tasks), encoding='utf-8')
        result = subprocess.run([EMACS, '-Q', '--batch', '-L', str(POSLIB / 'lisp'),
                                 '-l', str(HERE / 'differential.el'), str(request), str(answer)],
                                capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(f'poslib failed:\n{result.stderr}')
        return json.loads(answer.read_bytes())


def tree(rng, root, depth=0):
    """Fill root with random files and directories."""
    for name in rng.sample(NAMES, rng.randint(0, 6)):
        path = root / name
        if depth < 3 and rng.random() < 0.3:
            path.mkdir()
            tree(rng, path, depth + 1)
        else:
            size = rng.choice([0, 1, 7, 255, 256, 257, 1024, 3000])
            write(path, bytes(rng.randrange(256) for _ in range(size)),
                  rng.choice([0o644, 0o600, 0o755, 0o444]))


def relative(report, root):
    base = root.resolve()
    for item in report:
        item['archive'] = Path(item['archive']).relative_to(base).as_posix()
        item['checkpoint_writable'] = [Path(p).relative_to(base).as_posix()
                                       for p in item['checkpoint_writable']]
    return report


def enrol(root):
    plan = ai.preview(root)
    ai.apply_plan(plan, ai.sha(ai.encoded(plan)))


def mutate(rng, root):
    """Change, remove, add or unprotect some archived files."""
    files = [p for p in root.rglob('*') if p.is_file() and ai.META not in p.parts
             and ai.ANCHORS not in p.parts]
    for path in rng.sample(files, min(len(files), rng.randint(0, 3))):
        action = rng.choice(['change', 'remove', 'unprotect'])
        path.chmod(path.stat().st_mode | 0o200)
        if action == 'change':
            path.write_bytes(path.read_bytes() + b'!')
        elif action == 'remove':
            path.unlink()
    for archive in ai.roots(root):
        if rng.random() < 0.3:
            write(archive / 'added.md', b'new')


@unittest.skipUnless(shutil.which(EMACS), 'needs Emacs')
class Differential(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='pyposlib-differential-'))

    def tearDown(self):
        writable(self.work)
        shutil.rmtree(self.work)

    def test_cids_agree_on_random_trees(self):
        rng = random.Random(SEED)
        tasks, ours = [], []
        for i in range(40):
            root = self.work / f'cid-{i}'
            root.mkdir()
            tree(rng, root)
            limits = rng.choice([{}, dict(chunk=256, links=4), dict(chunk=100, links=2)])
            tasks.append(dict(kind='cid', path=str(root), **limits))
            ours.append(cid.cid_directory(root, chunk_size=limits.get('chunk', cid.CHUNK_SIZE),
                                          max_links=limits.get('links', cid.FILE_MAX_LINKS)))
        self.assertEqual(ours, poslib(tasks))

    def test_checks_agree_on_random_archives(self):
        rng = random.Random(SEED)
        tasks, ours = [], []
        for i in range(20):
            root = self.work / f'check-{i}'
            for project in range(rng.randint(1, 3)):
                archive = root / 'projects' / f'P{project}' / 'archives'
                archive.mkdir(parents=True)
                tree(rng, archive)
            enrol(root)
            mutate(rng, root)
            tasks.append(dict(kind='check', path=str(root)))
            try:
                ours.append(relative(ai.report(root), root))
            except ai.Refused as refused:
                ours.append('refused:' + refused.kind)
        self.assertEqual(ai.encoded(ours), ai.encoded(poslib(tasks)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
