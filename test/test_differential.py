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
from pyposlib import archive_integrity as ai
from pyposlib import cid
from pyposlib import seal

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
        # poslib's make deps fetches its dependencies into its _deps/.
        packages = [arg for name in ('markdown-mode', 'yaml')
                    for arg in ('-L', str(POSLIB.resolve() / '_deps' / name))]
        result = subprocess.run([EMACS, '-Q', '--batch', *packages, '-L', str(POSLIB / 'lisp'),
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


class DifferentialSeal(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='pyposlib-differential-'))

    def tearDown(self):
        writable(self.work)
        shutil.rmtree(self.work)

    @unittest.skipUnless(shutil.which(EMACS), 'needs Emacs')
    def test_repairs_agree_on_missing_directories(self):
        tasks, ours = [], []
        for problem in ('none', 'file', 'changed', 'missing', 'read-bits', 'executable'):
            root = self.work / problem
            (root / 'item/a').mkdir(parents=True)
            (root / 'item/z/leaf').mkdir(parents=True)
            write(root / 'item/result.txt', b'result')
            if problem == 'read-bits':
                (root / 'item/result.txt').chmod(0o600)
            plan = seal.plan(root / 'item', root / 'archives/item')
            seal.apply(plan, ai.sha(ai.encoded(plan)))
            item = root / 'archives/item'
            (item / 'a').rmdir()
            (item / 'z/leaf').rmdir()
            (item / 'z').rmdir()
            if problem == 'file':
                write(item / 'z', b'obstruction')
            elif problem == 'changed':
                (item / 'result.txt').chmod(0o644)
                (item / 'result.txt').write_bytes(b'changed')
            elif problem == 'missing':
                (item / 'result.txt').unlink()
            elif problem == 'read-bits':
                (item / 'result.txt').chmod(0o644)
            elif problem == 'executable':
                (item / 'result.txt').chmod(0o744)
            theirs = self.work / (problem + '-poslib')
            shutil.copytree(root, theirs)
            tasks.append(dict(kind='repair', path=str(theirs)))
            try:
                ours.append(dict(result=ai.repair(root), report=relative(ai.report(root), root)))
            except ai.Refused as refused:
                ours.append('refused:' + refused.kind)
        self.assertEqual(ai.encoded(ours), ai.encoded(poslib(tasks)))

    @unittest.skipUnless(shutil.which(EMACS), 'needs Emacs')
    def test_seals_agree_on_random_items(self):
        rng = random.Random(SEED)
        tasks, ours, pending = [], [], []
        for i in range(20):
            base = self.work / f'seal-{i}'
            archive = base / 'scope' / 'archives'
            archive.mkdir(parents=True)
            tree(rng, archive)
            if rng.random() < 0.5:
                enrol(base / 'scope')
            item = base / 'scope' / 'item'
            item.mkdir()
            tree(rng, item)
            for held in [item, *(p for p in sorted(item.rglob('*')) if p.is_dir())]:
                if rng.random() < 0.3:
                    (held / '_seal').mkdir()
            if rng.random() < 0.3:
                write(item / 'README.org', b'#+TITLE: Item\n#+COLLECTION: t\n')
            theirs = self.work / f'seal-{i}-poslib'
            shutil.copytree(base, theirs, symlinks=True)
            task = dict(source='scope/item', destination=f'scope/archives/sealed-{i}',
                        ledger_id='0f1e2d3c-4b5a-4968-8778-a6b5c4d3e2f1')
            tasks.append(dict(kind='seal', path=str(theirs), **task))
            root = base.resolve()
            try:
                try:
                    plan = seal.plan(root / task['source'], root / task['destination'], task['ledger_id'])
                except ai.Refused as refused:
                    if refused.kind != 'interpretation':
                        raise
                    plan = None  # poslib's to plan; ours to apply, below
                if plan is None:
                    pending.append((len(ours), root))
                    ours.append(None)
                    continue
                event, _ = seal.apply(plan, ai.sha(ai.encoded(plan)))
                ours.append(dict(plan={k: os.path.relpath(v, root)
                                       if k in ('source', 'destination', 'archive', 'ledger') else v
                                       for k, v in plan.items()},
                                 event=event.read_bytes().decode(),
                                 report=relative(ai.report(root), root)))
            except ai.Refused as refused:
                ours.append('refused:' + refused.kind)
        theirs = poslib(tasks)
        for at, root in pending:
            # Apply poslib's plan to our own copy, and compare what follows.
            plan = {k: str(root / v) if k in ('source', 'destination', 'archive', 'ledger') else v
                    for k, v in theirs[at]['plan'].items()}
            try:
                event, _ = seal.apply(plan, ai.sha(ai.encoded(plan)))
                ours[at] = dict(plan=theirs[at]['plan'], event=event.read_bytes().decode(),
                                report=relative(ai.report(root), root))
            except ai.Refused as refused:
                ours[at] = 'refused:' + refused.kind
        self.assertEqual(ai.encoded(ours), ai.encoded(theirs))

    @unittest.skipUnless(shutil.which(EMACS), 'needs Emacs')
    def test_links_agree_on_random_archives(self):
        """Every path of an archive poslib sealed an item into, a collection
        or not, has one link or one refusal, and a path that is not there."""
        rng = random.Random(SEED)
        seals = []
        for i in range(10):
            base = self.work / f'link-{i}'
            archive = base / 'scope' / 'archives'
            archive.mkdir(parents=True)
            tree(rng, archive)
            if rng.random() < 0.5:
                enrol(base / 'scope')
            item = base / 'scope' / 'item'
            item.mkdir()
            write(item / 'kept.txt', b'kept')
            tree(rng, item)
            if rng.random() < 0.5:
                write(item / 'README.org', b'#+TITLE: Item\n#+COLLECTION: t\n')
            seals.append(dict(kind='seal', path=str(base), source='scope/item',
                              destination='scope/archives/sealed',
                              ledger_id='0f1e2d3c-4b5a-4968-8778-a6b5c4d3e2f1'))
        poslib(seals)
        paths = [path for task in seals
                 for scope in [Path(task['path']) / 'scope']
                 for path in [*sorted(scope.rglob('*')), scope / 'archives' / 'absent' / 'file']]
        ours = []
        for path in paths:
            try:
                ours.append(seal.link(path))
            except ai.Refused as refused:
                ours.append('refused:' + refused.kind)
        self.assertTrue(any(link.startswith('ipfs://') and '/' in link[7:] for link in ours))
        self.assertEqual(ours, poslib([dict(kind='link', path=str(path)) for path in paths]))

    @unittest.skipUnless(shutil.which(EMACS), 'needs Emacs')
    def test_fetched_bytes_agree_on_random_sealed_items(self):
        """Both give the same bytes, or the same refusal, for the link to
        every sealed path of random scopes, for the same link with an Org
        search, and for links to nothing."""
        import base64
        rng = random.Random(SEED)
        seals = []
        for i in range(10):
            base = self.work / f'fetch-{i}'
            archive = base / 'scope' / 'archives'
            archive.mkdir(parents=True)
            tree(rng, archive)
            if rng.random() < 0.5:
                enrol(base / 'scope')
            item = base / 'scope' / 'item'
            item.mkdir()
            write(item / 'kept.txt', b'kept')
            write(item / 'bytes.bin', bytes(rng.randrange(256) for _ in range(300)))
            tree(rng, item)
            seals.append(dict(kind='seal', path=str(base), source='scope/item',
                              destination='scope/archives/sealed',
                              ledger_id='0f1e2d3c-4b5a-4968-8778-a6b5c4d3e2f1'))
        poslib(seals)
        tasks = []
        for task in seals:
            scope = Path(task['path']) / 'scope'
            for path in sorted((scope / 'archives' / 'sealed').rglob('*')):
                link = seal.link(path)
                tasks += [dict(kind='fetch', uri=link, directory=str(scope)),
                          dict(kind='fetch', uri=link + '::a search', directory=str(scope))]
            tasks += [dict(kind='fetch', uri='ipfs://bafkreiaaaa', directory=str(scope)),
                      dict(kind='fetch', uri='no link', directory=str(scope))]
        ours = []
        for task in tasks:
            try:
                ours.append(base64.b64encode(seal.fetch(task['uri'], task['directory'])).decode())
            except ai.Refused as refused:
                ours.append('refused:' + refused.kind)
        self.assertTrue(any(not answer.startswith('refused:') for answer in ours))
        self.assertTrue(any(answer == 'refused:absent' for answer in ours))
        self.assertEqual(ours, poslib(tasks))


if __name__ == '__main__':
    unittest.main(verbosity=2)
