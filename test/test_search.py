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
"""Search over an archive on disk: grep's behaviour behind the port, the
same answer as the keeper's, and the command at a shell."""
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
import unittest.mock

from fixtures import write
from pyposlib import archive_integrity as ai
from pyposlib import cid
from pyposlib import remote
from pyposlib import seal
from pyposlib import search
from test_remote import Scope, begun, over, refusal
from test_seal import KeptScope

TOOL = Path(__file__).resolve().parent.parent / 'archive_integrity.py'
ITEMS = (('first', {'a.txt': b'alpha\nbeta alpha\n', 'sub/b.txt': b'gamma', 'raw.bin': b'\xff\xfealpha'}),
         ('second', {'c.txt': b'alpha'}),
         ('third', {'x.txt': b'alpha', 'y.txt': b'alpha'}))


def sealed(scope, keeper=None):
    """ITEMS sealed in scope, and sent to keeper where one is given."""
    for item, files in ITEMS:
        sent = scope.seal(item, files)
        if keeper is not None:
            over(keeper).append(*sent, {})


def shape(hits):
    return [(h['ref'], h['range']['lines'], h['passage']) for h in hits]


class OnDisk(unittest.TestCase):
    def test_the_disk_and_the_keeper_give_one_answer(self):
        """Over one archive, sealed on disk and sent to a keeper, literal
        searches with and without a limit and a within give the same hits in
        the same order from both; a within neither enrols is absent at both."""
        with Scope() as scope:
            keeper = remote.Keeper()
            sealed(scope, keeper)
            disk = search.DiskArchiveSearch(scope.scope / 'archives')
            client = over(keeper)
            folded = ai.fold_cids(scope.scope / 'archives')
            asks = [dict(query='alpha'), dict(query='gam'), dict(query='zzz'), dict(query='alpha', limit=2),
                    dict(query='alpha', within=folded['third']), dict(query='alpha', within=folded['first/a.txt']),
                    dict(query='alpha', within=folded['.'], limit=4)]
            for ask in asks:
                with self.subTest(**ask):
                    self.assertEqual(client.search(**ask), disk.search(**ask))
            self.assertEqual(5, len(disk.search('alpha')))
            never = cid.cid_bytes(b'never')
            self.assertEqual(('absent', 'absent'), (refusal(lambda: disk.search('alpha', within=never)),
                                                    refusal(lambda: client.search('alpha', within=never))))

    def test_a_hit_on_disk_is_what_fetch_gives_at_its_range(self):
        """Each reference resolves on disk through fetch, from a directory
        beneath the scope, and the passage is the lines of the range; a file
        that is not UTF-8 gives no hit."""
        with Scope() as scope:
            sealed(scope)
            (scope.scope / 'canon').mkdir()
            hits = search.DiskArchiveSearch(scope.scope / 'archives').search('alpha')
            self.assertEqual(5, len(hits))
            for hit in hits:
                lines = search.lines_of(seal.fetch(hit['ref'], scope.scope / 'canon'))
                first, last = hit['range']['lines']
                self.assertEqual(hit['passage'], '\n'.join(lines[first - 1:last]))
            self.assertNotIn('raw.bin', ''.join(h['ref'] for h in hits))

    def test_regex_is_served_on_disk(self):
        """The disk declares literal and regex; a regex is matched within a
        line; one that does not parse is request; another mode is mode."""
        with Scope() as scope:
            sealed(scope)
            disk = search.DiskArchiveSearch(scope.scope / 'archives')
            self.assertEqual(('literal', 'regex'), disk.modes)
            self.assertEqual(['beta alpha', 'gamma'], [h['passage'] for h in disk.search('^[bg]', mode='regex')])
            self.assertEqual(['alpha'] * 4, [h['passage'] for h in disk.search('^alpha$', mode='regex')])
            self.assertEqual('request', refusal(lambda: disk.search('(', mode='regex')))
            self.assertEqual('mode', refusal(lambda: disk.search('alpha', mode='words')))

    def test_a_ledger_without_cids_is_hashed_from_disk(self):
        """A schema 1 ledger enrols no CID: the files are hashed as link
        hashes them, and each hit names its file by its own CID, there being
        no item."""
        with Scope() as scope:
            archive = scope.scope / 'archives'
            events = begun(0, 2)
            for number, (name, data) in enumerate(events, 1):
                write(archive / f'{number}.md', f'old {number}'.encode())
                ai.new_file(scope.scope / ai.INTEGRITY / 'ledger' / name, data)
            hits = search.DiskArchiveSearch(archive).search('old')
            self.assertEqual([(f'ipfs://{cid.cid_bytes(b"old 1")}', [1, 1], 'old 1'),
                              (f'ipfs://{cid.cid_bytes(b"old 2")}', [1, 1], 'old 2')], shape(hits))

    def test_a_scope_s_archives_are_searched_each_by_what_reaches_it(self):
        """Under one root, an archive on disk is searched here and one a
        keeper keeps through its keeper; the limit caps them together; a
        within that one archive enrols searches that one, and one that none
        enrols is absent."""
        with KeptScope() as kept:
            kept.seal('trial')
            other = kept.dir / 'projects' / 'b'
            write(other / 'note' / 'n.txt', b'a result\nno\nanother result\n')
            plan = seal.plan(other / 'note', other / 'archives' / 'note')
            seal.apply(plan, ai.sha(ai.encoded(plan)))
            keeper_for = lambda url: kept.client()  # noqa: E731
            kept_cids = ai.fold_cids(kept.scope / 'archives')
            other_cids = ai.fold_cids(other / 'archives')
            found = search.scope(kept.dir, 'result', keeper_for=keeper_for)
            self.assertEqual([(kept.scope / 'archives', [(f'ipfs://{kept_cids["trial"]}/result.txt', [1, 1], 'result')]),
                              (other / 'archives', [(f'ipfs://{other_cids["note"]}/n.txt', [1, 1], 'a result'),
                                                    (f'ipfs://{other_cids["note"]}/n.txt', [3, 3], 'another result')])],
                             [(archive, shape(hits)) for archive, hits in found])
            self.assertEqual([1, 1], [len(hits) for _, hits in search.scope(kept.dir, 'result', limit=2,
                                                                           keeper_for=keeper_for)])
            self.assertEqual([other / 'archives'],
                             [archive for archive, _ in search.scope(kept.dir, 'result', within=other_cids['note'],
                                                                     keeper_for=keeper_for)])
            self.assertEqual([], search.scope(kept.dir, 'nothing of the kind', keeper_for=keeper_for))
            self.assertEqual('absent', refusal(lambda: search.scope(kept.dir, 'result', within=cid.cid_bytes(b'x'),
                                                                    keeper_for=keeper_for)))

    def test_the_command_prints_grep_s_shape_with_a_reference(self):
        """search ROOT QUERY prints LINK:LINE:TEXT a line, in the archive's
        order, and exits 0; nothing found exits 1 and prints nothing; the
        options narrow it; a wrong option prints the usage and exits 2."""
        with Scope() as scope:
            sealed(scope)
            folded = ai.fold_cids(scope.scope / 'archives')

            def run(*args):
                done = subprocess.run([sys.executable, '-B', str(TOOL), 'search', str(scope.scope), *args],
                                      capture_output=True)
                return done.returncode, done.stdout.decode().splitlines(), done.stderr.decode()
            code, lines, _ = run('alpha')
            self.assertEqual(0, code)
            self.assertEqual([f'ipfs://{folded["first"]}/a.txt:1:alpha', f'ipfs://{folded["first"]}/a.txt:2:beta alpha',
                              f'ipfs://{folded["second"]}/c.txt:1:alpha', f'ipfs://{folded["third"]}/x.txt:1:alpha',
                              f'ipfs://{folded["third"]}/y.txt:1:alpha'], lines)
            self.assertEqual((1, []), run('zzz')[:2])
            self.assertEqual((0, [f'ipfs://{folded["first"]}/a.txt:2:beta alpha']), run('a a', '--limit', '1')[:2])
            self.assertEqual((0, [f'ipfs://{folded["second"]}/c.txt:1:alpha']),
                             run('alpha', '--within', folded['second'])[:2])
            self.assertEqual((0, [f'ipfs://{folded["first"]}/sub/b.txt:1:gamma']), run('^g', '--mode', 'regex')[:2])
            for wrong in (('alpha', '--limit'), ('alpha', '--colour', 'always'), ('alpha', '--limit', '1', '--limit', '2')):
                code, lines, err = run(*wrong)
                self.assertEqual((2, []), (code, lines))
                self.assertIn('search ROOT QUERY', err)
            self.assertEqual(2, run('alpha', '--limit', '0')[0])
            self.assertEqual(2, run('alpha', '--mode', 'semantic')[0])
            self.assertIn(b'search ROOT QUERY', subprocess.run([sys.executable, '-B', str(TOOL), 'help'],
                                                               capture_output=True).stdout)

    def test_a_passage_of_several_lines_prints_a_line_each(self):
        """A ranked adapter's passage may span lines: the command prints each
        on its own line, numbered on from the range's first."""
        out = io.BytesIO()
        hits = [dict(ref='ipfs://x/f.txt', range=dict(lines=[4, 5]), passage='four\nfive', score=0.5)]
        with unittest.mock.patch.object(search, 'scope', return_value=[(Path('a'), hits)]):
            self.assertEqual(0, search.command(['root', 'q'], out))
        self.assertEqual(['ipfs://x/f.txt:4:four', 'ipfs://x/f.txt:5:five'], out.getvalue().decode().splitlines())


if __name__ == '__main__':
    unittest.main(verbosity=2)
