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
"""pyposlib against the fixtures it shares with poslib: every one must agree."""
from pathlib import Path
import shutil
import tempfile
import unittest

from fixtures import build, fixtures, writable
from pyposlib import archive_integrity as ai
from pyposlib import cid


class Built:
    """A fixture built in a temporary directory, removed afterwards."""

    def __init__(self, fixture):
        self.fixture = fixture

    def __enter__(self):
        self.root = Path(tempfile.mkdtemp(prefix='pyposlib-'))
        build(self.fixture, self.root)
        return self.root

    def __exit__(self, *_):
        writable(self.root)
        shutil.rmtree(self.root)


def refusal(operation):
    """The kind operation is refused with, or None."""
    try:
        operation()
    except ai.Refused as refused:
        return refused.kind
    return None


class Formats(unittest.TestCase):
    def test_cids_are_those_ipfs_computes(self):
        for name, fixture in fixtures('cid'):
            with self.subTest(name), Built(fixture) as root:
                params = fixture.get('params', {})
                limits = dict(chunk_size=params.get('chunk', cid.CHUNK_SIZE),
                              max_links=params.get('links', cid.FILE_MAX_LINKS))
                path = root / fixture['entry']
                try:
                    got = (cid.cid_directory if path.is_dir() else cid.cid_file)(path, **limits)
                except cid.ShardingUnsupported:
                    got = 'sharding-unsupported'
                self.assertEqual(fixture.get('cid') or fixture['error'], got)

    def test_an_inventory_gives_the_cids_of_its_tree(self):
        """Every fixture in fixtures/inventory/: the tree on disk and the
        inventory of its files give every CID the fixture records."""
        for name, fixture in fixtures('inventory'):
            with self.subTest(name), Built(fixture) as root:
                params = fixture.get('params', {})
                limits = dict(chunk_size=params.get('chunk', cid.CHUNK_SIZE),
                              max_links=params.get('links', cid.FILE_MAX_LINKS))
                path = root / fixture['entry']
                self.assertEqual(fixture['cids'], cid.cid_tree(path, **limits))
                entries, empty = {}, []
                for file in path.rglob('*'):
                    rel = file.relative_to(path)
                    if any(part.startswith('.') for part in rel.parts):
                        continue
                    if file.is_file():
                        entries[rel.as_posix()] = (cid.cid_file(file, **limits), file.stat().st_size)
                    elif not any(not n.name.startswith('.') for n in file.iterdir()):
                        empty.append(rel.as_posix())
                self.assertEqual(fixture['cids'], cid.cid_inventory(entries, empty, **limits))

    def test_a_cid_decodes_to_the_bytes_it_encodes(self):
        binary = cid.leaf(b'hello')[0]
        self.assertEqual(36, len(binary))
        self.assertEqual(binary, cid.decode(cid.text(binary)))
        for bad in ('', 'b', 'QmNotBase32', 'BAFKREI'):
            with self.assertRaises(ValueError):
                cid.decode(bad)

    def test_a_file_s_dag_size_follows_from_its_size_alone(self):
        """With 256-byte chunks and 4 links a node, sizes across every shape
        of DAG give the size the file's real DAG has."""
        for size in (0, 1, 255, 256, 257, 1024, 1025, 3000, 5000):
            data = bytes(i % 251 for i in range(size))
            real = cid.content(size, lambda s, e: data[s:e], 256, 4)[1]
            self.assertEqual(real, cid.file_tsize(size, 256, 4), size)

    def test_an_inventory_refuses_what_ipfs_would_leave_out(self):
        given = cid.cid_bytes(b'x')
        for path in ('.hidden', 'a/.b/c', 'a//b', ''):
            with self.assertRaises(ValueError):
                cid.cid_inventory({path: (given, 1)})
        with self.assertRaises(ValueError):
            cid.cid_inventory({'a': (given, 1), 'a/b': (given, 1)})
        for empty in (['a'], ['a/b'], ['.c'], ['d//e']):
            with self.assertRaises(ValueError):
                cid.cid_inventory({'a/b': (given, 1)}, empty)

    def test_a_block_is_dag_json_written_one_way(self):
        """Every fixture in fixtures/dag-json/: a value's block and its CID, or
        bytes that are not the one block of their value, refused."""
        for name, fixture in fixtures('dag-json'):
            with self.subTest(name):
                if 'error' in fixture:
                    self.assertEqual(fixture['error'],
                                     refusal(lambda: ai.strict(fixture['bytes'].encode(), name)))
                    continue
                data = fixture['encoded'].encode()
                self.assertEqual(data, ai.block(fixture['value']))
                self.assertEqual(fixture['cid'], ai.event_cid(data))
                self.assertEqual(fixture['value'], ai.strict(data, name))

    def test_json_is_written_one_way(self):
        for name, fixture in fixtures('json'):
            with self.subTest(name):
                self.assertEqual(fixture['encoded'].encode(), ai.encoded(fixture['value']))

    def test_ledgers(self):
        for name, fixture in fixtures('ledger'):
            if fixture['kind'] in ('seal', 'convert'):
                continue  # test_seal.py
            with self.subTest(name), Built(fixture) as root:
                getattr(self, 'ledger_' + fixture['kind'])(fixture, root)

    def ledger_inventory(self, fixture, root):
        archive = root / fixture['archive']
        if 'error' in fixture:
            self.assertEqual(fixture['error'], refusal(lambda: ai.inventory(archive)))
            return
        inventory = ai.inventory(archive)
        self.assertEqual(ai.encoded(fixture['inventory']), ai.encoded(inventory))
        event = ai.encoded(dict(schema=1, previous=None, add=inventory, ledger_id=fixture['ledger_id']))
        self.assertEqual(fixture['event']['encoded'].encode(), event)
        self.assertEqual(fixture['event']['name'], f'{1:08}-{ai.sha(event)}.json')

    def ledger_history(self, fixture, root):
        archive = root / fixture['archive']
        if 'error' in fixture:
            self.assertEqual(fixture['error'], refusal(lambda: ai.history(archive)))
            return
        entries, head, events, _, root, collections, items, empty = ai.history(archive)
        self.assertEqual(fixture.get('empty', []), empty)
        self.assertEqual((fixture['head'], fixture['events']), (head, events))
        self.assertEqual((fixture['root'], fixture['collections']), (root, collections))
        self.assertEqual(fixture['items'], items)
        self.assertEqual(ai.encoded(fixture['entries']), ai.encoded(entries))

    def ledger_report(self, fixture, root):
        base = root.resolve()
        report = ai.report(root)
        for item in report:
            item['archive'] = Path(item['archive']).relative_to(base).as_posix()
            item['checkpoint_writable'] = [Path(p).relative_to(base).as_posix()
                                           for p in item['checkpoint_writable']]
        self.assertEqual(ai.encoded(fixture['report']), ai.encoded(report))


if __name__ == '__main__':
    unittest.main(verbosity=2)
