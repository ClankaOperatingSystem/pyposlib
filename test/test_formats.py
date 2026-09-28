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
import archive_integrity as ai
import cid


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

    def test_json_is_written_one_way(self):
        for name, fixture in fixtures('json'):
            with self.subTest(name):
                self.assertEqual(fixture['encoded'].encode(), ai.encoded(fixture['value']))

    def test_ledgers(self):
        for name, fixture in fixtures('ledger'):
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
        entries, head, events, _ = ai.history(archive)
        self.assertEqual((fixture['head'], fixture['events']), (head, events))
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
