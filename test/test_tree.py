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
"""pyposlib's reading of .pos/config.yaml against the fixtures it shares
with poslib, in fixtures/pos-directory/: every one must agree."""
import unittest

from fixtures import fixtures
from pyposlib import tree
from pyposlib.archive_integrity import Refused


def read(text):
    """What read_config makes of text: its configuration, or the kind it
    is refused with."""
    try:
        return tree.read_config(text)
    except Refused as refused:
        return refused.kind


class Tree(unittest.TestCase):
    def test_a_config_is_read_as_the_fixtures_say(self):
        found = fixtures('pos-directory')
        self.assertGreater(len(found), 20)
        for name, fixture in found:
            with self.subTest(name):
                expected = fixture['refused'] if 'refused' in fixture else fixture['config']
                self.assertEqual(read(fixture['yaml']), expected)

    def test_a_scalar_is_the_text_written_whatever_yaml_would_make_of_it(self):
        config = tree.read_config(
            'pos: 1\nchildren:\n  - path: projects/a\n    remote: 2026-10-01\n    branch: 0x1f\n')
        self.assertEqual(config['children'][0]['remote'], '2026-10-01')
        self.assertEqual(config['children'][0]['branch'], '0x1f')

    def test_text_that_is_not_yaml_is_refused(self):
        self.assertEqual(read('pos: [1\n'), 'not-yaml')


if __name__ == '__main__':
    unittest.main()
