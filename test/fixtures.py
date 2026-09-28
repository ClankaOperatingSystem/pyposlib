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
"""The fixtures shared with poslib: found in its checkout, built as its doc/formats.org describes."""
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
POSLIB = Path(os.environ.get('POSLIB', HERE.parent / 'poslib'))
FIXTURES = POSLIB / 'fixtures'


def fixtures(kind):
    """The fixtures of kind, a subdirectory, as (name, fixture) sorted by name."""
    return [(p.stem, json.loads(p.read_text(encoding='utf-8')))
            for p in sorted((FIXTURES / kind).glob('*.json'))]


def fixture_bytes(entry):
    if 'repeat' in entry:
        return bytes([entry['repeat'][0]]) * entry['repeat'][1]
    if 'pattern' in entry:
        return bytes(i % 251 for i in range(entry['pattern']))
    return entry['text'].encode('utf-8')


def write(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def build(fixture, root):
    """Build fixture's tree in root."""
    for entry in fixture['tree']:
        path = root / entry['path']
        if entry.get('directory'):
            path.mkdir(parents=True, exist_ok=True)
        elif 'symlink' in entry:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to(entry['symlink'])
        elif 'hardlink' in entry:
            os.link(root / entry['hardlink'], path)
        elif 'series' in entry:
            for i in range(entry['series']):
                write(root / (entry['path'] % i), fixture_bytes(entry), entry.get('mode', 0o644))
        else:
            write(path, fixture_bytes(entry), entry.get('mode', 0o644))


def writable(root):
    """Make everything under root writable, so it can be removed."""
    for here, dirs, files in os.walk(root):
        for name in dirs + files:
            path = Path(here) / name
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | 0o200)
