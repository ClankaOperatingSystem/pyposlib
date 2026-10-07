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
import hashlib
import json
import os
import tempfile
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
# A test asks no keeper but one a fixture has recorded; nor does poslib, run from here.
os.environ['POS_ARCHIVE_OFFLINE'] = '1'
# Nor does a test read or write the tokens a person has kept by signing in.
os.environ['XDG_CONFIG_HOME'] = tempfile.mkdtemp(prefix='pyposlib-config-')
os.environ.pop('POS_ARCHIVE_TOKEN', None)
POSLIB = Path(os.environ.get('POSLIB', HERE.parent / '_deps' / 'poslib'))
FIXTURES = POSLIB / 'fixtures'


def fixtures(kind):
    """The fixtures of kind, a subdirectory, as (name, fixture) sorted by name.
    None found is an error, so that a missing checkout cannot pass."""
    found = [(p.stem, json.loads(p.read_text(encoding='utf-8')))
             for p in sorted((FIXTURES / kind).glob('*.json'))]
    if not found:
        raise FileNotFoundError(f'No {kind} fixtures in {FIXTURES}')
    return found


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


class Tape:
    """A keeper that is a fixture's recording: each request must be the next
    one recorded, and is answered as it was."""

    def __init__(self, recorded):
        self.url, self.token = recorded['url'], recorded['token']
        self.left = list(recorded['exchanges'])

    def send(self, method, url, headers, body):
        if not self.left:
            raise AssertionError(f'A request the recording does not have: {method} {url}')
        exchange = self.left.pop(0)
        sent = dict(method=method, path=url[len(self.url):], authorization=headers.get('Authorization'))
        if body is not None:
            sent.update(content_type=headers['Content-Type'], body_sha256=hashlib.sha256(body).hexdigest())
        if sent != exchange['request']:
            raise AssertionError(f"Not the request recorded: {sent} for {exchange['request']}")
        return exchange['response']['status'], exchange['response']['body'].encode()

    def client(self):
        from pyposlib import remote
        return remote.HttpRemoteArchive(self.url, self.token, self.send)
