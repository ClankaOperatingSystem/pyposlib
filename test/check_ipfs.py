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
"""The CID fixtures against kubo, offline: python3 test/check_ipfs.py IPFS.

A fresh repository with the unixfs-v1-2025 profile, and ipfs add --only-hash,
which stores and announces nothing. kubo must give each fixture's recorded CID,
and so must we; for one we refuse, kubo must give the CID the fixture records.
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from fixtures import build, fixtures, writable
from pyposlib import cid


def kubo(program, repo, *args):
    result = subprocess.run([program, *args], env=dict(os.environ, IPFS_PATH=str(repo)),
                            capture_output=True, text=True, check=True)
    return result.stdout.strip()


def main(program):
    failed = 0
    with tempfile.TemporaryDirectory() as work:
        repo = Path(work) / 'repo'
        kubo(program, repo, 'init', '--profile', 'unixfs-v1-2025,test')
        print(kubo(program, repo, 'version'))
        for name, fixture in fixtures('cid'):
            root = Path(tempfile.mkdtemp(prefix='pyposlib-ipfs-'))
            try:
                build(fixture, root)
                path = root / fixture['entry']
                params = fixture.get('params', {})
                flags = (['--recursive'] if path.is_dir() else []) + \
                    ([f"--chunker=size-{params['chunk']}"] if 'chunk' in params else []) + \
                    ([f"--max-file-links={params['links']}"] if 'links' in params else [])
                theirs = kubo(program, repo, 'add', '--quieter', '--only-hash', *flags, str(path))
                limits = dict(chunk_size=params.get('chunk', cid.CHUNK_SIZE),
                              max_links=params.get('links', cid.FILE_MAX_LINKS))
                try:
                    ours = (cid.cid_directory if path.is_dir() else cid.cid_file)(path, **limits)
                except cid.ShardingUnsupported:
                    ours = 'sharding-unsupported'
                if theirs == (fixture.get('cid') or fixture['ipfs']) and \
                        ours == (fixture.get('cid') or fixture['error']):
                    print(f'ok    {name}')
                else:
                    failed += 1
                    print(f"FAIL  {name}: recorded {fixture.get('cid') or fixture['ipfs']}, "
                          f'kubo {theirs}, ours {ours}')
            finally:
                writable(root)
                shutil.rmtree(root)
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(os.path.abspath(sys.argv[1]) if '/' in sys.argv[1] else sys.argv[1]))
