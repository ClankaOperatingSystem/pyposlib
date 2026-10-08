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
"""Searching an archive, as section 12 of poslib's doc/remote-archive-protocol.txt
specifies: where a query is found, as hits that name a file by its
item's ipfs:// link, a range of lines in it and the passage there.

- ArchiveSearch: the port, a typing.Protocol; remote.HttpRemoteArchive
  satisfies it over the wire, and remote.Keeper in memory.
- found: the hits of a query over sources, in the archive's order, which
  is what every adapter of this library answers with; matcher, lines_of
  and hits_in are its parts.
- reference, beneath: a file's ipfs:// link as a sealed item's links
  name it, and which files are beneath a CID.
"""
import re
from typing import Protocol

from .archive_integrity import Refused

MODES = ('literal', 'regex')  # the modes this library matches itself; a keeper may declare more
LIMIT = 1000  # hits answered where no limit is asked for; the protocol wants at least 100


class ArchiveSearch(Protocol):
    """Where a query is found in what a ledger enrols. Raises Refused of the
    kind the protocol names: 'mode' for a mode not served, 'absent' for a
    within the ledger does not enrol, or an adapter that does not search,
    'request' for a query or limit not as the protocol has them."""

    def search(self, query: str, mode: str | None = None, limit: int | None = None,
               within: str | None = None) -> list[dict]:
        """The hits of query, each ref, range and passage, with score in a
        ranked mode: in literal where mode is None, at most limit of them,
        and beneath the CID within where it is given."""
        ...


def matcher(query, mode, modes=MODES):
    """A function of a line: whether query hits it in mode, one of modes.
    literal: the query's characters occur in it as given. regex: Python's
    re finds the query in it, which takes the POSIX extended expressions
    in ordinary use and not every one, [[:alpha:]] among what it lacks.
    Refused as 'mode' for a mode not in modes, as 'request' for an
    expression that does not parse."""
    if mode not in modes:
        raise Refused('mode', f'Not a mode this keeper searches in, {list(modes)}: {mode}')
    if mode == 'literal':
        return lambda line: query in line
    try:
        pattern = re.compile(query)
    except re.error as error:
        raise Refused('request', f'Not a regular expression: {error}')
    return lambda line: pattern.search(line) is not None


def lines_of(data):
    """The lines of data as the protocol counts them: its bytes decoded as
    UTF-8 and split at LF, a terminator after the last line making no line
    of its own. None where data is not UTF-8, which no text mode searches."""
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return None
    lines = text.split('\n')
    if lines[-1] == '':
        lines.pop()
    return lines


def hits_in(data, ref, is_hit):
    """Each hit in data, the file ref names: one for each line is_hit takes,
    its range that line and its passage the line without its terminator."""
    for number, line in enumerate(lines_of(data) or (), 1):
        if is_hit(line):
            yield dict(ref=ref, range=dict(lines=[number, number]), passage=line)


def found(sources, query, mode=None, limit=None, modes=MODES):
    """The hits of query over sources, each (ref, read) with read a function
    of no arguments giving the file's bytes, in the order of sources: the
    archive's, by path bytewise, which the protocol wants of literal and
    regex. mode is literal where None; limit, a positive integer, keeps the
    first hits, LIMIT where None."""
    if not isinstance(query, str) or not query:
        raise Refused('request', 'Expected q, the query')
    if limit is None:
        limit = LIMIT
    elif not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise Refused('request', f'limit is a positive integer: {limit!r}')
    is_hit = matcher(query, 'literal' if mode is None else mode, modes)
    hits = []
    for ref, read in sources:
        for hit in hits_in(read(), ref, is_hit):
            hits.append(hit)
            if len(hits) == limit:
                return hits
    return hits


def by_path(paths):
    """paths in the archive's order: bytewise."""
    return sorted(paths, key=str.encode)


def reference(path, cids, items, collections):
    """The ipfs:// link to the enrolled file at path, as a sealed item's links
    name it (poslib's doc/formats.org, "Links"): the CID of the item that
    holds it, else of the collection, else of the file itself, from cids,
    {path: cid}, then the path beneath that holder where the file is not
    the whole of it."""
    holder = next((h for h in [*items, *collections] if path == h or path.startswith(h + '/')), path)
    return f'ipfs://{cids[holder]}' + (f'/{path[len(holder) + 1:]}' if holder != path else '')


def beneath(cids, within):
    """A function of a path: whether it is within, a CID of cids, or beneath
    a directory that is. Refused as 'absent' where nothing in cids has it."""
    bases = [path for path, given in cids.items() if given == within]
    if not bases:
        raise Refused('absent', f'The ledger enrols nothing under {within}')
    return lambda path: any(base == '.' or path == base or path.startswith(base + '/') for base in bases)
