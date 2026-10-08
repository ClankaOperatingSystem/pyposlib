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
  satisfies it over the wire, remote.Keeper in memory, and
  DiskArchiveSearch over an archive on disk, which is grep's behaviour
  behind the port.
- found: the hits of a query over sources, in the archive's order, which
  is what every adapter of this library answers with; matcher, lines_of
  and hits_in are its parts.
- reference, beneath: a file's ipfs:// link as a sealed item's links
  name it, and which files are beneath a CID.
- scope, command: every archive under a root, each through the adapter
  that reaches it, and the command line's search.
"""
import os
from pathlib import Path
import re
import sys
from typing import Protocol

from . import archive_integrity as ai
from .archive_integrity import Refused
from . import cid

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


# ------------------------------------------------------------------ on disk

class DiskArchiveSearch:
    """ArchiveSearch over an archive on disk, the archives/ of a scope: what
    grep finds there, each hit a reference instead of a path, so that an
    agent at a shell gets from the archive what it would have got from
    grep and can cite it. literal and regex.

    The CIDs a reference names come from the ledger's fold, as a kept
    archive's do, with no file hashed; a ledger whose entries record no
    CID, one of schema 1, is hashed from disk as link hashes it."""

    modes = MODES

    def __init__(self, archive):
        self.archive = Path(archive)

    def search(self, query, mode=None, limit=None, within=None):
        entries, _, _, _, _, collections, items, empty = ai.history(self.archive)
        try:
            cids = ai.fold(entries, empty)
        except Refused:
            cids = cid.cid_tree(self.archive)
        chosen = beneath(cids, within) if within is not None else (lambda path: True)
        sources = [(reference(path, cids, items, collections), (self.archive / path).read_bytes)
                   for path in by_path(entries) if path in cids and chosen(path)]
        return found(sources, query, mode, limit, self.modes)


def scope(root, query, mode=None, limit=None, within=None, keeper_for=None):
    """The hits of query in each archive under root, as check finds them
    (ai.roots), in their order: [(archive, hits)]. An archive on disk is
    searched here and one a keeper keeps by its keeper, which keeper_for
    makes of its URL, ai.keeper_of by default. limit caps the hits of all
    together. With within, an archive that enrols nothing under it gives
    nothing, and it is refused as absent only where none does."""
    answers, left, enrolled = [], limit, within is None
    for archive in ai.roots(root):
        if left is not None and left < 1:
            break
        url = ai.kept(archive)
        adapter = (keeper_for or ai.keeper_of)(url) if url else DiskArchiveSearch(archive)
        try:
            hits = adapter.search(query, mode, left, within)
        except Refused as refused:
            if refused.kind != 'absent' or within is None:
                raise
            continue
        enrolled = True
        if hits:
            answers.append((archive, hits))
            if left is not None:
                left -= len(hits)
    if not enrolled:
        raise Refused('absent', f'No archive under {root} enrols anything under {within}')
    return answers


def command(args, out=None):
    """search ROOT QUERY [--mode MODE] [--limit N] [--within CID]: each hit
    of every archive under ROOT on standard output, a line of the passage
    at a time as LINK:LINE:TEXT, grep's shape with a reference for the
    path. Exit 0 with hits, 1 with none; None where args are not the
    command's, for the caller to print the usage."""
    if len(args) < 2 or len(args) % 2:
        return None
    root, query, options = args[0], args[1], {}
    for name, value in zip(args[2::2], args[3::2]):
        if name not in ('--mode', '--limit', '--within') or name[2:] in options:
            return None
        options[name[2:]] = value
    limit = options.get('limit')
    if limit is not None:
        if not limit.isdecimal() or int(limit) < 1:
            raise Refused('request', f'limit is a positive integer: {limit}')
        limit = int(limit)
    out = sys.stdout.buffer if out is None else out
    answers = scope(root, query, options.get('mode'), limit, options.get('within'))
    for _, hits in answers:
        for hit in hits:
            first = hit['range']['lines'][0]
            for offset, line in enumerate(hit['passage'].split('\n')):
                out.write(f"{hit['ref']}:{first + offset}:{line}{os.linesep}".encode())
    out.flush()
    return 0 if answers else 1
