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
"""The remote archive protocol, as poslib's doc/remote-archive-protocol.txt specifies.

A ledger stays with its scope; the archive it enrols may be kept away
from it, by a keeper reached at a URL. Seven operations pass between
them, under version 2 of the protocol; a keeper of version 1 alone takes
a file's bytes inside the append that enrols it, and a client speaks the
highest version a keeper lists (version_of).

- RemoteArchive: the port a sealing client calls, a typing.Protocol;
  search.ArchiveSearch is the port a reading client searches through.
- HttpRemoteArchive: both ports over HTTP, the protocol's wire.
- Keeper: the keeping side, in memory: it verifies what it is sent as
  the protocol requires, searches what it holds in literal mode, and is
  what a server wraps around its storage.
- named, following: the ledger a run of events names, and the events a
  client sends after one that names none.
- handle: the wire's keeping side, one request to one response.
- server: a keeper behind handle on a local port, for trying a client.
"""
import http.server
import json
import re
from typing import Mapping, Protocol, Sequence
import urllib.error
import urllib.parse
import urllib.request

from . import archive_integrity as ai
from .archive_integrity import Refused, encoded, sha
from . import cid
from . import search as searching
from . import signin

VERSIONS = (1, 2)
BLOCK_LIMIT = 1048576  # the largest block of an archive: one raw leaf
SILENCE = 60  # seconds a keeper may say nothing before a request is given up


def version_of(described):
    """The version a client speaks to the keeper described: the highest of
    VERSIONS the keeper lists under protocols, or 1 where it lists none, as
    a keeper of version 1 alone does. Refused as 'version' where none is
    shared."""
    offered = described.get('protocols') or [described.get('protocol', 1)]
    shared = [v for v in VERSIONS if v in offered]
    if not shared:
        raise Refused('version', f'The keeper serves protocol versions {offered}; this client speaks {list(VERSIONS)}')
    return max(shared)


class RemoteArchive(Protocol):
    """A ledger's archive, kept away from it: the operations of the
    protocol. Each raises Refused, of the kind the keeper names."""

    def describe(self) -> dict:
        """What the keeper holds of the ledger: protocol, protocols and any
        retiring, ledger_id, head, events, root and erased; and search, the
        modes it searches in, where it searches."""
        ...

    def held(self, cids: Sequence[str]) -> list[str]:
        """Which of cids the keeper holds no block for, in their order.
        Version 2."""
        ...

    def put(self, cid_text: str, data: bytes) -> bool:
        """Hold the block cid_text names, data; True if it was not held before.
        Version 2."""
        ...

    def event(self, number: int) -> bytes:
        """The bytes of event number, as the ledger's file holds them."""
        ...

    def append(self, name: str, event: bytes, files: Mapping[str, bytes],
               claims: Mapping[str, str], following: Sequence[tuple[str, bytes]] = ()) -> dict:
        """Append the event of bytes event, the ledger file name names, with
        the client's claims; the description after. files, by their CIDs,
        travel with the event under version 1 and are empty under version 2,
        whose bytes are put as blocks first. following is the events after
        it, each (name, bytes) in order, by which an event that names no
        ledger is known for this ledger's (following). The same event at the
        same number again changes nothing."""
        ...

    def read(self, cid_text: str, path: str = '') -> bytes:
        """The bytes of the block cid_text, or of the file at path beneath
        it when it is a directory."""
        ...


# ----------------------------------------------------------------- identity

def named(events):
    """The ledger_id events name, each (name, bytes) in order: that of the
    last of them that has one, or None. In a valid chain every event that
    has one has the same, and none follows one that has."""
    for _, data in reversed(events):
        found = json.loads(data).get('ledger_id')
        if found is not None:
            return found
    return None


def following(events, number):
    """What a client sends after event number of events, a ledger's (name,
    bytes) in order, so that a keeper can tell whose the event is.

    An event's ledger is named by the event or by one before it. A ledger
    begun before events carried a ledger_id has first events that name
    none, and for one of those the client sends the events after it, up to
    and including the first that does name the ledger: each event's
    previous is the hash of the one before, so that event vouches for all
    before it. For any other event this is empty; and it is empty where no
    event names a ledger, since nothing then vouches."""
    if named(events[:number]) is not None:
        return []
    for index in range(number, len(events)):
        if named(events[index:index + 1]) is not None:
            return list(events[number:index + 1])
    return []


# ------------------------------------------------------------------ keeping

class Keeper:
    """The keeping side of the protocol.

    It keeps a ledger's events and the blocks of what they enrol, and
    takes nothing on trust: an event must be the next of a valid chain,
    a file's bytes must hash to the CID they are sent under, and once
    the ledger is of schema 3 its fold must give the event's root with
    every enrolled file held.

    ledger_id is the ledger it is to keep, and it takes no event of
    another (whose). Given none it keeps whichever ledger it is first
    sent an event of, and is that ledger's from the first event that
    names one.

    Alone it keeps everything in memory. A server gives it what it
    already holds: events, the ledger's (name, bytes) in order; blocks,
    a mapping of CID to bytes that may be shared between ledgers, of
    which it uses only membership, reading and assignment; and erased,
    a mapping of CID to when. It writes blocks before it counts an
    event appended, so that whoever records the event after append
    returns records nothing whose bytes are not held.

    protocols is the versions it serves, VERSIONS by default; one of (1,)
    is a keeper of version 1 alone, whose describe has protocol and no
    protocols, and one without 1 takes no file inside an append. retiring,
    by version, is the date after which it may stop serving that version.
    A block put before any event enrols it is held until forgotten, which
    this keeper never does; a server may, after the protocol's seven days.

    modes is what it searches in, over the blocks it holds, literal alone
    by default; one given no modes does not search, and describes no
    search member. A server that answers a ranked mode from an index of
    its own declares that mode and answers it itself."""

    def __init__(self, ledger_id=None, events=(), blocks=None, erased=None, protocols=VERSIONS, retiring=None,
                 modes=('literal',)):
        self.ledger_id = ledger_id
        self.events, self.claims = list(events), []
        self.blocks = {} if blocks is None else blocks
        self.erased = {} if erased is None else erased
        self.protocols = tuple(sorted(protocols))
        self.retiring = dict(retiring or {})
        self.modes = tuple(modes)
        self._cids = None

    def _state(self, events):
        entries, head, root, collections, items, empty = ai.chain(events)
        return entries, head, root, empty, collections, items

    def cids(self):
        """What the ledger folds to, {path: cid}; nothing while it holds a
        legacy entry or no event."""
        if self._cids is None:
            self._cids = {}
            if self.events:
                entries, _, _, empty, _, _ = self._state(self.events)
                try:
                    self._cids = ai.fold(entries, empty)
                except Refused:
                    pass
        return self._cids

    def describe(self):
        head, root = None, None
        if self.events:
            _, head, root, _, _, _ = self._state(self.events)
        # A ledger with no event yet has no id to describe, whichever the
        # keeper was told to keep.
        described = dict(protocol=self.protocols[0], ledger_id=self.ledger_id if self.events else None, head=head,
                         events=len(self.events), root=root, erased=sorted(self.erased))
        if self.protocols != (1,):
            described['protocols'] = list(self.protocols)
            if self.retiring:
                described['retiring'] = {str(v): d for v, d in sorted(self.retiring.items())}
        if self.modes:
            described['search'] = dict(modes=list(self.modes))
        return described

    def held(self, cids):
        """Which of cids the keeper holds no block for, in their order."""
        if not isinstance(cids, list) or not all(isinstance(c, str) and ai.is_cid(c) for c in cids):
            raise Refused('request', 'Expected an array of CIDs')
        return [c for c in cids if c not in self.blocks]

    def put(self, cid_text, data):
        """Hold the block cid_text names; True if it was not held before.
        Refused as entry unless data is that block, as size above BLOCK_LIMIT."""
        if len(data) > BLOCK_LIMIT:
            raise Refused('size', f'A block is at most {BLOCK_LIMIT} bytes')
        if not ai.is_cid(cid_text) or cid.text(cid.binary_cid(cid.codec(cid_text), data)) != cid_text:
            raise Refused('entry', f'Bytes are not those of the CID they were put under: {cid_text}')
        new = cid_text not in self.blocks
        self.blocks[cid_text] = data
        return new

    def holds_dag(self, cid_text):
        """Whether the block cid_text names is held with every block it links,
        through every level: what it is for an entry's bytes to be held."""
        if cid_text not in self.blocks:
            return False
        if cid.codec(cid_text) != cid.DAG_PB:
            return True
        links, _ = cid.parse(self.blocks[cid_text])
        return all(self.holds_dag(cid.text(child)) for child, _, _ in links)

    def event(self, number):
        if not 1 <= number <= len(self.events):
            raise Refused('absent', f'No event {number}')
        return self.events[number - 1][1]

    def whose(self, name, event, following):
        """Refuse, as identity, an event that is not this keeper's ledger's.

        The ledger an event belongs to is the one named by the chain it
        ends: the events held, then the event. Where that chain names
        none, the event is one of the first of a ledger begun before
        events carried a ledger_id, and nothing in it says whose it is.
        It is then taken only with following, the events after it up to
        one that names this ledger, which must be valid next events of
        the same chain: each event's previous is the hash of the one
        before, so the event that names the ledger could follow no other
        first events than these. following is verified and not kept; its
        events are appended when they are sent in their turn.

        A keeper told no ledger has none to hold an event to."""
        if self.ledger_id is None:
            return
        chain = [*self.events, (name, event)]
        if named(chain) is None and following:
            chain = [*chain, *following]
            ai.chain(chain)
        if named(chain) != self.ledger_id:
            raise Refused('identity', 'The event is not this ledger\'s: it names another, or it names '
                                      'none and no event sent after it names this one')

    def append(self, name, event, files, claims, following=()):
        match = ai.EVENT_NAME.fullmatch(name)
        if not match:
            raise Refused('sequence', f'Not an event\'s name: {name}')
        number = int(match[1])
        if number <= len(self.events):
            if self.events[number - 1] != (name, event):
                raise Refused('chain', f'Another event is number {number}')
            return self.describe()
        if number != len(self.events) + 1:
            raise Refused('chain', f'The next event is number {len(self.events) + 1}')
        if files and 1 not in self.protocols:
            raise Refused('version', f'Files travel inside an append only in version 1; this keeper serves '
                                     f'{list(self.protocols)}: put the blocks first')
        for given, data in files.items():
            if not ai.is_cid(given) or cid.cid_bytes(data) != given:
                raise Refused('entry', f'Bytes are not those of the CID they were sent under: {given}')
        entries, head, root, empty, _, _ = self._state([*self.events, (name, event)])
        value = json.loads(event)
        self.whose(name, event, list(following))
        # What was kept before this event: everything, if the event before
        # was of schema 3; nothing, if the ledger is only now being kept.
        kept = bool(self.events) and ai.is_event_cid(ai.EVENT_NAME.fullmatch(self.events[-1][0])[2])
        before = set(self.cids().values()) if kept else set()
        cids, directories = None, {}
        if value['schema'] == 3:
            cids = ai.fold(entries, empty, directories)
            if cids['.'] != root:
                raise Refused('root', 'The ledger does not fold to the event\'s root')
            for path in (value['add'] if kept else entries):
                given = entries[path]['cid']
                if (given not in files and not self.holds_dag(given)
                        and not any(part.startswith('.') for part in path.split('/'))):
                    raise Refused('entry', f'Bytes not held for {path}')
        for data in files.values():
            for given, block in cid.blocks(data).items():
                self.blocks[given] = block
        for given, block in directories.items():
            if given not in before:
                self.blocks[given] = block
        self.blocks[ai.event_cid(ai.as_block(event))] = ai.as_block(event)
        self.events.append((name, event))
        self.claims.append(dict(claims))
        self.ledger_id = self.ledger_id or value.get('ledger_id')
        self._cids = cids
        return self.describe()

    def holds(self, cid_text):
        """Whether the ledger enrols cid_text: a file, a directory or an event."""
        return (cid_text in self.cids().values()
                or any(ai.event_cid(ai.as_block(data)) == cid_text for _, data in self.events))

    def erase(self, cid_text, when):
        """Forget the bytes of cid_text, and say when: the ledger is unchanged.
        Where blocks are shared between ledgers, forgetting is the server's."""
        if not self.holds(cid_text):
            raise Refused('absent', f'Not held: {cid_text}')
        self.blocks.pop(cid_text, None)
        self.erased[cid_text] = when

    def read(self, cid_text, path=''):
        if cid_text in self.erased:
            raise Refused('erased', f'Erased on {self.erased[cid_text]}: {cid_text}')
        if not self.holds(cid_text):
            raise Refused('absent', f'Not held: {cid_text}')
        try:
            return walk(self.blocks, cid_text, [p for p in path.split('/') if p])
        except KeyError:
            raise Refused('absent', f'Nothing at {path!r} under {cid_text}')

    def search(self, query, mode=None, limit=None, within=None):
        """Where query is found in the files the ledger enrols, over the
        blocks held: hits in the archive's order, by path then line, each
        naming its file as a sealed item's links do. A file whose bytes are
        erased gives no hit, nor does one that is not UTF-8. Refused as
        'absent' by a keeper given no modes, and for a within the ledger does
        not enrol; as 'mode' for a mode not in modes."""
        if not self.modes:
            raise Refused('absent', 'This keeper does not search')
        cids = self.cids()
        entries, _, _, _, collections, items = self._state(self.events)
        chosen = searching.beneath(cids, within) if within is not None else (lambda path: True)

        def read(given):
            return lambda: walk(self.blocks, given, [])
        sources = [(searching.reference(path, cids, items, collections), read(cids[path]))
                   for path in searching.by_path(entries)
                   if path in cids and cids[path] not in self.erased and chosen(path)]
        return searching.found(sources, query, mode, limit, self.modes)


def walk(blocks, cid_text, parts):
    """The bytes at parts beneath the block cid_text of blocks; KeyError if
    there is nothing there, or what is there is a directory."""
    block = blocks[cid_text]
    if cid.codec(cid_text) != cid.DAG_PB:
        if parts:
            raise KeyError(parts[0])
        return block
    links, data = cid.parse(block)
    if data[:2] == b'\x08\x01':
        if not parts:
            raise KeyError('a directory')
        for child, name, _ in links:
            if name == parts[0].encode():
                return walk(blocks, cid.text(child), parts[1:])
        raise KeyError(parts[0])
    if parts:
        raise KeyError(parts[0])
    return b''.join(walk(blocks, cid.text(child), []) for child, _, _ in links)


# --------------------------------------------------------------------- wire

STATUS = {'chain': 409, 'absent': 404, 'erased': 410, 'size': 413, 'access': 403, 'version': 422, 'mode': 422}
KIND = {401: 'access', 403: 'access', 404: 'absent', 409: 'chain', 410: 'erased', 413: 'size'}
JSON, BYTES = 'application/json', 'application/octet-stream'


def multipart(parts):
    """The body and content type of parts, each (name, bytes), written one way:
    the boundary is taken from the bytes, so equal parts are equal bodies."""
    boundary = 'pos-' + sha(b''.join(data for _, data in parts))
    body = b''.join(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
                    + data + b'\r\n' for name, data in parts) + f'--{boundary}--\r\n'.encode()
    return body, f'multipart/form-data; boundary={boundary}'


def parts_of(body, content_type):
    """The (name, bytes) parts of a multipart/form-data body, as multipart writes one."""
    match = re.fullmatch(r'multipart/form-data; boundary=([A-Za-z0-9\'()+_,./:=?-]{1,70})', content_type or '')
    if not match:
        raise Refused('request', 'Expected multipart/form-data with a boundary')
    delimiter = b'--' + match[1].encode()
    if not body.startswith(delimiter + b'\r\n') or not body.endswith(delimiter + b'--\r\n'):
        raise Refused('request', 'Not a multipart body')
    parts = []
    for section in body[len(delimiter) + 2:-len(delimiter) - 4].split(delimiter + b'\r\n'):
        head, separator, data = section.partition(b'\r\n\r\n')
        name = re.fullmatch(rb'Content-Disposition: form-data; name="([^"\r\n]*)"', head)
        if not separator or not name or not data.endswith(b'\r\n'):
            raise Refused('request', 'Not a multipart part')
        parts.append((name[1].decode(), data[:-2]))
    return parts


def query_of(query):
    """The parameters of a URL's query, {name: value}, each percent-decoded:
    a plus is a plus, as the protocol encodes a space as %20."""
    parameters = {}
    for pair in query.split('&') if query else ():
        name, _, value = pair.partition('=')
        parameters[urllib.parse.unquote(name)] = urllib.parse.unquote(value)
    return parameters


def handle(keeper, method, path, headers, body):
    """Answer one request of the wire against keeper: (status, content type, body).
    path is the request's, below the ledger's base URL, with its query."""
    try:
        path, _, query = path.partition('?')
        event = re.fullmatch(r'/events/([1-9][0-9]*)', path)
        read = re.fullmatch(r'/ipfs/(b[a-z2-7]+)(?:/(.*))?', path)
        block = re.fullmatch(r'/blocks/(b[a-z2-7]+)', path)
        if method == 'GET' and path in ('', '/'):
            return 200, JSON, encoded(keeper.describe())
        if method in ('POST', 'PUT') and (path == '/blocks' or block) and 2 not in keeper.protocols:
            raise Refused('version', f'Blocks are put in version 2; this keeper serves {list(keeper.protocols)}')
        if method == 'POST' and path == '/blocks':
            try:
                cids = json.loads(body or b'')
            except ValueError:
                raise Refused('request', 'Expected a JSON array of CIDs')
            return 200, JSON, encoded(dict(missing=keeper.held(cids)))
        if method == 'PUT' and block:
            return (201 if keeper.put(block[1], body or b'') else 200), JSON, encoded({})
        if method == 'GET' and event:
            return 200, BYTES, keeper.event(int(event[1]))
        if method == 'GET' and read:
            return 200, BYTES, keeper.read(read[1], urllib.parse.unquote(read[2] or ''))
        if method == 'GET' and path == '/search':
            asked = query_of(query)
            limit = asked.get('limit')
            if limit is not None:
                if not limit.isdecimal() or int(limit) < 1:
                    raise Refused('request', f'limit is a positive integer: {limit}')
                limit = int(limit)
            hits = keeper.search(asked.get('q'), asked.get('mode'), limit, asked.get('within'))
            return 200, JSON, encoded(dict(hits=hits))
        if method == 'POST' and path == '/events':
            kinds = [v for k, v in headers.items() if k.lower() == 'content-type']
            parts = parts_of(body or b'', kinds[0] if kinds else None)
            names = [name for name, _ in parts]
            if names[:3] != ['name', 'event', 'claims'] or len(set(names)) != len(names):
                raise Refused('request', 'Expected the parts name, event and claims, '
                                         'then later events by name and files by CID')
            # After claims a part is a later event, named as a ledger file
            # is, or a file, named by its CID; the two cannot be confused.
            later = [part for part in parts[3:] if ai.EVENT_NAME.fullmatch(part[0])]
            if later != parts[3:3 + len(later)]:
                raise Refused('request', 'Later events come before the files')
            try:
                claims = json.loads(parts[2][1])
            except ValueError:
                claims = None
            if not isinstance(claims, dict) or not all(isinstance(v, str) for v in claims.values()):
                raise Refused('request', 'claims is an object of strings')
            before = keeper.describe()['events']
            after = keeper.append(parts[0][1].decode(), parts[1][1], dict(parts[3 + len(later):]), claims, later)
            return (201 if after['events'] > before else 200), JSON, encoded(after)
        raise Refused('absent', f'Nothing answers {method} {path}')
    except Refused as refused:
        return (STATUS.get(refused.kind, 422), JSON,
                encoded(dict(refused=refused.kind, message=str(refused))))


def send(method, url, headers, body):
    """One HTTP exchange: (status, body). What HttpRemoteArchive sends with.
    A keeper that says nothing for SILENCE seconds, or goes away part way,
    is refused as 'remote'."""
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=SILENCE) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read()
    except OSError as error:
        raise Refused('remote', f'{url}: {getattr(error, "reason", None) or error}')


class HttpRemoteArchive:
    """RemoteArchive and search.ArchiveSearch over HTTP: the ledger's base
    URL, and a bearer token if the keeper wants one. Given no token, a request carries the one kept for
    the keeper by signing in, if there is one (signin). send is the exchange,
    replaced in tests."""

    def __init__(self, url, token=None, send=send):
        self.url, self.token, self.send = url.rstrip('/'), token, send

    def call(self, method, path, body=None, content_type=None, status_too=False):
        """The body the keeper answers with, or with status_too (status, body)."""
        token = self.token or signin.token_for(self.url)

        def exchange(token):
            headers = {}
            if token:
                headers['Authorization'] = f'Bearer {token}'
            if content_type:
                headers['Content-Type'] = content_type
            return self.send(method, self.url + path, headers, body)

        status, answer = exchange(token)
        if status == 401 and not self.token:
            # A keeper not seen before may take a token already kept: once.
            adopted = signin.adopt(self.url)
            if adopted:
                status, answer = exchange(adopted)
        if status in (200, 201):
            return (status, answer) if status_too else answer
        try:
            refusal = json.loads(answer)
            kind, message = refusal['refused'], refusal.get('message', '')
        except (ValueError, KeyError, TypeError):
            kind, message = KIND.get(status, 'remote'), f'{method} {path} answered {status}'
        if status == 401 and not self.token:
            message = f'Not signed in to this keeper; sign in with: sign-in {self.url}'
        raise Refused(kind, message)

    def describe(self):
        return json.loads(self.call('GET', '/'))

    def event(self, number):
        return self.call('GET', f'/events/{number}')

    def held(self, cids):
        return json.loads(self.call('POST', '/blocks', encoded(list(cids)), JSON))['missing']

    def put(self, cid_text, data):
        return self.call('PUT', f'/blocks/{cid_text}', data, BYTES, status_too=True)[0] == 201

    def append(self, name, event, files, claims, following=()):
        body, content_type = multipart([('name', name.encode()), ('event', event),
                                        ('claims', encoded(dict(claims))), *following,
                                        *sorted(files.items())])
        return json.loads(self.call('POST', '/events', body, content_type))

    def read(self, cid_text, path=''):
        return self.call('GET', f'/ipfs/{cid_text}' + (f'/{urllib.parse.quote(path)}' if path else ''))

    def search(self, query, mode=None, limit=None, within=None):
        """The hits the keeper answers: q, then mode, limit and within where
        given, each percent-encoded but for RFC 3986's unreserved characters,
        as poslib sends them."""
        parameters = [('q', query), ('mode', mode), ('limit', limit), ('within', within)]
        asked = '&'.join(f'{name}={urllib.parse.quote(str(value), safe="")}'
                         for name, value in parameters if value is not None)
        return json.loads(self.call('GET', f'/search?{asked}'))['hits']


def server(keeper, host='127.0.0.1', port=0, token=None):
    """An HTTP server answering the wire from keeper, for trying a client
    against: not a deployment. With token, requests must bear it."""
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def answer(self):
            length = int(self.headers.get('Content-Length') or 0)
            if token and self.headers.get('Authorization') != f'Bearer {token}':
                status, kind, body = 401, JSON, encoded(dict(refused='access', message='No such token'))
            else:
                status, kind, body = handle(keeper, self.command, self.path.rstrip('/') if self.path != '/' else '/',
                                            dict(self.headers.items()), self.rfile.read(length))
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = answer

    return http.server.ThreadingHTTPServer((host, port), Handler)
