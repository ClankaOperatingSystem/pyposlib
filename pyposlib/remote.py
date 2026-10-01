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
from it, by a keeper reached at a URL. Four operations pass between them.

- RemoteArchive: the port a sealing client calls, a typing.Protocol.
- HttpRemoteArchive: that port over HTTP, the protocol's wire.
- Keeper: the keeping side, in memory: it verifies what it is sent as
  the protocol requires, and is what a server wraps around its storage.
- handle: the wire's keeping side, one request to one response.
- server: a keeper behind handle on a local port, for trying a client.
"""
import http.server
import json
import re
from typing import Mapping, Protocol
import urllib.error
import urllib.parse
import urllib.request

from . import archive_integrity as ai
from .archive_integrity import Refused, encoded, sha
from . import cid

VERSION = 1


class RemoteArchive(Protocol):
    """A ledger's archive, kept away from it: the four operations of the
    protocol. Each raises Refused, of the kind the keeper names."""

    def describe(self) -> dict:
        """What the keeper holds of the ledger: protocol, ledger_id, head,
        events, root and erased."""
        ...

    def event(self, number: int) -> bytes:
        """The bytes of event number, as the ledger's file holds them."""
        ...

    def append(self, name: str, event: bytes, files: Mapping[str, bytes],
               claims: Mapping[str, str]) -> dict:
        """Append the event of bytes event, the ledger file name names, with
        files by their CIDs and the client's claims; the description after.
        The same event at the same number again changes nothing."""
        ...

    def read(self, cid_text: str, path: str = '') -> bytes:
        """The bytes of the block cid_text, or of the file at path beneath
        it when it is a directory."""
        ...


# ------------------------------------------------------------------ keeping

class Keeper:
    """The keeping side of the protocol, in memory.

    It keeps a ledger's events and the blocks of what they enrol, and
    takes nothing on trust: an event must be the next of a valid chain,
    a file's bytes must hash to the CID they are sent under, and once
    the ledger is of schema 3 its fold must give the event's root with
    every enrolled file held."""

    def __init__(self, ledger_id=None):
        self.ledger_id = ledger_id
        self.events, self.claims, self.blocks, self.erased = [], [], {}, {}
        self._cids = {}

    def _state(self, events):
        entries, head, root, _, _, empty = ai.chain(events)
        return entries, head, root, empty

    def describe(self):
        head, root = None, None
        if self.events:
            _, head, root, _ = self._state(self.events)
        return dict(protocol=VERSION, ledger_id=self.ledger_id, head=head, events=len(self.events),
                    root=root, erased=sorted(self.erased))

    def event(self, number):
        if not 1 <= number <= len(self.events):
            raise Refused('absent', f'No event {number}')
        return self.events[number - 1][1]

    def append(self, name, event, files, claims):
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
        for given, data in files.items():
            if not ai.is_cid(given) or cid.cid_bytes(data) != given:
                raise Refused('entry', f'Bytes are not those of the CID they were sent under: {given}')
        entries, head, root, empty = self._state([*self.events, (name, event)])
        value = json.loads(event)
        if self.ledger_id not in (None, value.get('ledger_id')):
            raise Refused('identity', 'The event is another ledger\'s')
        cids = {}
        if value['schema'] == 3:
            blocks = {}
            cids = ai.fold(entries, empty, blocks)
            if cids['.'] != root:
                raise Refused('root', 'The ledger does not fold to the event\'s root')
            held = {**self.blocks, **files}
            for path, entry in entries.items():
                if entry['cid'] not in held and not any(part.startswith('.') for part in path.split('/')):
                    raise Refused('entry', f'Bytes not held for {path}')
            self.blocks.update(blocks)
        for data in files.values():
            self.blocks.update(cid.blocks(data))
        self.blocks[ai.event_cid(ai.as_block(event))] = ai.as_block(event)
        self.events.append((name, event))
        self.claims.append(dict(claims))
        self.ledger_id = self.ledger_id or value.get('ledger_id')
        self._cids = cids
        return self.describe()

    def holds(self, cid_text):
        """Whether the ledger enrols cid_text: a file, a directory or an event."""
        return (cid_text in self._cids.values()
                or any(ai.event_cid(ai.as_block(data)) == cid_text for _, data in self.events))

    def erase(self, cid_text, when):
        """Forget the bytes of cid_text, and say when: the ledger is unchanged."""
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

STATUS = {'chain': 409, 'absent': 404, 'erased': 410, 'size': 413, 'access': 403}
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


def handle(keeper, method, path, headers, body):
    """Answer one request of the wire against keeper: (status, content type, body).
    path is the request's, below the ledger's base URL."""
    try:
        event = re.fullmatch(r'/events/([1-9][0-9]*)', path)
        read = re.fullmatch(r'/ipfs/(b[a-z2-7]+)(?:/(.*))?', path)
        if method == 'GET' and path in ('', '/'):
            return 200, JSON, encoded(keeper.describe())
        if method == 'GET' and event:
            return 200, BYTES, keeper.event(int(event[1]))
        if method == 'GET' and read:
            return 200, BYTES, keeper.read(read[1], urllib.parse.unquote(read[2] or ''))
        if method == 'POST' and path == '/events':
            kinds = [v for k, v in headers.items() if k.lower() == 'content-type']
            parts = parts_of(body or b'', kinds[0] if kinds else None)
            names = [name for name, _ in parts]
            if names[:3] != ['name', 'event', 'claims'] or len(set(names)) != len(names):
                raise Refused('request', 'Expected the parts name, event and claims, then files by CID')
            try:
                claims = json.loads(parts[2][1])
            except ValueError:
                claims = None
            if not isinstance(claims, dict) or not all(isinstance(v, str) for v in claims.values()):
                raise Refused('request', 'claims is an object of strings')
            before = keeper.describe()['events']
            after = keeper.append(parts[0][1].decode(), parts[1][1], dict(parts[3:]), claims)
            return (201 if after['events'] > before else 200), JSON, encoded(after)
        raise Refused('absent', f'Nothing answers {method} {path}')
    except Refused as refused:
        return (STATUS.get(refused.kind, 422), JSON,
                encoded(dict(refused=refused.kind, message=str(refused))))


def send(method, url, headers, body):
    """One HTTP exchange: (status, body). What HttpRemoteArchive sends with."""
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read()
    except urllib.error.URLError as error:
        raise Refused('remote', f'{url}: {error.reason}')


class HttpRemoteArchive:
    """RemoteArchive over HTTP: the ledger's base URL, and a bearer token if
    the keeper wants one. send is the exchange, replaced in tests."""

    def __init__(self, url, token=None, send=send):
        self.url, self.token, self.send = url.rstrip('/'), token, send

    def call(self, method, path, body=None, content_type=None):
        headers = {}
        if self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        if content_type:
            headers['Content-Type'] = content_type
        status, answer = self.send(method, self.url + path, headers, body)
        if status in (200, 201):
            return answer
        try:
            refusal = json.loads(answer)
            kind, message = refusal['refused'], refusal.get('message', '')
        except (ValueError, KeyError, TypeError):
            kind, message = KIND.get(status, 'remote'), f'{method} {path} answered {status}'
        raise Refused(kind, message)

    def describe(self):
        return json.loads(self.call('GET', '/'))

    def event(self, number):
        return self.call('GET', f'/events/{number}')

    def append(self, name, event, files, claims):
        body, content_type = multipart([('name', name.encode()), ('event', event),
                                        ('claims', encoded(dict(claims))), *sorted(files.items())])
        return json.loads(self.call('POST', '/events', body, content_type))

    def read(self, cid_text, path=''):
        return self.call('GET', f'/ipfs/{cid_text}' + (f'/{urllib.parse.quote(path)}' if path else ''))


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
