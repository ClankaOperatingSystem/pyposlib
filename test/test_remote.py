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
"""The remote archive protocol: the client port over its wire, the keeper,
and poslib's tapes in fixtures/remote/, which hold both to one exchange."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import unittest

from fixtures import HERE, POSLIB, fixtures, write, writable
from pyposlib import archive_integrity as ai
from pyposlib import cid
from pyposlib import remote
from pyposlib import seal

LEDGER_ID = '0f1e2d3c-4b5a-4968-8778-a6b5c4d3e2f1'
EMACS = os.environ.get('EMACS', 'emacs')


def over(keeper, base='https://keeper.example/ledger'):
    """A client whose exchanges go straight to keeper's side of the wire."""
    def send(method, url, headers, body):
        assert url.startswith(base), url
        status, _, answer = remote.handle(keeper, method, url[len(base):], headers, body)
        return status, answer
    return remote.HttpRemoteArchive(base, send=send)


class Scope:
    """A temporary scope whose seals give real events to send."""

    def __enter__(self):
        self.dir = Path(tempfile.mkdtemp(prefix='pyposlib-remote-')).resolve()
        self.scope = self.dir / 'scope'
        (self.scope / 'archives').mkdir(parents=True)
        return self

    def __exit__(self, *_):
        writable(self.dir)
        shutil.rmtree(self.dir)

    def seal(self, item, files, empty=()):
        """Seal item, files by path and empty directories, and return what
        its event's append sends: (name, bytes, files by CID)."""
        for path, data in files.items():
            write(self.scope / item / path, data)
        for path in empty:
            (self.scope / item / path).mkdir(parents=True)
        plan = seal.plan(self.scope / item, self.scope / 'archives' / item, LEDGER_ID)
        event, _ = seal.apply(plan, ai.sha(ai.encoded(plan)))
        return self.sent(event)

    def sent(self, event):
        data = event.read_bytes()
        add = json.loads(data).get('add', {})
        return event.name, data, {entry['cid']: (self.scope / 'archives' / path).read_bytes()
                                  for path, entry in add.items()}

    def history(self):
        return ai.history(self.scope / 'archives')


def refusal(operation):
    try:
        operation()
    except ai.Refused as refused:
        return refused.kind
    return None


class Protocol(unittest.TestCase):
    def test_a_seal_is_appended_and_read_back(self):
        """Each event with its files; the keeper's head and root are the
        ledger's, and what was sealed reads back by CID and by path."""
        keeper = remote.Keeper()
        client = over(keeper)
        self.assertEqual(dict(protocol=1, ledger_id=None, head=None, events=0, root=None, erased=[]),
                         client.describe())
        with Scope() as scope:
            first = scope.seal('first', {'a.txt': b'first'})
            big = bytes(i % 251 for i in range(cid.CHUNK_SIZE + 1))
            second = scope.seal('second', {'b.txt': b'second', 'sub/c.txt': b'c', 'big': big},
                                empty=['hollow'])
            self.assertEqual(1, client.append(*first, {})['events'])
            described = client.append(*second, dict(head='abc', dirty='false'))
            _, head, events, _, root, _, _, _ = scope.history()
            self.assertEqual((LEDGER_ID, head, events, root),
                             tuple(described[k] for k in ('ledger_id', 'head', 'events', 'root')))
            self.assertEqual(dict(head='abc', dirty='false'), keeper.claims[-1])
            folded = ai.fold_cids(scope.scope / 'archives')
            self.assertEqual(first[1], client.event(1))
            self.assertEqual(b'first', client.read(folded['first/a.txt']))
            self.assertEqual(b'c', client.read(folded['second'], 'sub/c.txt'))
            self.assertEqual(b'second', client.read(root, 'second/b.txt'))
            self.assertEqual(big, client.read(root, 'second/big'))
            self.assertEqual(second[1], client.read(head))
            for absent in (lambda: client.event(3), lambda: client.read(folded['second']),
                           lambda: client.read(root, 'second/hollow'), lambda: client.read(root, 'nowhere'),
                           lambda: client.read(cid.cid_bytes(b'never sealed'))):
                self.assertEqual('absent', refusal(absent))

    def test_an_event_again_changes_nothing_and_another_is_refused(self):
        with Scope() as scope:
            first = scope.seal('first', {'a.txt': b'first'})
            second = scope.seal('second', {'b.txt': b'second'})
            client = over(remote.Keeper())
            self.assertEqual('chain', refusal(lambda: client.append(*second, {})))
            once = client.append(*first, {})
            self.assertEqual(once, client.append(*first, {}))
            other = ai.block(dict(json.loads(first[1]), item='other'))
            self.assertEqual('chain', refusal(
                lambda: client.append(f'00000001-{ai.event_cid(other)}.json', other, first[2], {})))

    def test_what_is_sent_is_verified(self):
        """Bytes under a CID not theirs, a file not sent, a root the ledger
        does not fold to, an event that is not a block or not its name's,
        and another ledger's event: each refused by its kind."""
        with Scope() as scope:
            name, event, files = scope.seal('first', {'a.txt': b'first'})
            value = json.loads(event)

            def named(data):
                return f'00000001-{ai.event_cid(data)}.json'
            wrong_root = ai.block(dict(value, root=cid.cid_bytes(b'x')))
            newline = event + b'\n'
            cases = {
                'entry': [lambda c: c.append(name, event, {k: b'other' for k in files}, {}),
                          lambda c: c.append(name, event, {}, {})],
                'root': [lambda c: c.append(named(wrong_root), wrong_root, files, {})],
                'encoding': [lambda c: c.append(named(newline), newline, files, {})],
                'sequence': [lambda c: c.append(named(b'{}'), event, files, {}),
                             lambda c: c.append('first.json', event, files, {})],
            }
            for kind, attempts in cases.items():
                for attempt in attempts:
                    self.assertEqual(kind, refusal(lambda: attempt(over(remote.Keeper()))))
            self.assertEqual('identity', refusal(
                lambda: over(remote.Keeper('1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d')).append(name, event, files, {})))

    def test_a_schema_2_ledger_is_replayed_then_converted(self):
        """Its old events go bare, the conversion event with every file the
        ledger enrols; the keeper then folds to the root the ledger recorded."""
        with Scope() as scope:
            archive = scope.scope / 'archives'
            for item, files in (('a', {'x.txt': b'x'}), ('b', {'y.txt': b'y'})):
                for path, data in files.items():
                    write(archive / item / path, data)
                add = {f'{item}/{p}': seal.entry(archive / item / p) for p in files}
                head, events = ai.history(archive)[1:3]
                data = ai.encoded(dict(schema=2, previous=head, ledger_id=LEDGER_ID, item=item, add=add,
                                       root=cid.cid_directory(archive), collections=[]))
                ai.new_file(scope.scope / ai.INTEGRITY / 'ledger' / f'{events + 1:08}-{ai.sha(data)}.json', data)
            seal.convert(scope.scope)
            entries, head, _, events, root, _, _, _ = scope.history()
            client = over(remote.Keeper())
            every = {e['cid']: (archive / p).read_bytes() for p, e in entries.items()}
            for event in events[:-1]:
                client.append(event.name, event.read_bytes(), {}, {})
            self.assertEqual('entry', refusal(
                lambda: client.append(events[-1].name, events[-1].read_bytes(), {}, {})))
            described = client.append(events[-1].name, events[-1].read_bytes(), every, {})
            self.assertEqual((head, root), (described['head'], described['root']))
            self.assertEqual(b'y', client.read(root, 'b/y.txt'))

    def test_an_erased_block_is_gone_and_said_to_be(self):
        with Scope() as scope:
            name, event, files = scope.seal('first', {'a.txt': b'first'})
            keeper = remote.Keeper()
            client = over(keeper)
            client.append(name, event, files, {})
            given = next(iter(files))
            keeper.erase(given, '2026-10-01')
            self.assertEqual('erased', refusal(lambda: client.read(given)))
            self.assertEqual([given], client.describe()['erased'])
            self.assertEqual(event, client.event(1))

    def test_the_wire_is_http(self):
        """A keeper behind a real socket: the client's own exchange, a
        token wanted, and a keeper nowhere."""
        with Scope() as scope:
            name, event, files = scope.seal('first', {'a.txt': b'first'})
            served = remote.server(remote.Keeper(), token='let-me-in')
            thread = threading.Thread(target=served.serve_forever, daemon=True)
            thread.start()
            try:
                url = f'http://127.0.0.1:{served.server_address[1]}'
                client = remote.HttpRemoteArchive(url, 'let-me-in')
                self.assertEqual(1, client.append(name, event, files, {})['events'])
                self.assertEqual(b'first', client.read(next(iter(files))))
                self.assertEqual(event, client.event(1))
                self.assertEqual('absent', refusal(lambda: client.event(2)))
                self.assertEqual('access', refusal(remote.HttpRemoteArchive(url, 'wrong').describe))
            finally:
                served.shutdown()
                served.server_close()
            self.assertEqual('remote', refusal(remote.HttpRemoteArchive(url, 'let-me-in').describe))


@unittest.skipUnless(shutil.which(EMACS), 'needs Emacs')
class Poslib(unittest.TestCase):
    def test_poslib_s_client_reaches_a_keeper_over_http(self):
        """poslib's own HTTP exchange against a keeper on a socket: an event
        appended with its file, described, fetched and read back by path,
        an event that is not there, and a caller without the token."""
        with Scope() as scope:
            name, event, files = scope.seal('first', {'sub/c é.txt': 'été'.encode()})
            keeper = remote.Keeper()
            served = remote.server(keeper, token='let-me-in')
            threading.Thread(target=served.serve_forever, daemon=True).start()
            request, answer = scope.dir / 'request.json', scope.dir / 'answer.json'
            folded = ai.fold_cids(scope.scope / 'archives')
            request.write_text(json.dumps(dict(
                url=f'http://127.0.0.1:{served.server_address[1]}', token='let-me-in', name=name,
                event=event.decode(), files={k: v.decode() for k, v in files.items()},
                claims=dict(tool='poslib'), cid=folded['first'], path='sub/c é.txt')), encoding='utf-8')
            try:
                result = subprocess.run([EMACS, '-Q', '--batch', '-L', str(POSLIB / 'lisp'),
                                         '-l', str(HERE / 'remote.el'), str(request), str(answer)],
                                        capture_output=True, text=True)
            finally:
                served.shutdown()
                served.server_close()
            self.assertEqual(0, result.returncode, result.stderr)
            got = json.loads(answer.read_bytes())
            self.assertEqual(keeper.describe(), got['appended'])
            self.assertEqual(keeper.describe(), got['described'])
            self.assertEqual(dict(tool='poslib'), keeper.claims[0])
            self.assertEqual((event.decode(), 'été'), (got['event'], got['read']))
            self.assertEqual((dict(refused='absent'), dict(refused='access')),
                             (got['absent'], got['stranger']))


def call(client, spec):
    """Make the call a tape's exchange describes; its result as the tape writes it."""
    operation = spec['operation']
    if operation == 'describe':
        return client.describe()
    if operation == 'event':
        return dict(bytes=client.event(spec['number']).decode())
    if operation == 'read':
        return dict(bytes=client.read(spec['cid'], spec.get('path', '')).decode())
    return client.append(spec['name'], spec['event'].encode(),
                         {k: v.encode() for k, v in spec['files'].items()}, spec['claims'])


class Tapes(unittest.TestCase):
    def test_the_client_makes_each_tape_s_requests(self):
        """Every tape in fixtures/remote/: for each call the client sends the
        request recorded, byte for byte, and makes of the response the
        result or the refusal recorded."""
        for name, tape in fixtures('remote'):
            for index, exchange in enumerate(tape['exchanges']):
                with self.subTest(f'{name} {index}'):
                    sent = {}

                    def send(method, url, headers, body, exchange=exchange, sent=sent):
                        sent.update(method=method, path=url[len(tape['url']):],
                                    authorization=headers.get('Authorization'))
                        if body is not None:
                            sent.update(content_type=headers['Content-Type'], body_sha256=ai.sha(body))
                        return exchange['response']['status'], exchange['response']['body'].encode()
                    client = remote.HttpRemoteArchive(tape['url'], tape['token'], send)
                    try:
                        got = dict(result=call(client, exchange['call']))
                    except ai.Refused as refused:
                        got = dict(refused=refused.kind)
                    self.assertEqual(exchange['request'], sent)
                    self.assertEqual({k: exchange[k] for k in ('result', 'refused') if k in exchange}, got)

    def test_the_keeper_gives_each_tape_s_responses(self):
        """Every tape, its requests made in order of one keeper: the status
        recorded, and the body recorded, or for a refusal its kind."""
        for name, tape in fixtures('remote'):
            keeper = remote.Keeper()
            for index, exchange in enumerate(tape['exchanges']):
                with self.subTest(f'{name} {index}'):
                    answered = {}

                    def send(method, url, headers, body, answered=answered):
                        status, _, answer = remote.handle(keeper, method, url[len(tape['url']):], headers, body)
                        answered.update(status=status, body=answer)
                        return status, answer
                    try:
                        call(remote.HttpRemoteArchive(tape['url'], tape['token'], send), exchange['call'])
                    except ai.Refused:
                        pass
                    expected = exchange['response']
                    self.assertEqual(expected['status'], answered['status'])
                    if 'refused' in exchange:
                        self.assertEqual(exchange['refused'], json.loads(answered['body'])['refused'])
                    else:
                        self.assertEqual(expected['body'].encode(), answered['body'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
