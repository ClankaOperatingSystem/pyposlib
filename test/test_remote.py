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
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from fixtures import HERE, POSLIB, fixtures, write, writable
from pyposlib import archive_integrity as ai
from pyposlib import cid
from pyposlib import remote
from pyposlib import seal
from pyposlib import search

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


def begun(unnamed, named=1, ledger_id=LEDGER_ID, text='old'):
    """The first events of a ledger begun before events carried a
    ledger_id, as (name, bytes): unnamed schema 1 events that name no
    ledger, then named that name ledger_id. text tells one such ledger
    from another."""
    events, previous = [], None
    for number in range(1, unnamed + named + 1):
        data = f'{text} {number}'.encode()
        value = dict(schema=1, previous=previous,
                     add={f'{number}.md': dict(mode=0o444, sha256=ai.sha(data), size=len(data))})
        if number > unnamed:
            value['ledger_id'] = ledger_id
        event = ai.encoded(value)
        previous = ai.sha(event)
        events.append((f'{number:08}-{previous}.json', event))
    return events


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
        self.assertEqual(dict(protocol=1, protocols=[1, 2], ledger_id=None, head=None, events=0, root=None,
                              erased=[], search=dict(modes=['literal'])),
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

    def test_under_version_2_the_blocks_are_put_before_the_event(self):
        """The client asks which blocks the keeper lacks, puts those, and
        appends the event alone; a block put again is not new; what was
        sealed reads back whole."""
        keeper = remote.Keeper()
        client = over(keeper)
        with Scope() as scope:
            big = bytes(i % 251 for i in range(2 * cid.CHUNK_SIZE + 1))
            name, event, files = scope.seal('first', {'a.txt': b'first', 'big': big})
            blocks = {}
            for data in files.values():
                blocks.update(cid.blocks(data))
            cids = sorted(blocks)
            self.assertEqual(5, len(cids))  # a leaf, three leaves and the node over them
            self.assertEqual(cids, client.held(cids))
            self.assertEqual('entry', refusal(lambda: client.append(name, event, {}, {})))
            self.assertEqual([True] * 5, [client.put(c, blocks[c]) for c in cids])
            self.assertFalse(client.put(cids[0], blocks[cids[0]]))
            self.assertEqual([], client.held(cids))
            self.assertEqual(1, client.append(name, event, {}, {})['events'])
            folded = ai.fold_cids(scope.scope / 'archives')
            self.assertEqual(big, client.read(folded['first/big']))
            self.assertEqual(b'first', client.read(folded['first/a.txt']))

    def test_an_entry_is_held_only_with_every_block_beneath_it(self):
        """A file of several chunks is held when its node and all its leaves
        are: the node alone is not enough."""
        keeper = remote.Keeper()
        client = over(keeper)
        with Scope() as scope:
            big = bytes(i % 251 for i in range(2 * cid.CHUNK_SIZE + 1))
            name, event, files = scope.seal('first', {'big': big})
            blocks = cid.blocks(big)
            root = cid.cid_bytes(big)
            client.put(root, blocks[root])
            self.assertEqual('entry', refusal(lambda: client.append(name, event, {}, {})))
            for c, block in blocks.items():
                client.put(c, block)
            self.assertEqual(1, client.append(name, event, {}, {})['events'])

    def test_what_is_put_is_verified(self):
        keeper = remote.Keeper()
        client = over(keeper)
        leaf = cid.cid_bytes(b'hello')
        self.assertEqual('entry', refusal(lambda: client.put(leaf, b'other bytes')))
        self.assertEqual('size', refusal(lambda: client.put(leaf, bytes(remote.BLOCK_LIMIT + 1))))
        self.assertEqual('request', refusal(lambda: client.held(['not a cid'])))
        self.assertEqual(422, remote.handle(keeper, 'POST', '/blocks', {}, b'{"not": "an array"}')[0])
        self.assertEqual([leaf], client.held([leaf]))

    def test_a_keeper_of_version_2_alone_takes_no_file_inside_an_append(self):
        keeper = remote.Keeper(protocols=(2,))
        client = over(keeper)
        self.assertEqual((2, [2]), (client.describe()['protocol'], client.describe()['protocols']))
        with Scope() as scope:
            name, event, files = scope.seal('first', {'a.txt': b'first'})
            self.assertEqual('version', refusal(lambda: client.append(name, event, files, {})))
            self.assertEqual(0, keeper.describe()['events'])

    def test_a_keeper_of_version_1_alone_has_no_blocks_and_says_so(self):
        keeper = remote.Keeper(protocols=(1,))
        client = over(keeper)
        self.assertNotIn('protocols', client.describe())
        leaf = cid.cid_bytes(b'hello')
        self.assertEqual('version', refusal(lambda: client.put(leaf, b'hello')))
        self.assertEqual('version', refusal(lambda: client.held([leaf])))

    def test_the_version_spoken_is_the_highest_shared(self):
        self.assertEqual(1, remote.version_of(dict(protocol=1)))
        self.assertEqual(2, remote.version_of(dict(protocol=1, protocols=[1, 2])))
        self.assertEqual(2, remote.version_of(dict(protocol=2, protocols=[2])))
        self.assertEqual(1, remote.version_of(dict(protocol=1, protocols=[1])))
        self.assertEqual('version', refusal(lambda: remote.version_of(dict(protocol=3, protocols=[3]))))

    def test_a_retiring_version_is_announced_with_its_date(self):
        keeper = remote.Keeper(retiring={1: '2027-01-31'})
        self.assertEqual({'1': '2027-01-31'}, over(keeper).describe()['retiring'])
        self.assertNotIn('retiring', remote.Keeper().describe())

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

    def test_a_keeper_is_given_what_a_server_already_holds(self):
        """Another keeper over the same events and blocks answers as the
        first did, and a later seal asks its store only for what it adds."""
        class Store(dict):
            def __init__(self):
                super().__init__()
                self.asked, self.written = [], []

            def __contains__(self, key):
                self.asked.append(key)
                return super().__contains__(key)

            def __setitem__(self, key, value):
                self.written.append(key)
                super().__setitem__(key, value)

        with Scope() as scope:
            first = scope.seal('first', {'a.txt': b'first', 'sub/b.txt': b'b'})
            second = scope.seal('second', {'c.txt': b'second'})
            store = Store()
            keeper = remote.Keeper(blocks=store)
            over(keeper).append(*first, {})
            again = remote.Keeper(LEDGER_ID, keeper.events, store)
            folded = ai.fold_cids(scope.scope / 'archives')
            self.assertEqual(keeper.describe(), again.describe())
            self.assertEqual(b'b', over(again).read(folded['first'], 'sub/b.txt'))
            store.asked.clear()
            store.written.clear()
            over(again).append(*second, {})
            self.assertEqual([], store.asked)
            self.assertEqual({folded['second/c.txt'], folded['second'], folded['.'],
                              again.describe()['head']}, set(store.written))
            self.assertEqual(b'second', over(remote.Keeper(LEDGER_ID, again.events, store)).read(
                folded['.'], 'second/c.txt'))

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
                self.assertEqual([dict(ref=f'ipfs://{ai.fold_cids(scope.scope / "archives")["first"]}/a.txt',
                                       range=dict(lines=[1, 1]), passage='first')],
                                 client.search('irs'))
                self.assertEqual('absent', refusal(lambda: client.event(2)))
                self.assertEqual('access', refusal(remote.HttpRemoteArchive(url, 'wrong').describe))
            finally:
                served.shutdown()
                served.server_close()
            self.assertEqual('remote', refusal(remote.HttpRemoteArchive(url, 'let-me-in').describe))

    def test_a_keeper_that_says_nothing_is_given_up_on(self):
        """A socket that takes a request and never answers it: the client
        waits as long as it is told to and no longer."""
        listening = socket.create_server(('127.0.0.1', 0))
        patience, remote.SILENCE = remote.SILENCE, 0.3
        try:
            url = f'http://127.0.0.1:{listening.getsockname()[1]}'
            began = time.monotonic()
            self.assertEqual('remote', refusal(remote.HttpRemoteArchive(url, 'let-me-in').describe))
            self.assertLess(time.monotonic() - began, 5)
        finally:
            remote.SILENCE = patience
            listening.close()


OTHER_ID = '1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d'


class Identity(unittest.TestCase):
    """Whose an event is: a keeper told which ledger it keeps takes no
    event of another, and an event that names no ledger only with the
    events after it that show whose it is."""

    def test_events_name_the_ledger_of_the_last_that_has_one(self):
        events = begun(2, 2)
        self.assertEqual([None, None, LEDGER_ID, LEDGER_ID],
                         [remote.named(events[:count]) for count in range(1, 5)])
        self.assertIsNone(remote.named([]))

    def test_an_event_that_names_no_ledger_is_followed_to_the_first_that_does(self):
        """Each of the first events that name none is followed by the rest
        of them and the first that names the ledger, and by no more; an
        event that names the ledger, or comes after one, by nothing."""
        events = begun(3, 2)
        self.assertEqual([events[1:4], events[2:4], events[3:4], [], []],
                         [remote.following(events, number) for number in range(1, 6)])

    def test_a_ledger_no_event_names_is_followed_by_nothing(self):
        events = begun(3, 0)
        self.assertEqual([[], [], []], [remote.following(events, number) for number in range(1, 4)])

    def test_first_events_that_name_no_ledger_are_taken_with_those_after_them(self):
        """A server makes a keeper for each request, of the ledger it keeps
        and the events it holds. Each event is appended alone: what follows
        it is read and not kept."""
        events, held = begun(3, 2), []
        for number, (name, event) in enumerate(events, 1):
            keeper = remote.Keeper(LEDGER_ID, held)
            described = over(keeper).append(name, event, {}, {}, remote.following(events, number))
            self.assertEqual((LEDGER_ID, number, name[9:-5]),
                             (described['ledger_id'], described['events'], described['head']))
            held = keeper.events
        self.assertEqual(events, held)

    def test_an_event_that_names_no_ledger_is_refused_unless_this_ledger_follows(self):
        """Sent alone; followed only by events that name none; followed to
        an event that names another ledger; followed by another ledger's
        events, which are no next events of this chain; and followed out of
        order. Nothing of a refused append is kept."""
        events = begun(2)
        another = begun(2, ledger_id=OTHER_ID)
        elsewhere = begun(2, text='other')
        self.assertEqual(events[:2], another[:2])
        cases = [('identity', []),
                 ('identity', events[1:2]),
                 ('identity', another[1:]),
                 ('chain', elsewhere[1:]),
                 ('sequence', events[2:] + events[1:2])]
        for kind, following in cases:
            with self.subTest(kind=kind, following=[name[:8] for name, _ in following]):
                keeper = remote.Keeper(LEDGER_ID)
                self.assertEqual(kind, refusal(lambda: over(keeper).append(*events[0], {}, {}, following)))
                self.assertEqual(([], {}), (keeper.events, keeper.blocks))

    def test_a_held_event_that_names_no_ledger_does_not_admit_another_ledger(self):
        """A keeper that holds first events of its ledger refuses the next,
        which names none either, when what follows names another."""
        events = begun(2)
        another = begun(2, ledger_id=OTHER_ID)
        keeper = remote.Keeper(LEDGER_ID)
        over(keeper).append(*events[0], {}, {}, events[1:])
        self.assertEqual('identity', refusal(lambda: over(keeper).append(*another[1], {}, {}, another[2:])))
        self.assertEqual(events[:1], keeper.events)

    def test_an_event_that_names_its_ledger_needs_nothing_after_it(self):
        """Its own, taken alone; another ledger's, refused whatever follows."""
        events = begun(0, 2)
        another = begun(0, 2, ledger_id=OTHER_ID)
        keeper = remote.Keeper(LEDGER_ID)
        self.assertEqual('identity', refusal(lambda: over(keeper).append(*another[0], {}, {}, events[1:])))
        self.assertEqual(1, over(keeper).append(*events[0], {}, {})['events'])

    def test_once_a_ledger_is_named_every_event_names_it(self):
        events = begun(1)
        value = dict(schema=1, previous=events[-1][0][9:-5], add={})
        unnamed = ai.encoded(value)
        keeper = remote.Keeper(LEDGER_ID)
        over(keeper).append(*events[0], {}, {}, events[1:])
        over(keeper).append(*events[1], {}, {})
        self.assertEqual('identity', refusal(
            lambda: over(keeper).append(f'00000003-{ai.sha(unnamed)}.json', unnamed, {}, {})))

    def test_a_keeper_told_no_ledger_keeps_the_first_it_is_sent(self):
        """It takes events that name none as they come, and is the
        ledger's from the first event that names one."""
        events = begun(2)
        keeper = remote.Keeper()
        client = over(keeper)
        self.assertEqual([None, None, LEDGER_ID],
                         [client.append(name, event, {}, {})['ledger_id'] for name, event in events])
        other = ai.encoded(dict(schema=1, previous=events[-1][0][9:-5], add={}, ledger_id=OTHER_ID))
        self.assertEqual('identity', refusal(
            lambda: client.append(f'00000004-{ai.sha(other)}.json', other, {}, {})))

    def test_later_events_travel_after_the_claims_and_before_the_files(self):
        """The client writes them in order, then the files by CID. A keeper
        refuses a body with one after a file, or with one twice."""
        events = begun(2)
        data = b'old 1'
        file = (cid.cid_bytes(data), data)
        sent = []

        def send(method, url, headers, body):
            sent.append(remote.parts_of(body, headers['Content-Type']))
            return 201, b'{}'
        remote.HttpRemoteArchive('https://keeper.example/ledger', 'token', send).append(
            *events[0], dict([file]), {}, events[1:])
        self.assertEqual(['name', 'event', 'claims', events[1][0], events[2][0], file[0]],
                         [name for name, _ in sent[0]])
        head = [('name', events[0][0].encode()), ('event', events[0][1]), ('claims', b'{}')]
        for parts in ([*head, file, *events[1:]], [*head, events[1], events[1]]):
            body, content_type = remote.multipart(parts)
            status, _, answer = remote.handle(remote.Keeper(LEDGER_ID), 'POST', '/events',
                                              {'Content-Type': content_type}, body)
            self.assertEqual((422, 'request'), (status, json.loads(answer)['refused']))


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
                claims=dict(tool='poslib'), cid=folded['first'], path='sub/c é.txt', query='ét')),
                encoding='utf-8')
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
            self.assertEqual(dict(hits=keeper.search('ét')), got['search'])
            self.assertEqual(f'ipfs://{folded["first"]}/sub/c é.txt', got['search']['hits'][0]['ref'])
            self.assertEqual((dict(refused='absent'), dict(refused='access')),
                             (got['absent'], got['stranger']))


class Search(unittest.TestCase):
    """Section 12: where a query is found, from the keeper over the blocks it
    holds, and the matching every adapter shares."""

    def kept(self, scope):
        """A keeper with three items sealed and sent: text of several lines,
        a file that is not UTF-8, one file's bytes under two paths."""
        keeper = remote.Keeper()
        client = over(keeper)
        for item, files in (('first', {'a.txt': b'alpha\nbeta alpha\n', 'sub/b.txt': b'gamma',
                                       'raw.bin': b'\xff\xfealpha'}),
                            ('second', {'c.txt': b'alpha'}),
                            ('third', {'x.txt': b'alpha', 'y.txt': b'alpha'})):
            client.append(*scope.seal(item, files), {})
        return keeper, client, ai.fold_cids(scope.scope / 'archives')

    def assertConfirmed(self, client, hits):
        """The trust invariant: read of each hit's ref at its range gives its passage."""
        for hit in hits:
            match = seal.LINK.fullmatch(hit['ref'])
            lines = search.lines_of(client.read(match[1], match[2] or ''))
            first, last = hit['range']['lines']
            self.assertEqual(hit['passage'], '\n'.join(lines[first - 1:last]))

    def test_a_literal_search_finds_each_line_by_its_item_s_link(self):
        """A hit for each line the query occurs in, in the archive's order by
        path then line, naming the file by its item's CID and the path beneath;
        the same bytes under two paths hit at each; a file that is not UTF-8
        gives none; and each passage is what read gives at its range."""
        with Scope() as scope:
            keeper, client, folded = self.kept(scope)
            hits = client.search('alpha')
            self.assertEqual([(f'ipfs://{folded["first"]}/a.txt', [1, 1], 'alpha'),
                              (f'ipfs://{folded["first"]}/a.txt', [2, 2], 'beta alpha'),
                              (f'ipfs://{folded["second"]}/c.txt', [1, 1], 'alpha'),
                              (f'ipfs://{folded["third"]}/x.txt', [1, 1], 'alpha'),
                              (f'ipfs://{folded["third"]}/y.txt', [1, 1], 'alpha')],
                             [(h['ref'], h['range']['lines'], h['passage']) for h in hits])
            self.assertEqual({'ref', 'range', 'passage'}, set(hits[0]))
            self.assertConfirmed(client, hits)
            self.assertEqual([], client.search('delta'))
            self.assertEqual(['gamma'], [h['passage'] for h in client.search('gam')])

    def test_a_limit_keeps_the_first_hits_and_within_searches_beneath_a_cid(self):
        """limit cuts the list where it stands; within an item, a file or the
        root searches that alone; a CID the ledger does not enrol is absent."""
        with Scope() as scope:
            keeper, client, folded = self.kept(scope)
            self.assertEqual(['alpha', 'beta alpha'], [h['passage'] for h in client.search('alpha', limit=2)])
            self.assertEqual([f'ipfs://{folded["second"]}/c.txt'],
                             [h['ref'] for h in client.search('alpha', within=folded['second'])])
            self.assertEqual([[1, 1], [2, 2]],
                             [h['range']['lines'] for h in client.search('alpha', within=folded['first/a.txt'])])
            self.assertEqual(5, len(client.search('alpha', within=folded['.'])))
            self.assertEqual(1, len(client.search('alpha', within=folded['.'], limit=1)))
            self.assertEqual('absent', refusal(lambda: client.search('alpha', within=cid.cid_bytes(b'never'))))

    def test_a_mode_is_served_as_declared(self):
        """literal alone by default, and regex is refused as mode; a keeper
        declaring regex answers it, and an expression that does not parse is
        refused as request."""
        with Scope() as scope:
            keeper, client, folded = self.kept(scope)
            self.assertEqual(dict(modes=['literal']), client.describe()['search'])
            self.assertEqual('mode', refusal(lambda: client.search('al.ha', mode='regex')))
            self.assertEqual('mode', refusal(lambda: client.search('alpha', mode='semantic')))
            keeper.modes = ('literal', 'regex')
            self.assertEqual(dict(modes=['literal', 'regex']), client.describe()['search'])
            self.assertEqual(['beta alpha', 'gamma'],
                             [h['passage'] for h in client.search('^[bg]', mode='regex')])
            self.assertEqual('request', refusal(lambda: client.search('(', mode='regex')))

    def test_what_is_asked_is_checked(self):
        """No q, an empty q, a limit that is not a positive integer: request,
        at the port and on the wire."""
        with Scope() as scope:
            keeper, client, folded = self.kept(scope)
            self.assertEqual('request', refusal(lambda: client.search('')))
            self.assertEqual('request', refusal(lambda: client.search('alpha', limit=0)))
            self.assertEqual('request', refusal(lambda: client.search('alpha', limit=True)))
            for path in ('/search', '/search?mode=literal', '/search?q=', '/search?q=alpha&limit=abc',
                         '/search?q=alpha&limit=0', '/search?q=alpha&limit=-1'):
                status, _, answer = remote.handle(keeper, 'GET', path, {}, None)
                self.assertEqual((422, 'request'), (status, json.loads(answer)['refused']), path)

    def test_the_query_travels_percent_encoded_and_a_plus_is_a_plus(self):
        """A space goes as %20 and comes back a space; a plus is sent as %2B
        and comes back a plus; mode, limit and within follow q in order and
        only where given."""
        with Scope() as scope:
            keeper, client, folded = self.kept(scope)
            sent = []

            def send(method, url, headers, body):
                sent.append(url)
                status, _, answer = remote.handle(keeper, method, url[len('https://k.example'):], headers, body)
                return status, answer
            asking = remote.HttpRemoteArchive('https://k.example', 'tape-token', send)
            self.assertEqual(['beta alpha'], [h['passage'] for h in asking.search('beta alpha')])
            self.assertEqual([], asking.search('a+b', limit=3, within=folded['.']))
            self.assertEqual(['https://k.example/search?q=beta%20alpha',
                              f'https://k.example/search?q=a%2Bb&limit=3&within={folded["."]}'], sent)
            client.append(*scope.seal('fourth', {'plus.txt': b'a+b'}), {})
            self.assertEqual(['a+b'], [h['passage'] for h in asking.search('a+b')])

    def test_an_erased_file_and_a_keeper_that_does_not_search_give_nothing(self):
        """Erased bytes are not searched, and the rest still are; a keeper
        given no modes describes no search and refuses the operation as
        absent, which the wire answers 404."""
        with Scope() as scope:
            keeper, client, folded = self.kept(scope)
            keeper.erase(folded['second/c.txt'], '2026-10-08')
            self.assertEqual([f'ipfs://{folded["first"]}/a.txt'] * 2,
                             [h['ref'] for h in client.search('alpha')])
            silent = remote.Keeper(modes=())
            self.assertNotIn('search', silent.describe())
            self.assertEqual('absent', refusal(lambda: over(silent).search('alpha')))
            self.assertEqual(404, remote.handle(silent, 'GET', '/search?q=alpha', {}, None)[0])

    def test_the_matching_is_the_protocol_s(self):
        """Lines split at LF with the last terminator making no line, CR kept;
        a file that is not UTF-8 has no lines; a reference names the item,
        else the collection, else the file; beneath takes a file, a
        directory or the root."""
        self.assertEqual(['a', 'b'], search.lines_of(b'a\nb\n'))
        self.assertEqual(['a', 'b'], search.lines_of(b'a\nb'))
        self.assertEqual(['a\r', ''], search.lines_of(b'a\r\n\n'))
        self.assertEqual([], search.lines_of(b''))
        self.assertIsNone(search.lines_of(b'\xff'))
        cids = {'.': 'root', 'item': 'i', 'item/a.txt': 'a', 'item/coll': 'c', 'item/coll/b.txt': 'b',
                'coll': 'k', 'coll/c.txt': 'cc', 'lone.txt': 'l'}
        self.assertEqual('ipfs://i/a.txt', search.reference('item/a.txt', cids, ['item'], ['item/coll']))
        self.assertEqual('ipfs://i/coll/b.txt', search.reference('item/coll/b.txt', cids, ['item'], ['item/coll']))
        self.assertEqual('ipfs://k/c.txt', search.reference('coll/c.txt', cids, ['item'], ['coll']))
        self.assertEqual('ipfs://l', search.reference('lone.txt', cids, ['item'], ['coll']))
        beneath = search.beneath(cids, 'c')
        self.assertEqual([False, True, False], [beneath(p) for p in ('item/a.txt', 'item/coll/b.txt', 'coll/c.txt')])
        self.assertTrue(all(search.beneath(cids, 'root')(p) for p in cids))
        self.assertEqual([True, False], [search.beneath(cids, 'a')(p) for p in ('item/a.txt', 'item/coll/b.txt')])
        self.assertEqual('absent', refusal(lambda: search.beneath(cids, 'nowhere')))
        self.assertEqual([dict(ref='r', range=dict(lines=[2, 2]), passage='xy')],
                         list(search.hits_in(b'a\nxy\n', 'r', lambda line: 'y' in line)))


def call(client, spec):
    """Make the call a tape's exchange describes; its result as the tape writes it."""
    operation = spec['operation']
    if operation == 'describe':
        return client.describe()
    if operation == 'event':
        return dict(bytes=client.event(spec['number']).decode())
    if operation == 'read':
        return dict(bytes=client.read(spec['cid'], spec.get('path', '')).decode())
    if operation == 'held':
        return dict(missing=client.held(spec['cids']))
    if operation == 'put':
        return dict(held='new' if client.put(spec['cid'], spec['block'].encode()) else 'already')
    if operation == 'search':
        return dict(hits=client.search(spec['q'], spec.get('mode'), spec.get('limit'), spec.get('within')))
    return client.append(spec['name'], spec['event'].encode(),
                         {k: v.encode() for k, v in spec['files'].items()}, spec['claims'],
                         [(later['name'], later['event'].encode()) for later in spec.get('following', [])])


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
        """Every tape, its requests made in order of one keeper, told the
        ledger the tape says it keeps, if it says: the status recorded, and
        the body recorded, or for a refusal its kind."""
        for name, tape in fixtures('remote'):
            keeper = remote.Keeper(tape.get('ledger_id'), protocols=tape.get('protocols', remote.VERSIONS),
                                   modes=tape.get('search', ()))
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
