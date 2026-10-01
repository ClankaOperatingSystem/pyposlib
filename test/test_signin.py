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
"""Signing in to a keeper, as section 8 of poslib's
doc/remote-archive-protocol.txt specifies.

The issuer here is a stand-in on a local port: it says where its endpoints
are, hands a code to whoever asks at its authorization endpoint, and gives a
token for a code only to the client that holds the verifier its challenge
was made from. The browser is a stand-in too: it follows the redirect the
issuer answers with, which is all a person's browser does once they have
signed in.
"""
import base64
import hashlib
import http.server
import json
import os
import stat
import threading
import time
import unittest
import urllib.parse
import urllib.request

import fixtures  # noqa: F401  (keeps the tests away from a person's own tokens)
from pyposlib import archive_integrity as ai
from pyposlib import remote
from pyposlib import signin

SCOPES = ['openid', 'a-scope']


class Issuer:
    """An authorization server and two keepers that name it, on one local port."""

    def __init__(self):
        issuer = self
        self.codes, self.refreshes, self.asked, self.lifetime = {}, {}, [], 3600

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def answer(self, status, value, headers=()):
                body = json.dumps(value).encode()
                self.send_response(status)
                for name, text in headers:
                    self.send_header(name, text)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parts = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(parts.query))
                if parts.path == signin.WELL_KNOWN:
                    self.answer(200, dict(resource=issuer.url, authorization_servers=[issuer.url],
                                          scopes_supported=SCOPES, client_id='a-public-client'))
                elif parts.path == '/.well-known/openid-configuration':
                    self.answer(200, dict(authorization_endpoint=issuer.url + '/authorize',
                                          token_endpoint=issuer.url + '/token'))
                elif parts.path == '/authorize':
                    issuer.asked.append(query)
                    code = f'code-{len(issuer.asked)}'
                    issuer.codes[code] = query
                    self.send_response(302)
                    self.send_header('Location', query['redirect_uri'] + '?' + urllib.parse.urlencode(
                        dict(code=code, state=issuer.state or query['state'])))
                    self.end_headers()
                else:
                    self.answer(404, dict(error='not here'))

            def do_POST(self):
                form = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers['Content-Length'])).decode()))
                if form.get('grant_type') == 'authorization_code':
                    asked = issuer.codes.pop(form.get('code'), None)
                    challenge = base64.urlsafe_b64encode(
                        hashlib.sha256(form.get('code_verifier', '').encode()).digest()).rstrip(b'=').decode()
                    if (asked is None or asked['code_challenge'] != challenge
                            or asked['code_challenge_method'] != 'S256'
                            or asked['redirect_uri'] != form.get('redirect_uri')
                            or asked['client_id'] != form.get('client_id')):
                        return self.answer(400, dict(error='invalid_grant'))
                elif form.get('grant_type') == 'refresh_token':
                    if issuer.refreshes.pop(form.get('refresh_token'), None) != form.get('client_id'):
                        return self.answer(400, dict(error='invalid_grant'))
                else:
                    return self.answer(400, dict(error='unsupported_grant_type'))
                issuer.granted += 1
                refresh = f'refresh-{issuer.granted}'
                issuer.refreshes[refresh] = form['client_id']
                self.answer(200, dict(access_token=f'access-{issuer.granted}', token_type='Bearer',
                                      expires_in=issuer.lifetime, refresh_token=refresh))

        self.granted, self.state = 0, None
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.server.server_address[1]}'
        self.other = f'http://localhost:{self.server.server_address[1]}'  # a second origin, the same keeper
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def browser(opened):
    """A browser whose person signs in at once: it follows the issuer's
    redirect back to the loopback address."""
    def open_it(url):
        opened.append(url)
        threading.Thread(target=lambda: urllib.request.urlopen(url, timeout=10).read(), daemon=True).start()
    return open_it


class SigningIn(unittest.TestCase):
    def setUp(self):
        self.issuer = Issuer()
        if signin.tokens_file().exists():
            signin.tokens_file().unlink()

    def tearDown(self):
        self.issuer.close()

    def test_signing_in_keeps_a_token_only_its_owner_can_read(self):
        """The browser is sent to the issuer with the keeper's client, the
        scopes it names and one for a refresh token, and a challenge; the
        code that comes back is exchanged with the verifier; and what is
        kept is in a file of mode 0600."""
        opened = []
        told = signin.sign_in(self.issuer.url + '/ledgers/a', browser(opened), timeout=10)
        self.assertEqual((True, self.issuer.url, 'a-public-client'),
                         (told['opened'], told['issuer'], told['client_id']))
        (asked,) = self.issuer.asked
        self.assertEqual(('code', 'a-public-client', 'openid a-scope offline_access', 'S256'),
                         (asked['response_type'], asked['client_id'], asked['scope'],
                          asked['code_challenge_method']))
        self.assertRegex(asked['redirect_uri'], r'^http://localhost:\d+/callback$')
        self.assertEqual('access-1', signin.token_for(self.issuer.url + '/ledgers/a'))
        self.assertEqual(0o600, stat.S_IMODE(signin.tokens_file().stat().st_mode))

    def test_one_sign_in_serves_every_ledger_of_a_keeper(self):
        """Asked to sign in to a second origin that names the same issuer and
        client, nothing is opened; and a request to an origin never seen
        adopts the token after its first refusal."""
        opened = []
        signin.sign_in(self.issuer.url, browser(opened), timeout=10)
        again = signin.sign_in(self.issuer.other, browser(opened), timeout=10)
        self.assertEqual((1, False), (len(opened), again['opened']))

        signin.tokens_file().write_text(json.dumps(dict(
            signin.load(), keepers={self.issuer.url: dict(issuer=self.issuer.url, client_id='a-public-client')})))
        sent = []

        def send(method, url, headers, body):
            sent.append(headers.get('Authorization'))
            return (200, b'{"events":0}') if headers.get('Authorization') == 'Bearer access-1' else (401, b'')
        described = remote.HttpRemoteArchive(self.issuer.other + '/ledgers/b', None, send).describe()
        self.assertEqual(dict(events=0), described)
        self.assertEqual([None, 'Bearer access-1'], sent)
        self.assertIn(self.issuer.other, signin.load()['keepers'])

    def test_a_token_about_to_expire_is_refreshed_and_kept(self):
        self.issuer.lifetime = 30
        signin.sign_in(self.issuer.url, browser([]), timeout=10)
        self.assertEqual('access-2', signin.token_for(self.issuer.url))
        self.assertEqual('refresh-2', signin.load()['tokens'][f'{self.issuer.url} a-public-client']['refresh_token'])

    def test_a_token_that_cannot_be_refreshed_is_no_token(self):
        self.issuer.lifetime = 30
        signin.sign_in(self.issuer.url, browser([]), timeout=10)
        self.issuer.refreshes.clear()
        self.assertIsNone(signin.token_for(self.issuer.url))

    def test_an_answer_that_is_not_the_one_asked_for_is_refused(self):
        """The state that comes back must be the state that was sent."""
        self.issuer.state = 'another'
        with self.assertRaises(ai.Refused) as refused:
            signin.sign_in(self.issuer.url, browser([]), timeout=10)
        self.assertEqual('access', refused.exception.kind)
        self.assertFalse(signin.tokens_file().exists())

    def test_nobody_signing_in_is_refused_when_the_wait_runs_out(self):
        with self.assertRaises(ai.Refused) as refused:
            signin.sign_in(self.issuer.url, lambda url: None, timeout=0.3)
        self.assertEqual('access', refused.exception.kind)

    def test_a_keeper_that_does_not_say_how_is_not_signed_in_to(self):
        """A keeper with nothing at the address where it would say."""
        silent = http.server.HTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler)
        threading.Thread(target=silent.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(ai.Refused) as refused:
                signin.sign_in(f'http://127.0.0.1:{silent.server_address[1]}', browser([]), timeout=1)
            self.assertEqual('access', refused.exception.kind)
        finally:
            silent.shutdown()
            silent.server_close()

    def test_a_request_without_a_token_says_to_sign_in(self):
        """Refused for want of a token, with none kept, a request says how to
        get one and opens nothing."""
        with self.assertRaises(ai.Refused) as refused:
            remote.HttpRemoteArchive(self.issuer.url + '/ledgers/a', None,
                                     lambda *_: (401, b'{"refused":"access"}')).describe()
        self.assertEqual('access', refused.exception.kind)
        self.assertIn('sign-in ' + self.issuer.url + '/ledgers/a', str(refused.exception))
        self.assertEqual([], self.issuer.asked)

    def test_what_either_library_keeps_the_other_reads(self):
        """The shared fixture: a kept file, and the token each keeper's
        requests then carry."""
        for name, fixture in fixtures.fixtures('signin'):
            signin.tokens_file().parent.mkdir(parents=True, exist_ok=True)
            signin.tokens_file().write_text(json.dumps(fixture['file']))
            for carried in fixture['carried']:
                with self.subTest(f"{name} {carried['url']}"):
                    self.assertEqual(carried['token'], signin.token_for(carried['url']))

    def test_the_environment_s_token_is_used_and_nothing_kept_is_read(self):
        signin.sign_in(self.issuer.url, browser([]), timeout=10)
        os.environ['POS_ARCHIVE_TOKEN'] = 'from-the-environment'
        try:
            sent = []
            keeper = ai.keeper_of(self.issuer.url)
            keeper.send = lambda method, url, headers, body: (sent.append(headers['Authorization']), (200, b'{}'))[1]
            keeper.describe()
            self.assertEqual(['Bearer from-the-environment'], sent)
        finally:
            del os.environ['POS_ARCHIVE_TOKEN']


if __name__ == '__main__':
    unittest.main(verbosity=2)
