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
"""Signing in to a keeper, and the tokens kept, as section 8 of poslib's
doc/remote-archive-protocol.txt specifies.

A keeper that takes tokens from an OAuth 2.0 authorization server says how a
person gets one: the issuer, the scopes to ask for and the public client to
sign in as. Signing in is the authorization code flow with PKCE to a
loopback address, and happens when a person asks for it and at no other
time. What it yields is kept in one file, which poslib reads too.

- sign_in: sign a person in to the keeper at a URL.
- token_for: the token a request to a keeper carries, refreshed if need be.
- adopt: after a refusal, find that a keeper not seen before takes a token
  already kept.
"""
import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

from .archive_integrity import Refused

WELL_KNOWN = '/.well-known/oauth-protected-resource'
SOON = 60  # a token that expires within this many seconds is refreshed first


def fetch(url, form=None):
    """One exchange with a keeper or an issuer: (status, body). With form, a
    POST of it, urlencoded. Replaced in tests."""
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    request = urllib.request.Request(url, data=data, headers={'Accept': 'application/json'})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read()
    except OSError as error:
        raise Refused('remote', f'{url}: {getattr(error, "reason", None) or error}')


def tokens_file():
    """Where the tokens are kept: pos/tokens.json under $XDG_CONFIG_HOME, or ~/.config."""
    config = os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config')
    return Path(config) / 'pos' / 'tokens.json'


def load():
    """What is kept: {tokens: {"ISSUER CLIENT": ...}, keepers: {ORIGIN: ...}}."""
    try:
        kept = json.loads(tokens_file().read_bytes())
    except (OSError, ValueError):
        kept = {}
    if not isinstance(kept, dict):
        kept = {}
    for part in ('tokens', 'keepers'):
        if not isinstance(kept.get(part), dict):
            kept[part] = {}
    return kept


def save(kept):
    """Replace the file whole, readable by its owner alone."""
    path = tokens_file()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix='tokens-', dir=path.parent)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(json.dumps(kept, indent=1, sort_keys=True).encode() + b'\n')
    os.chmod(name, 0o600)
    os.replace(name, path)


def origin(url):
    """The origin of url: its scheme and host, with its port if it names one."""
    parts = urllib.parse.urlsplit(url)
    return f'{parts.scheme}://{parts.netloc}'


def told_by(url):
    """What the keeper at url says of signing in: its issuer, the client to
    sign in as and the scopes to ask for. Refuses 'access' for a keeper that
    does not say."""
    status, body = fetch(origin(url) + WELL_KNOWN)
    try:
        told = json.loads(body) if status == 200 else None
        issuer = told['authorization_servers'][0]
        client, scopes = told['client_id'], list(told['scopes_supported'])
        if not (isinstance(issuer, str) and isinstance(client, str)
                and all(isinstance(scope, str) for scope in scopes)):
            raise ValueError
    except (ValueError, KeyError, IndexError, TypeError):
        raise Refused('access', f'This keeper does not say how to sign in: {origin(url)}')
    return dict(issuer=issuer, client_id=client, scopes=scopes)


def endpoints(issuer):
    """The issuer's authorization and token endpoints, from its own discovery."""
    status, body = fetch(issuer.rstrip('/') + '/.well-known/openid-configuration')
    try:
        told = json.loads(body) if status == 200 else None
        return told['authorization_endpoint'], told['token_endpoint']
    except (ValueError, KeyError, TypeError):
        raise Refused('remote', f'The issuer does not say where to sign in: {issuer}')


def _key(issuer, client):
    return f'{issuer} {client}'


def _granted(answer, scopes, previous=None):
    """A kept token, from what a token endpoint answered."""
    status, body = answer
    try:
        told = json.loads(body) if status == 200 else None
        return dict(access_token=told['access_token'],
                    expires_at=int(time.time()) + int(told.get('expires_in', 0)),
                    refresh_token=told.get('refresh_token') or previous,
                    scopes=scopes)
    except (ValueError, KeyError, TypeError):
        return None


def _usable(kept, issuer, client):
    """The access token kept for the issuer and client, refreshed first if it
    is about to expire; None if none is kept or it cannot be refreshed. What
    is kept is rewritten when it changes."""
    key = _key(issuer, client)
    token = kept['tokens'].get(key)
    if not isinstance(token, dict) or 'access_token' not in token:
        return None
    if token.get('expires_at', 0) - time.time() > SOON:
        return token['access_token']
    if not token.get('refresh_token'):
        return None
    try:
        _, token_endpoint = endpoints(issuer)
        renewed = _granted(fetch(token_endpoint, dict(grant_type='refresh_token', client_id=client,
                                                      refresh_token=token['refresh_token'])),
                           token.get('scopes', []), token['refresh_token'])
    except Refused:
        return None
    if renewed is None:
        return None
    kept['tokens'][key] = renewed
    save(kept)
    return renewed['access_token']


def token_for(url):
    """The token a request to the keeper at url carries, or None: the one kept
    for its origin, refreshed if it is about to expire."""
    kept = load()
    entry = kept['keepers'].get(origin(url))
    if not isinstance(entry, dict):
        return None
    return _usable(kept, entry.get('issuer'), entry.get('client_id'))


def adopt(url):
    """A token for a keeper not seen before, if one is already kept for the
    issuer and client it names: signing in to one of a keeper's ledgers
    serves its others. The origin is then recorded. None otherwise."""
    kept = load()
    if origin(url) in kept['keepers']:
        return None
    try:
        told = told_by(url)
    except Refused:
        return None
    token = _usable(kept, told['issuer'], told['client_id'])
    if token is None:
        return None
    kept = load()
    kept['keepers'][origin(url)] = dict(issuer=told['issuer'], client_id=told['client_id'])
    save(kept)
    return token


def _challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()


def _wait_for_code(server, state, timeout):
    """The code the browser brings back to the loopback address, with the
    state that was sent."""
    found = {}

    class Callback(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            parts = urllib.parse.urlsplit(self.path)
            query = dict(urllib.parse.parse_qsl(parts.query))
            if parts.path == '/callback':
                found.update(query)
                body = (b'Signed in. This window can be closed.\n' if 'code' in query
                        else b'Not signed in. This window can be closed.\n')
            else:
                body = b'Nothing here.\n'
            self.send_response(200 if parts.path == '/callback' else 404)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server.RequestHandlerClass = Callback
    deadline = time.time() + timeout
    while not found and time.time() < deadline:
        server.timeout = max(0.1, min(1.0, deadline - time.time()))
        server.handle_request()
    if not found:
        raise Refused('access', 'Nobody signed in before the wait ran out')
    if found.get('state') != state or 'code' not in found:
        raise Refused('access', f"Signing in was refused: {found.get('error', 'the answer was not the one asked for')}")
    return found['code']


def sign_in(url, browser=webbrowser.open, timeout=300):
    """Sign a person in to the keeper at url, and keep what that yields.

    If a token is already kept for the issuer and client the keeper names,
    nothing is opened and the keeper is recorded as taking it. Otherwise the
    person's browser is sent to the issuer, by browser, and the code it
    brings back to a loopback address is exchanged for a token.
    {keeper, issuer, client_id, expires_at, opened}: opened is whether a
    browser was."""
    told = told_by(url)
    issuer, client = told['issuer'], told['client_id']
    kept = load()
    opened = False
    if _usable(kept, issuer, client) is None:
        authorization, token_endpoint = endpoints(issuer)
        scopes = told['scopes'] + [s for s in ['offline_access'] if s not in told['scopes']]
        verifier = secrets.token_urlsafe(48)
        state = secrets.token_urlsafe(16)
        server = http.server.HTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler)
        try:
            redirect = f'http://localhost:{server.server_address[1]}/callback'
            browser(authorization + ('&' if '?' in authorization else '?') + urllib.parse.urlencode(dict(
                response_type='code', client_id=client, redirect_uri=redirect, scope=' '.join(scopes),
                state=state, code_challenge=_challenge(verifier), code_challenge_method='S256')))
            opened = True
            code = _wait_for_code(server, state, timeout)
        finally:
            server.server_close()
        granted = _granted(fetch(token_endpoint, dict(grant_type='authorization_code', code=code,
                                                      redirect_uri=redirect, client_id=client,
                                                      code_verifier=verifier)), scopes)
        if granted is None:
            raise Refused('access', f'The issuer gave no token for the code: {issuer}')
        kept = load()
        kept['tokens'][_key(issuer, client)] = granted
    kept['keepers'][origin(url)] = dict(issuer=issuer, client_id=client)
    save(kept)
    return dict(keeper=origin(url), issuer=issuer, client_id=client,
                expires_at=kept['tokens'][_key(issuer, client)]['expires_at'], opened=opened)
