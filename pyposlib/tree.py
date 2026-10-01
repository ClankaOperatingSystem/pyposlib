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
"""A repository's .pos/config.yaml, as poslib's doc/pos-directory.txt specifies.

A repository declares there the repositories mounted beneath it, its
other working trees, where its scopes' archives are kept and the server
it is bound to.

- read_config: a config.yaml's text, checked, with defaults filled in.

Planning a tree from its files and doing a plan are poslib's alone.
"""
import re

import yaml

from .archive_integrity import Refused

VERSION = 1
CONFIG_FILE = '.pos/config.yaml'

_PAIR = r'(?:projects|responsibilities)/[^/]+'
_SCOPE = rf'{_PAIR}(?:/{_PAIR})*'
_WORKTREE = re.compile(rf'(?:({_SCOPE})/)?_worktrees/([^/]+)')
_INTEGER = re.compile(r'0|[1-9][0-9]*')


def _scope_path(path):
    """Whether path is a scope's path beneath a repository's root: pairs
    of projects/NAME or responsibilities/NAME."""
    return (re.fullmatch(_SCOPE, path) is not None
            and not any(part in ('.', '..') for part in path.split('/')))


def _within(path, container):
    """Whether path is container or beneath it."""
    return path == container or path.startswith(container + '/')


def _is_mapping(value):
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _typed(value, kind):
    """(True, value read as kind), or (False, None) if it is not of kind.
    value is as loaded, every scalar the text that was written. A string
    is any text but the empty one and the two words for null; a boolean
    is true or false; an integer is a whole number in digits."""
    if kind == 'string':
        return (isinstance(value, str) and value not in ('', 'null', '~')), value
    if kind == 'boolean':
        return value in ('true', 'false'), value == 'true'
    if kind == 'integer':
        if isinstance(value, str) and _INTEGER.fullmatch(value):
            return True, int(value)
        return False, None
    if kind == 'sequence':
        return isinstance(value, list), value
    return _is_mapping(value), value


def _mapping(value, what, keys):
    """The mapping value, checked against keys, each (name, kind, required):
    a key not among them, a value not of its kind and a required key that
    is absent are each refused. what names the mapping in a refusal."""
    if not _is_mapping(value):
        raise Refused('not-a-mapping', f'{what} is not a mapping')
    names = [name for name, _, _ in keys]
    for key in value:
        if key not in names:
            raise Refused('unknown-key', f'{what} has a key this version does not define: {key}')
    checked = {}
    for name, kind, required in keys:
        if name in value:
            ok, typed = _typed(value[name], kind)
            if not ok:
                raise Refused('wrong-type', f'{what}: {name} is not a {kind}')
            checked[name] = typed
        elif required:
            raise Refused('missing-key', f'{what} lacks {name}')
    return checked


def _distinct(paths, what):
    seen = set()
    for path in paths:
        if path in seen:
            raise Refused('bad-path', f'{what} is named twice: {path}')
        seen.add(path)


def _own_scope(path, children, what):
    """Refuse if path, a scope, is one of children or beneath one."""
    for child in children:
        if _within(path, child['path']):
            raise Refused('bad-path', f'{what} is in a child, which declares its own: {path}')


def _children(entries):
    children = []
    for entry in entries:
        child = _mapping(entry, 'A child', [('path', 'string', True), ('remote', 'string', True),
                                            ('branch', 'string', False), ('skills-up', 'boolean', False)])
        if not _scope_path(child['path']):
            raise Refused('bad-path', f"Not a child's path: {child['path']}")
        children.append({'path': child['path'], 'remote': child['remote'],
                         'branch': child.get('branch', 'master'),
                         'skills-up': child.get('skills-up', False)})
    for a in children:
        for b in children:
            if a is not b and _within(b['path'], a['path']):
                raise Refused('bad-path', f"A child's path is another's or beneath it: {b['path']}")
    return children


def _worktrees(entries, children):
    worktrees = []
    for entry in entries:
        tree = _mapping(entry, 'A worktree', [('path', 'string', True), ('of', 'string', False),
                                              ('remote', 'string', False), ('branch', 'string', False)])
        path = tree['path']
        match = _WORKTREE.fullmatch(path)
        if not match or match.group(2) in ('.', '..'):
            raise Refused('bad-path', f"Not a worktree's path: {path}")
        if match.group(1) is not None:
            if not _scope_path(match.group(1)):
                raise Refused('bad-path', f"Not a worktree's path: {path}")
            _own_scope(match.group(1), children, 'A worktree')
        if ('of' in tree) == ('remote' in tree):
            raise Refused('bad-value', f'A worktree has one of of and remote: {path}')
        if 'remote' in tree:
            worktrees.append({'path': path, 'remote': tree['remote'],
                              'branch': tree.get('branch', 'master')})
        elif not any(child['path'] == tree['of'] for child in children):
            raise Refused('bad-value', f"A worktree is of no declared child: {tree['of']}")
        elif 'branch' not in tree:
            raise Refused('missing-key', 'A worktree of a child lacks branch')
        else:
            worktrees.append({'path': path, 'of': tree['of'], 'branch': tree['branch']})
    _distinct([tree['path'] for tree in worktrees], 'A worktree')
    return worktrees


def _archives(entries, children):
    archives = []
    for entry in entries:
        archive = _mapping(entry, 'An archive', [('scope', 'string', True), ('kept', 'string', True),
                                                 ('url', 'string', False)])
        scope, kept = archive['scope'], archive['kept']
        if scope != '.':
            if not _scope_path(scope):
                raise Refused('bad-path', f"Not a scope's path: {scope}")
            _own_scope(scope, children, 'An archive')
        if kept not in ('committed', 'uncommitted', 'remote'):
            raise Refused('bad-value', f'An archive is not kept {kept}')
        if kept != 'remote':
            if 'url' in archive:
                raise Refused('bad-value', f'Only a remote archive has a url: {scope}')
            archives.append({'scope': scope, 'kept': kept})
        elif 'url' in archive:
            archives.append({'scope': scope, 'kept': kept, 'url': archive['url']})
        else:
            raise Refused('missing-key', 'A remote archive lacks url')
    _distinct([archive['scope'] for archive in archives], "An archive's scope")
    return archives


def read_config(text):
    """The configuration in text, a config.yaml's, checked: a dict of
    children, worktrees and archives, each a list with its defaults
    filled in, and server, a dict or None. Every scalar is read as the
    text written, and the keys' kinds decide what it is. Raises Refused,
    of a kind doc/pos-directory.txt names, for a file it does not allow."""
    try:
        parsed = yaml.load(text, Loader=yaml.BaseLoader)
    except yaml.YAMLError:
        raise Refused('not-yaml', 'Not readable as YAML') from None
    if parsed is None:
        parsed = {}
    if not _is_mapping(parsed):
        raise Refused('not-a-mapping', 'The file is not a mapping')
    known, version = _typed(parsed.get('pos'), 'integer')
    if known and version != VERSION:
        raise Refused('unknown-version', f'Not a version this reader knows: {version}')
    top = _mapping(parsed, 'The file', [('pos', 'integer', True), ('children', 'sequence', False),
                                        ('worktrees', 'sequence', False), ('archives', 'sequence', False),
                                        ('server', 'mapping', False)])
    children = _children(top.get('children', []))
    return {'children': children,
            'worktrees': _worktrees(top.get('worktrees', []), children),
            'archives': _archives(top.get('archives', []), children),
            'server': (_mapping(top['server'], 'The server',
                                [('name', 'string', True), ('mcp', 'string', True)])
                       if 'server' in top else None)}
