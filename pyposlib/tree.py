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
"""A node's configuration, as poslib's doc/pos-directory.txt specifies.

A node is a repository or a directory of one. Its configuration is in
.clanka or .pos, as config.yaml or config.yml, and declares what kind of
node it is, what is beneath it, its other working trees, where its
scopes' archives are kept and the server it is bound to. Two steps bring
a tree to what its files declare.

What is installed comes from a source the tool is given, a directory of
skills and commands. It is copied into auto/ in the configuration
directory of each repository that has a configuration, and links to it
are made where a coding agent and a person look. Nothing is written in a
repository with no configuration, a product.

- read_config: a config.yaml's text, checked, with defaults filled in.
- config_file: the configuration file a node has.
- plan: what needs to be done for the tree at a root; it changes nothing
  and uses no network.
- apply: do a plan, if the tree still gives it, and return the plan that
  remains.
- main: the command line, poslib's pos-tree-batch command for command.

The agent files of the document's section 5 are not planned: a server is
read and checked, and nothing is done with it.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from fnmatch import fnmatchcase

import yaml

from .archive_integrity import CONFIG_PATHS, Refused, config_files, encoded

VERSION = 2

_WORKTREE = re.compile(r'(?:(.+)/)?_worktrees/[^/]+')
_IMAGE = re.compile(r'[^ \t\n"\'#]+')
_INTEGER = re.compile(r'0|[1-9][0-9]*')
_UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
# The directories a walk does not enter when no node declares exclude:
# archives and attics, Node's modules, and names beginning with an
# underscore or a dot, as doc/pos-directory.txt has it.
DEFAULT_EXCLUDE = ('archives', 'attic', 'node_modules', '_*', '.*')
_ARCHIVE_BEGIN = '# BEGIN ClankOS archive excludes\n'
_ARCHIVE_END = '# END ClankOS archive excludes\n'
# The note the tool writes in an ordinary .claude/skills, and where the
# convention of keeping skills in .agents/skills/ is described.
NOTE = 'README.clankos'
_CONVENTION = 'https://agentskills.io/client-implementation/adding-skills-support'


def _archive_block(text):
    """The bounds of our block, or None. Refuse damaged or duplicate markers."""
    if not text.endswith('\n'):
        text += '\n'
    lines = text.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line == _ARCHIVE_BEGIN]
    ends = [i for i, line in enumerate(lines) if line == _ARCHIVE_END]
    if not starts and not ends:
        return None
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise Refused('archive-excludes', 'Damaged archive exclude block')
    return sum(map(len, lines[:starts[0]])), sum(map(len, lines[:ends[0] + 1]))


def _archive_text(directory, paths):
    """The current exclude text and its replacement, preserving other rules."""
    file = Path(_exclude_file(directory))
    if file.is_symlink():
        raise Refused('archive-excludes', 'The exclude file is a symbolic link')
    old = file.read_text(encoding='utf-8') if file.exists() else ''
    bounds = _archive_block(old)
    # Anchored, directory-only patterns; quote Git's glob characters and spaces.
    patterns = ['/' + re.sub(r'([\\*?\[\] ])', r'\\\1', path) + '/\n' for path in paths]
    block = _ARCHIVE_BEGIN + ''.join(patterns) + _ARCHIVE_END if paths else ''
    if bounds:
        new = old[:bounds[0]] + block + old[bounds[1]:]
    else:
        new = old + ('\n' if old and not old.endswith('\n') and block else '') + block
    return old, new


def _path(path):
    """Whether path is a path beneath a node, relative and going down: it
    has no empty part, no part that is . or .., and no backslash."""
    return '\\' not in path and not any(part in ('', '.', '..') for part in path.split('/'))


def _location(top, name):
    """The path top gives for name, less a final slash, or None if it gives
    none. A path that does not stay beneath its node is refused."""
    if name not in top:
        return None
    value = top[name]
    path = value[:-1] if len(value) > 1 and value.endswith('/') else value
    if not _path(path):
        raise Refused('bad-path', f'Not a path for {name}: {value}')
    return path


def _within(path, container):
    """Whether path is container or beneath it."""
    return path == container or path.startswith(container + '/')


def _is_mapping(value):
    return isinstance(value, dict) and all(isinstance(key, str) for key in value)


def _typed(value, kind):
    """(True, value read as kind), or (False, None) if it is not of kind.
    value is as loaded, every scalar the text that was written. A string
    is any text but the empty one and the two words for null; an integer
    is a whole number in digits."""
    if kind == 'string':
        return (isinstance(value, str) and value not in ('', 'null', '~')), value
    if kind == 'integer':
        if isinstance(value, str) and _INTEGER.fullmatch(value):
            return True, int(value)
        return False, None
    if kind == 'sequence':
        return isinstance(value, list), value
    return _is_mapping(value), value


def _mapping(value, what, keys, warnings, where=None):
    """The mapping value, checked against keys, each (name, kind, required):
    a value not of its kind and a required key that is absent are each
    refused. what names the mapping in a refusal. A key not among them is
    a warning, added to warnings and naming the key after where, the
    mapping's place in the file; the key is left unread, so a file written
    for a newer reader is read with that key's default."""
    if not _is_mapping(value):
        raise Refused('not-a-mapping', f'{what} is not a mapping')
    names = [name for name, _, _ in keys]
    for key in value:
        if key not in names:
            warnings.append(f'unknown-key: {where + "." if where else ""}{key}')
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


def _children(entries, warnings):
    children = []
    for index, entry in enumerate(entries):
        child = _mapping(entry, 'A child', [('path', 'string', True), ('remote', 'string', False),
                                            ('branch', 'string', False)],
                         warnings, f'children[{index}]')
        if not _path(child['path']):
            raise Refused('bad-path', f"Not a child's path: {child['path']}")
        # A branch is a repository's: a child with no remote is a
        # directory of this one.
        if 'remote' not in child and 'branch' in child:
            raise Refused('bad-value', f"A child with no remote has no branch: {child['path']}")
        children.append({'path': child['path'], 'remote': child.get('remote'),
                         'branch': child.get('branch', 'master') if 'remote' in child else None})
    for a in children:
        for b in children:
            if a is not b and _within(b['path'], a['path']):
                raise Refused('bad-path', f"A child's path is another's or beneath it: {b['path']}")
    return children


def _worktrees(entries, children, warnings):
    worktrees = []
    for index, entry in enumerate(entries):
        tree = _mapping(entry, 'A worktree', [('path', 'string', True), ('of', 'string', False),
                                              ('remote', 'string', False), ('branch', 'string', False)],
                        warnings, f'worktrees[{index}]')
        path = tree['path']
        match = _WORKTREE.fullmatch(path) if _path(path) else None
        if not match:
            raise Refused('bad-path', f"Not a worktree's path: {path}")
        if match.group(1) is not None:
            _own_scope(match.group(1), children, 'A worktree')
        if ('of' in tree) == ('remote' in tree):
            raise Refused('bad-value', f'A worktree has one of of and remote: {path}')
        if 'remote' in tree:
            worktrees.append({'path': path, 'remote': tree['remote'],
                              'branch': tree.get('branch', 'master')})
        elif not any(child['path'] == tree['of'] and child['remote'] is not None for child in children):
            raise Refused('bad-value', f"A worktree is of no declared child with a remote: {tree['of']}")
        elif 'branch' not in tree:
            raise Refused('missing-key', 'A worktree of a child lacks branch')
        else:
            worktrees.append({'path': path, 'of': tree['of'], 'branch': tree['branch']})
    _distinct([tree['path'] for tree in worktrees], 'A worktree')
    return worktrees


def _archives(entries, children, warnings):
    archives = []
    for index, entry in enumerate(entries):
        archive = _mapping(entry, 'An archive', [('scope', 'string', True), ('kept', 'string', True),
                                                 ('ledger', 'string', False), ('url', 'string', False),
                                                 ('sweep', 'string', False), ('path', 'string', False)],
                           warnings, f'archives[{index}]')
        scope, kept = archive['scope'], archive['kept']
        if scope != '.':
            if not _path(scope):
                raise Refused('bad-path', f"Not a scope's path: {scope}")
            _own_scope(scope, children, 'An archive')
        if kept not in ('committed', 'uncommitted', 'remote'):
            raise Refused('bad-value', f'An archive is not kept {kept}')
        if 'ledger' in archive and not _UUID.fullmatch(archive['ledger']):
            raise Refused('bad-value', f"Not a ledger's id: {archive['ledger']}")
        ledger = {'ledger': archive['ledger']} if 'ledger' in archive else {}
        if 'sweep' in archive and archive['sweep'] not in ('weekly', 'sealed'):
            raise Refused('bad-value', f"Done items are swept weekly or sealed, not {archive['sweep']}")
        if 'path' in archive and archive.get('sweep') != 'weekly':
            raise Refused('bad-value', f'Only a weekly sweep has a path: {scope}')
        sweep = {**({'sweep': archive['sweep']} if 'sweep' in archive else {}),
                 **({'path': _location(archive, 'path')} if 'path' in archive else {})}
        if kept != 'remote':
            if 'url' in archive:
                raise Refused('bad-value', f'Only a remote archive has a url: {scope}')
            archives.append({'scope': scope, 'kept': kept, **ledger, **sweep})
        elif 'url' in archive:
            archives.append({'scope': scope, 'kept': kept, **ledger, 'url': archive['url'], **sweep})
        else:
            raise Refused('missing-key', 'A remote archive lacks url')
    _distinct([archive['scope'] for archive in archives], "An archive's scope")
    seen = set()
    for archive in archives:
        if archive.get('ledger') in seen:
            raise Refused('bad-value', f"A ledger is named twice: {archive['ledger']}")
        if 'ledger' in archive:
            seen.add(archive['ledger'])
    return archives


def _exclusions(value):
    """value, a configuration's exclude sequence, checked: each entry a
    directory's name or a glob over one, with * for any text, or a path
    beneath the node when it holds a slash, its final slash dropped. None
    for None."""
    if value is None:
        return None
    checked = []
    for entry in value:
        ok, _ = _typed(entry, 'string')
        if not ok:
            raise Refused('wrong-type', 'exclude: an entry is not a string')
        checked.append(_location({'exclude': entry}, 'exclude') if '/' in entry else entry)
    return checked


def exclusions(config):
    """The exclusions in force at the node whose configuration is config:
    its exclude entries, or DEFAULT_EXCLUDE when it declares none, or when
    config is None."""
    declared = None if config is None else config['exclude']
    return list(DEFAULT_EXCLUDE) if declared is None else declared


def unwalked(path, exclusions):
    """Whether path, relative to the node whose exclusions these are, is a
    directory they keep a walk out of. An entry with a slash names a path
    and excludes it and what lies beneath it; any other names a
    directory, with * for any text, wherever it lies beneath the node."""
    name = path.rsplit('/', 1)[-1]
    return any(_within(path, entry) if '/' in entry else fnmatchcase(name, entry)
               for entry in exclusions)


def read_config(text):
    """The configuration in text, a config.yaml's, checked: a dict of
    kind, projects, methodologies, image and bin, each a string or None;
    exclude, a list of strings or None; children, worktrees and archives,
    each a list with its defaults filled in; server, a dict or None; and
    warnings, a list of strings, one for each key this reader does not
    know, which it leaves unread. kind is 'responsibility' for a
    node that says where its projects belong, 'project' for one that says
    where its methodologies belong, and None for one that says neither,
    which is yet to be configured. Every scalar is read as the text
    written, and the keys' kinds decide what it is. Raises Refused, of a
    kind doc/pos-directory.txt names, for a file it does not allow."""
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
    warnings = []
    top = _mapping(parsed, 'The file', [('pos', 'integer', True), ('projects', 'string', False),
                                        ('methodologies', 'string', False), ('image', 'string', False),
                                        ('bin', 'string', False), ('exclude', 'sequence', False), ('children', 'sequence', False),
                                        ('worktrees', 'sequence', False), ('archives', 'sequence', False),
                                        ('server', 'mapping', False)], warnings)
    projects, methodologies = _location(top, 'projects'), _location(top, 'methodologies')
    image = top.get('image')
    children = _children(top.get('children', []), warnings)
    if projects is not None and methodologies is not None:
        raise Refused('bad-value', 'A node says where its projects belong or its methodologies, not both')
    # A tool with no YAML reader finds the image by its line.
    if image is not None and not (_IMAGE.fullmatch(image)
                                  and re.search(f'^image: {re.escape(image)}$', text, re.MULTILINE)):
        raise Refused('bad-value', 'The image is not on one line, as image: NAME, unquoted')
    return {'kind': ('responsibility' if projects is not None
                     else 'project' if methodologies is not None else None),
            'projects': projects, 'methodologies': methodologies, 'image': image,
            'bin': _location(top, 'bin'),
            'exclude': _exclusions(top.get('exclude')),
            'children': children,
            'worktrees': _worktrees(top.get('worktrees', []), children, warnings),
            'archives': _archives(top.get('archives', []), children, warnings),
            'server': (_mapping(top['server'], 'The server',
                                [('name', 'string', True), ('mcp', 'string', True)], warnings, 'server')
                       if 'server' in top else None),
            'warnings': warnings}


# Git

def _git(directory, *args, env=None):
    """Run git in directory with args: (status, what it printed, less its
    final newline)."""
    result = subprocess.run(['git', *args], cwd=directory, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=env)
    output = result.stdout.decode('utf-8', 'replace')
    return result.returncode, output[:-1] if output.endswith('\n') else output


def _git_line(directory, *args):
    """What git printed in directory with args, or None if it failed."""
    status, output = _git(directory, *args)
    return output if status == 0 else None


def _is_repository(directory):
    return os.path.lexists(os.path.join(directory, '.git'))


def _tracked(directory, path):
    return _git(directory, 'ls-files', '--error-unmatch', '--', path)[0] == 0


def _exclude_file(directory):
    """The info/exclude file of the repository at directory, or None."""
    file = _git_line(directory, 'rev-parse', '--git-path', 'info/exclude')
    return None if file is None else os.path.join(directory, file)


def _excluded(directory, path):
    """Whether the repository at directory excludes path: whether its
    info/exclude holds the line this tool writes for it."""
    file = _exclude_file(directory)
    if file is None or not os.path.isfile(file):
        return False
    return '/' + path in Path(file).read_text(encoding='utf-8').split('\n')


def _one_config(files):
    """The one of files, the configuration paths found in a node, or None;
    refused if there are two."""
    if len(files) > 1:
        raise Refused('two-configurations', f'Two configurations: {", ".join(files)}')
    return files[0] if files else None


def config_file(directory):
    """The configuration file of the node at directory, relative to it, or
    None if it has none. Raises Refused, two-configurations, if it has two."""
    return _one_config(config_files(directory))


def _config(directory, branch, made):
    """The configuration of the node at directory, or None if it has none.
    With branch, directory is a repository and it is read from that branch
    as committed; with None, from the working tree. A file that is refused
    is refused, and so are two configurations. Its warnings go to made,
    the plan being made, naming the node."""
    if branch is not None:
        listed = _git_line(directory, 'ls-tree', '--name-only', '-r', branch, '--', *CONFIG_PATHS)
        file = _one_config([name for name in (listed or '').split('\n') if name])
        text = None if file is None else _git_line(directory, 'show', f'{branch}:{file}')
    else:
        file = config_file(directory)
        text = None if file is None else Path(directory, file).read_text(encoding='utf-8')
    if text is None:
        return None
    config = read_config(text)
    made.warnings.extend(f'{made.rel(directory)}: {warning}' for warning in config['warnings'])
    return config


# The plan

class _Node:
    """A repository of the tree that is mounted as declared: its
    configuration, or None; its children mounted as declared, each (entry,
    node); and held, the directories of its children that are there and are
    not planned, because of a finding."""

    def __init__(self, directory, config, children, held):
        self.directory, self.config = directory, config
        self.children, self.held = children, held


class _Plan:
    """The plan being made for the tree at root."""

    def __init__(self, root, source=None):
        self.root, self.source = root, source
        self.actions, self.findings, self.warnings = [], [], []
        self.archive_paths = {}
        self.archive_refused = set()

    def archives(self, repo, base, config):
        """Collect this node's uncommitted archives, stopping at child boundaries.
        A directory the node's exclusions name is not looked into, though
        one named archives is a scope wherever it lies."""
        policies = {entry['scope']: entry['kept'] for entry in config['archives']}
        boundaries = [entry['path'] for entry in config['children'] + config['worktrees']]
        excluded = exclusions(config)
        scopes = {'.', *policies}

        def walk(directory, scope):
            for name in sorted(os.listdir(directory)):
                full = os.path.join(directory, name)
                relative = name if scope == '.' else scope + '/' + name
                if (os.path.islink(full) or not os.path.isdir(full)
                        or any(_within(relative, path) for path in boundaries)):
                    continue
                if name == 'archives':
                    scopes.add(scope)
                elif (not unwalked(relative, excluded)
                      and not _is_repository(full) and not config_files(full)):
                    walk(full, relative)

        walk(base, '.')
        for scope in sorted(scopes):
            at = base
            for part in (() if scope == '.' else scope.split('/')):
                at = os.path.join(at, part)
                if _is_repository(at) or config_files(at):
                    break
            else:
                at = None
            if at is not None:
                continue  # A nearer node owns this scope, even if undeclared.
            path = os.path.normpath(os.path.join(base, scope, 'archives'))
            relative = os.path.relpath(path, repo)
            # Explicit declarations cannot lead through symlinks either.
            if _through_link(repo, relative):
                self.find('path-taken', self.rel(path), 'a symbolic link')
                self.archive_refused.add(repo)
            elif policies.get(scope, 'uncommitted') == 'uncommitted':
                self.archive_paths.setdefault(repo, set()).add(relative)

    def archive_excludes(self, repo):
        if repo in self.archive_refused:
            return
        paths = sorted(self.archive_paths.get(repo, set()))
        try:
            old, new = _archive_text(repo, paths)
            if old != new:
                self.act('archive-excludes', repository=self.rel(repo), paths=paths)
        except Refused as refused:
            self.find('config-refused', self.rel(repo), f'{refused.kind}: {refused}')

    def rel(self, path):
        return os.path.relpath(path, self.root)

    def act(self, do, **pairs):
        self.actions.append({'do': do, **pairs})

    def find(self, finding, path, detail=None):
        self.findings.append({'finding': finding, 'path': path,
                              **({} if detail is None else {'detail': detail})})

    def exclude(self, directory, path):
        if not _excluded(directory, path):
            self.act('exclude', repository=self.rel(directory), path=path)

    def undeclared(self, repo, mounted, local, excluded, prefix='', node=''):
        """Find what is beneath the repository at repo that no entry
        declares: a repository, and a directory holding a configuration.
        mounted are the declared paths of repositories, which are not
        looked into, and local those of directories, which are, each with
        the exclusions it declares or None; both relative to repo.
        excluded are the exclusions in force, declared by the node at
        node, a prefix with its final slash or '' for repo; a local node
        that declares its own replaces them beneath it. prefix is the
        directory being looked in, with its final slash."""
        for name in sorted(os.listdir(os.path.join(repo, prefix))):
            path = prefix + name
            full = os.path.join(repo, path)
            if path in mounted or os.path.islink(full) or not os.path.isdir(full):
                continue
            if unwalked(path[len(node):], excluded):
                continue
            if path in local:
                own = local[path]
                self.undeclared(repo, mounted, local, excluded if own is None else own,
                                path + '/', node if own is None else path + '/')
            # A submodule is the repository's own, tracked and declared by git.
            elif _is_repository(full):
                if not _tracked(repo, path):
                    self.find('undeclared', self.rel(full))
            elif config_files(full):
                self.find('undeclared', self.rel(full), 'a configuration')
            else:
                self.undeclared(repo, mounted, local, excluded, path + '/', node)

    def declared(self, repo, base, config, mounted, local):
        """Plan what config declares, the configuration of the node at
        base, which is the repository at repo or a directory of it. Return
        (nodes, held): a node for each repository mounted as declared, as
        (entry, node) with the entry's path relative to repo, and the
        directories of those that are there and are not planned. The
        declared paths of repositories are added to mounted and those of
        directories to local, with the exclusions each declares or None,
        relative to repo."""
        nodes, held = [], []
        self.archives(repo, base, config)
        if config['kind'] is None:
            self.find('unconfigured', self.rel(base))
        for child in sorted(config['children'], key=lambda child: child['path']):
            path = os.path.join(base, child['path'])
            within = os.path.relpath(path, repo)
            shown = self.rel(path)
            if child['remote'] is not None:
                mounted.append(within)
                self.exclude(repo, within)
                if _through_link(repo, within):
                    self.find('path-taken', shown, 'a symbolic link')
                elif _empty(path):
                    self.act('clone', path=shown, remote=child['remote'], branch=child['branch'])
                elif not _is_repository(path):
                    self.find('path-taken', shown, 'not a repository')
                elif _git_line(path, 'config', '--get', 'remote.origin.url') != child['remote']:
                    held.append(path)
                    self.find('other-remote', shown)
                elif _git_line(path, 'symbolic-ref', '--short', '-q', 'HEAD') != child['branch']:
                    held.append(path)
                    self.find('off-branch', shown, 'declared ' + child['branch'])
                else:
                    try:
                        nodes.append(({**child, 'path': within},
                                      self.mounts(path, _config(path, child['branch'], self))))
                    except Refused as refused:
                        held.append(path)
                        self.find('config-refused', shown, f'{refused.kind}: {refused}')
            # A directory of this repository: what it declares is planned
            # as this repository's.
            elif _through_link(repo, within):
                self.find('path-taken', shown, 'a symbolic link')
            elif not os.path.exists(path):
                self.find('missing', shown)
            elif not os.path.isdir(path):
                self.find('path-taken', shown, 'not a directory')
            elif _is_repository(path):
                mounted.append(within)
                self.find('path-taken', shown, 'a repository, declared with no remote')
            else:
                local[within] = None
                try:
                    own = _config(path, None, self)
                    if own is not None:
                        if own['exclude'] is not None:
                            local[within] = exclusions(own)
                        below = self.declared(repo, path, own, mounted, local)
                        nodes.extend(below[0])
                        held.extend(below[1])
                except Refused as refused:
                    self.archive_refused.add(repo)
                    self.find('config-refused', shown, f'{refused.kind}: {refused}')
        for worktree in sorted(config['worktrees'], key=lambda tree: tree['path']):
            path = os.path.join(base, worktree['path'])
            within = os.path.relpath(path, repo)
            shown = self.rel(path)
            mounted.append(within)
            self.exclude(repo, within)
            if _through_link(repo, within):
                self.find('path-taken', shown, 'a symbolic link')
            elif _empty(path):
                source = ({'of': self.rel(os.path.join(base, worktree['of']))}
                          if 'of' in worktree else {'remote': worktree['remote']})
                self.act('clone', path=shown, **source, branch=worktree['branch'])
            elif not _is_repository(path):
                self.find('path-taken', shown, 'not a repository')
        return nodes, held

    def mounts(self, directory, config):
        """Plan what is mounted in the repository at directory, and return
        its node, with a node for each repository beneath it that is
        mounted as declared, by this repository or by a directory of it."""
        mounted, local = [], {}
        nodes, held = self.declared(directory, directory, config, mounted, local) if config else ([], [])
        self.undeclared(directory, mounted, local, exclusions(config))
        if config:
            self.archive_excludes(directory)
        return _Node(directory, config, nodes, held)

    def taken(self, directory, path):
        """Find path, in the repository at directory, held by something not
        the tool's. The detail says whether the repository tracks it and, if
        so, the commit that added it."""
        if _tracked(directory, path):
            added = _git_line(directory, 'log', '--diff-filter=A', '--format=%h', '--', path)
            detail = ('tracked, added in ' + added.split('\n')[-1] if added
                      else 'tracked, not yet committed')
        else:
            detail = 'untracked'
        self.find('name-taken', self.rel(os.path.join(directory, path)), detail)

    def link_in(self, directory, within, names, targets, auto):
        """Plan the tool's links in within, a directory of the repository at
        directory. Each of names is to be a link to the entry of that name
        in targets, a directory of auto. A name held by something else is
        found and left, and another of the tool's links there is removed."""
        inside = os.path.join(directory, within)
        closed = _closed(directory, within)
        if closed is not None:
            if names:
                self.taken(directory, closed)
            return
        for name in names:
            path, link = f'{within}/{name}', os.path.join(inside, name)
            target = os.path.relpath(os.path.join(targets, name), inside)
            if _own_link(link, auto):
                self.exclude(directory, path)
                if os.readlink(link) != target:
                    self.act('unlink', path=self.rel(link))
                    self.act('link', path=self.rel(link), target=target)
            elif os.path.lexists(link):
                self.taken(directory, path)
            else:
                self.exclude(directory, path)
                self.act('link', path=self.rel(link), target=target)
        if os.path.isdir(inside):
            for name in sorted(os.listdir(inside)):
                link = os.path.join(inside, name)
                if name not in names and _own_link(link, auto):
                    self.act('unlink', path=self.rel(link))

    def claude(self, directory, skills, auto):
        """Plan .claude/skills in the repository at directory for skills,
        installed in auto. Absent, it is to be a link to ../.agents/skills
        when there are skills there. An ordinary directory has the tool's
        links made in it too, and its note. A file or a symbolic link,
        there or at .claude, is left."""
        inside = os.path.join(directory, '.claude', 'skills')
        closed = _closed(directory, '.claude/skills')
        ordinary = closed is None and os.path.isdir(inside)
        if closed is not None:
            pass
        elif ordinary:
            self.link_in(directory, '.claude/skills', skills, os.path.join(auto, 'skills'), auto)
            path, note = f'.claude/skills/{NOTE}', os.path.join(inside, NOTE)
            if not skills:
                pass
            elif _tracked(directory, path):
                self.taken(directory, path)
            else:
                self.exclude(directory, path)
                if not (os.path.isfile(note)
                        and Path(note).read_text(encoding='utf-8') == _note_text(inside)):
                    self.act('note', path=self.rel(note))
        elif skills or _agents_entries(directory):
            self.exclude(directory, '.claude/skills')
            self.act('link', path=self.rel(inside), target='../.agents/skills')
        # The note went with the directory's entries when they were moved.
        stray = os.path.join(directory, '.agents', 'skills', NOTE)
        if (not ordinary and os.path.isfile(stray)
                and not _tracked(directory, f'.agents/skills/{NOTE}')):
            self.act('unlink', path=self.rel(stray))

    def installs(self, node):
        """Plan what is installed in node and in the repositories beneath
        it. A repository with a configuration has auto/ in its configuration
        directory, replaced from the source when its version is another, and
        links to what auto/ holds. One with none, a product, has nothing
        planned in it but the removal of links an earlier tool made."""
        directory = node.directory
        for name in _agents_entries(directory):
            if self.earlier_link(directory, name):
                self.act('unlink', path=self.rel(os.path.join(directory, '.agents/skills', name)))
        auto = _auto(directory) if node.config else None
        if auto is not None:
            version = _version(self.source) if self.source else None
            stale = version is not None and version != _version(auto)
            held = self.source if stale else auto
            skills = _held(held, 'skills')
            if stale or os.path.lexists(auto):
                self.exclude(directory, os.path.relpath(auto, directory))
            if stale:
                self.act('install', path=self.rel(auto), version=version)
            self.link_in(directory, '.agents/skills', skills, os.path.join(auto, 'skills'), auto)
            if node.config['bin'] is not None:
                self.link_in(directory, node.config['bin'], _held(held, 'bin'),
                             os.path.join(auto, 'bin'), auto)
            self.claude(directory, skills, auto)
        for _, child in node.children:
            self.installs(child)

    def earlier_link(self, directory, name):
        """Whether name, in the skills at directory, is a link an earlier
        tool made: an untracked symbolic link whose target is a skill's
        directory in another repository of the tree."""
        skills = os.path.join(directory, '.agents', 'skills')
        link = os.path.join(skills, name)
        if not os.path.islink(link):
            return False
        target = os.path.normpath(os.path.join(skills, os.readlink(link)))
        parent = os.path.dirname(target)
        return (target.startswith(self.root + '/')
                and parent.endswith('/.agents/skills')
                and parent != skills
                and not _tracked(directory, '.agents/skills/' + name))


def _through_link(directory, path):
    """Whether path, beneath directory, is or passes through a symbolic link."""
    at = directory
    for part in path.split('/'):
        at = os.path.join(at, part)
        if os.path.islink(at):
            return True
    return False


def _empty(path):
    """Whether path is absent or an empty directory."""
    return not os.path.exists(path) or (os.path.isdir(path) and not os.listdir(path))


def _version(directory):
    """The version directory holds, a source or an auto directory, or None:
    the first line of the file version there."""
    file = os.path.join(directory, 'version')
    if not os.path.isfile(file):
        return None
    lines = Path(file).read_text(encoding='utf-8').split('\n')
    return lines[0].strip() or None


def _held(directory, kind):
    """The names directory holds of kind, a source or an auto directory,
    sorted: 'skills', each directory holding a SKILL.md, or 'bin', each
    file."""
    inside = os.path.join(directory, kind)
    if not os.path.isdir(inside):
        return []
    return [name for name in sorted(os.listdir(inside))
            if (os.path.exists(os.path.join(inside, name, 'SKILL.md')) if kind == 'skills'
                else os.path.isfile(os.path.join(inside, name)))]


def _check_source(source):
    """Refuse source, a directory to install from, unless it is one: it
    names its version, and each of its skills is named clankos-NAME."""
    if _version(source) is None:
        raise Refused('bad-source', f'The source names no version: {source}')
    for name in _held(source, 'skills'):
        if not name.startswith('clankos-'):
            raise Refused('bad-source', f"A skill's name does not begin clankos-: {name}")


def _auto(directory):
    """The auto directory of the repository at directory, or None. It is in
    the configuration directory there, which a repository whose working
    tree has no configuration lacks."""
    file = config_file(directory)
    return None if file is None else os.path.join(directory, os.path.dirname(file), 'auto')


def _own_link(link, auto):
    """Whether link is a symbolic link whose target is in auto."""
    if not os.path.islink(link):
        return False
    target = os.path.normpath(os.path.join(os.path.dirname(link), os.readlink(link)))
    return target.startswith(auto + '/')


def _closed(directory, path):
    """The first part of path under directory that links cannot be made
    beneath: one that is there and is a symbolic link or not a directory,
    as a path relative to directory. None if every part is a directory or
    absent."""
    at, within = directory, []
    for part in path.split('/'):
        at = os.path.join(at, part)
        within.append(part)
        if os.path.islink(at) or (os.path.lexists(at) and not os.path.isdir(at)):
            return '/'.join(within)
    return None


def _agents_entries(directory):
    """The names in .agents/skills of the repository at directory, sorted:
    none where a part of that path is not an ordinary directory."""
    skills = os.path.join(directory, '.agents', 'skills')
    return (sorted(os.listdir(skills))
            if _closed(directory, '.agents/skills') is None and os.path.isdir(skills) else [])


def _note_text(inside):
    """The text of the note for inside, an ordinary .claude/skills. It
    names what there is no skill: not a directory holding a SKILL.md."""
    others = [name for name in sorted(os.listdir(inside))
              if name != NOTE and not os.path.exists(os.path.join(inside, name, 'SKILL.md'))]
    listed = ('\nA skill is a directory holding a SKILL.md. These entries are not,\n'
              'and no agent reads them as skills:\n\n'
              + ''.join(f'  {name}\n' for name in others)) if others else ''
    return ('ClankOS made the links named clankos-* in this directory, and this\n'
            'note.\n\n'
            "Coding agents share skills from .agents/skills/. This directory's\n"
            'skills can be moved there, and .claude/skills replaced by a symbolic\n'
            'link to ../.agents/skills. ClankOS then makes its links in the one\n'
            'place and removes this note.\n'
            + listed
            + f'\nThe convention is described at\n{_CONVENTION}\n')


def plan(root, source=None):
    """The plan for the tree at root, a repository. source, if given, is
    the directory to install from. A dict of pos, the
    version; actions, what needs to be done, in an order it can be done
    in; findings, what was found and is not acted on; and warnings, what
    the configurations read said that this reader does not know, each a
    string naming the node. Paths in it are relative to root. Nothing is
    changed and no network is used. Raises Refused if root is not a
    repository, or source not a source."""
    directory = os.path.abspath(root)
    if not _is_repository(directory):
        raise Refused('not-a-repository', f'Not a repository: {root}')
    if source is not None:
        source = os.path.abspath(source)
        _check_source(source)
    made = _Plan(directory, source)
    try:
        made.installs(made.mounts(directory, _config(directory, None, made)))
    except Refused as refused:
        made.find('config-refused', '.', f'{refused.kind}: {refused}')
    return {'pos': VERSION, 'actions': made.actions, 'findings': made.findings,
            'warnings': made.warnings}


# The second step

def _run(directory, *args):
    """Run git in directory with args, never prompting; refuse if it fails."""
    status, output = _git(directory, *args, env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'})
    if status:
        raise Refused('failed', f'git {" ".join(args)}: {output}')


def _do(root, action, source=None):
    do = action['do']
    if do == 'install':
        auto = os.path.join(root, action['path'])
        if source is None:
            raise Refused('failed', f'No source to install from: {action["path"]}')
        if os.path.isdir(auto) and not os.path.islink(auto):
            shutil.rmtree(auto)
        elif os.path.lexists(auto):
            os.remove(auto)
        os.makedirs(os.path.dirname(auto), exist_ok=True)
        shutil.copytree(source, auto)
    elif do == 'note':
        note = Path(root, action['path'])
        note.write_text(_note_text(str(note.parent)), encoding='utf-8')
    elif do == 'archive-excludes':
        directory = os.path.join(root, action['repository'])
        file = Path(_exclude_file(directory))
        _, new = _archive_text(directory, action['paths'])
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(new, encoding='utf-8')
    elif do == 'exclude':
        file = Path(_exclude_file(os.path.join(root, action['repository'])))
        file.parent.mkdir(parents=True, exist_ok=True)
        held = file.read_text(encoding='utf-8') if file.exists() else ''
        if held and not held.endswith('\n'):
            held += '\n'
        file.write_text(f'{held}/{action["path"]}\n', encoding='utf-8')
    elif do == 'clone':
        path = os.path.join(root, action['path'])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        branch = action['branch']
        if 'of' in action:
            of = os.path.join(root, action['of'])
            if (_git_line(of, 'rev-parse', '--verify', '--quiet', 'refs/heads/' + branch) is not None
                    or _git_line(of, 'rev-parse', '--verify', '--quiet',
                                 'refs/remotes/origin/' + branch) is not None):
                _run(of, 'worktree', 'add', '--quiet', path, branch)
            else:
                _run(of, 'worktree', 'add', '--quiet', '-b', branch, path)
        else:
            _run(root, 'clone', '--quiet', '--branch', branch, '--', action['remote'], path)
    elif do == 'link':
        link = os.path.join(root, action['path'])
        if os.path.lexists(link):
            raise Refused('failed', f'Something is at {action["path"]}')
        os.makedirs(os.path.dirname(link), exist_ok=True)
        try:
            os.symlink(action['target'], link)
        except OSError as error:
            raise Refused('failed', f'Cannot make a symbolic link at {action["path"]}: '
                                    f'{error.strerror}') from None
    elif do == 'unlink':
        link = os.path.join(root, action['path'])
        if not (os.path.islink(link) or os.path.basename(link) == NOTE):
            raise Refused('failed', f'Not a link or a note: {action["path"]}')
        os.remove(link)
    else:
        raise Refused('failed', f'Not an action this tool does: {do}')


def apply(root, given, source=None):
    """Do the actions of the plan given in the tree at root, and return the
    plan that remains. given is as plan returns it with source, the
    directory to install from if any. Raises Refused: stale-plan, having done nothing, if
    the tree no longer gives that plan; failed if an action cannot be done,
    in which case what was done before it stays done. Cloning uses the
    network."""
    directory = os.path.abspath(root)
    fresh = plan(root, source)
    if encoded(fresh) != encoded(given):
        raise Refused('stale-plan', 'The tree no longer gives this plan')
    for action in fresh['actions']:
        _do(directory, action, None if source is None else os.path.abspath(source))
    return plan(root, source)


def ignore_archives(root):
    """Apply only archive exclusions from a fresh plan; return the remaining
    plan. Clone no repository, install nothing and change no link."""
    for action in plan(root)['actions']:
        if action['do'] == 'archive-excludes':
            _do(os.path.abspath(root), action)
    return plan(root)


# Command line

USAGE = """Usage: COMMAND ...  (help prints this)

  plan ROOT [SOURCE]
      print what needs to be done for the tree at ROOT to be as its
      configurations declare, as JSON; change nothing.  SOURCE is the
      directory of skills and commands to install; with none, nothing
      is installed
  apply ROOT PLAN [SOURCE]
      do what the plan in the file PLAN holds, or - for standard input,
      if the tree at ROOT still gives it with SOURCE; print the plan
      that remains
  archives ROOT
      update only the managed archive rules in Git's info/exclude;
      print the remaining plan; do not clone repositories, install or
      link

Exit 0 nothing to do, 1 something to do or to report, 2 refused.
"""


def main(args=None):
    """Run a command, poslib's pos-tree-batch command for command."""
    args = sys.argv[1:] if args is None else list(args)
    try:
        if len(args) in (2, 3) and args[0] == 'plan':
            made = plan(*args[1:])
        elif len(args) == 2 and args[0] == 'archives':
            made = ignore_archives(args[1])
        elif len(args) in (3, 4) and args[0] == 'apply':
            text = sys.stdin.buffer.read() if args[2] == '-' else Path(args[2]).read_bytes()
            try:
                given = json.loads(text)
            except ValueError:
                print('plan: Not a readable plan', file=sys.stderr)
                return 2
            made = apply(args[1], given, *args[3:])
        elif args in (['help'], ['-h'], ['--help']):
            sys.stdout.write(USAGE)
            return 0
        else:
            sys.stderr.write(USAGE)
            return 2
    except Refused as refused:
        print(f'{refused.kind}: {refused}', file=sys.stderr)
        return 2
    sys.stdout.buffer.write(encoded(made))
    return 1 if made['actions'] or made['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
