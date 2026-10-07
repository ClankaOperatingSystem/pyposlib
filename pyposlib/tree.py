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
import subprocess
import sys

import yaml

from .archive_integrity import CONFIG_PATHS, Refused, config_files, encoded

VERSION = 2

_WORKTREE = re.compile(r'(?:(.+)/)?_worktrees/[^/]+')
_IMAGE = re.compile(r'[^ \t\n"\'#]+')
_INTEGER = re.compile(r'0|[1-9][0-9]*')
_UUID = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
# Directories not looked into for what is undeclared; nor are hidden
# ones and those beginning with an underscore.
_UNWALKED = ('archives', 'attic', 'node_modules')
_ARCHIVE_BEGIN = '# BEGIN ClankOS archive excludes\n'
_ARCHIVE_END = '# END ClankOS archive excludes\n'


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
        child = _mapping(entry, 'A child', [('path', 'string', True), ('remote', 'string', False),
                                            ('branch', 'string', False), ('skills-up', 'boolean', False)])
        if not _path(child['path']):
            raise Refused('bad-path', f"Not a child's path: {child['path']}")
        # A branch and skills are a repository's: a child with no remote
        # is a directory of this one.
        if 'remote' not in child and ('branch' in child or 'skills-up' in child):
            raise Refused('bad-value', f"A child with no remote has no branch or skills-up: {child['path']}")
        children.append({'path': child['path'], 'remote': child.get('remote'),
                         'branch': child.get('branch', 'master') if 'remote' in child else None,
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


def _archives(entries, children):
    archives = []
    for entry in entries:
        archive = _mapping(entry, 'An archive', [('scope', 'string', True), ('kept', 'string', True),
                                                 ('ledger', 'string', False), ('url', 'string', False)])
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
        if kept != 'remote':
            if 'url' in archive:
                raise Refused('bad-value', f'Only a remote archive has a url: {scope}')
            archives.append({'scope': scope, 'kept': kept, **ledger})
        elif 'url' in archive:
            archives.append({'scope': scope, 'kept': kept, **ledger, 'url': archive['url']})
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


def read_config(text):
    """The configuration in text, a config.yaml's, checked: a dict of
    kind, projects, methodologies and image, each a string or None;
    children, worktrees and archives, each a list with its defaults
    filled in; and server, a dict or None. kind is 'responsibility' for a
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
    top = _mapping(parsed, 'The file', [('pos', 'integer', True), ('projects', 'string', False),
                                        ('methodologies', 'string', False), ('image', 'string', False),
                                        ('children', 'sequence', False),
                                        ('worktrees', 'sequence', False), ('archives', 'sequence', False),
                                        ('server', 'mapping', False)])
    projects, methodologies = _location(top, 'projects'), _location(top, 'methodologies')
    image = top.get('image')
    children = _children(top.get('children', []))
    if projects is not None and methodologies is not None:
        raise Refused('bad-value', 'A node says where its projects belong or its methodologies, not both')
    # A tool with no YAML reader finds the image by its line.
    if image is not None and not (_IMAGE.fullmatch(image)
                                  and re.search(f'^image: {re.escape(image)}$', text, re.MULTILINE)):
        raise Refused('bad-value', 'The image is not on one line, as image: NAME, unquoted')
    return {'kind': ('responsibility' if projects is not None
                     else 'project' if methodologies is not None else None),
            'projects': projects, 'methodologies': methodologies, 'image': image,
            'children': children,
            'worktrees': _worktrees(top.get('worktrees', []), children),
            'archives': _archives(top.get('archives', []), children),
            'server': (_mapping(top['server'], 'The server',
                                [('name', 'string', True), ('mcp', 'string', True)])
                       if 'server' in top else None)}


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


def _config(directory, branch):
    """The configuration of the node at directory, or None if it has none.
    With branch, directory is a repository and it is read from that branch
    as committed; with None, from the working tree. A file that is refused
    is refused, and so are two configurations."""
    if branch is not None:
        listed = _git_line(directory, 'ls-tree', '--name-only', '-r', branch, '--', *CONFIG_PATHS)
        file = _one_config([name for name in (listed or '').split('\n') if name])
        text = None if file is None else _git_line(directory, 'show', f'{branch}:{file}')
    else:
        file = config_file(directory)
        text = None if file is None else Path(directory, file).read_text(encoding='utf-8')
    return None if text is None else read_config(text)


# The plan

class _Node:
    """A repository of the tree that is mounted as declared: its children
    mounted as declared, each (entry, node), and held, the directories of
    its children that are there and are not planned, because of a finding."""

    def __init__(self, directory, children, held):
        self.directory, self.children, self.held = directory, children, held


class _Plan:
    """The plan being made for the tree at root."""

    def __init__(self, root):
        self.root = root
        self.actions, self.findings = [], []
        self.archive_paths = {}
        self.archive_refused = set()

    def archives(self, repo, base, config):
        """Collect this node's uncommitted archives, stopping at child boundaries."""
        policies = {entry['scope']: entry['kept'] for entry in config['archives']}
        boundaries = [entry['path'] for entry in config['children'] + config['worktrees']]
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
                elif (name not in _UNWALKED and not name.startswith(('.', '_'))
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

    def undeclared(self, repo, mounted, local, prefix=''):
        """Find what is beneath the repository at repo that no entry
        declares: a repository, and a directory holding a configuration.
        mounted are the declared paths of repositories, which are not
        looked into, and local those of directories, which are; both
        relative to repo. prefix is the directory being looked in, with
        its final slash."""
        for name in sorted(os.listdir(os.path.join(repo, prefix))):
            path = prefix + name
            full = os.path.join(repo, path)
            if path in mounted or os.path.islink(full) or not os.path.isdir(full):
                continue
            if name in _UNWALKED or name.startswith(('.', '_')):
                continue
            if path in local:
                self.undeclared(repo, mounted, local, path + '/')
            # A submodule is the repository's own, tracked and declared by git.
            elif _is_repository(full):
                if not _tracked(repo, path):
                    self.find('undeclared', self.rel(full))
            elif config_files(full):
                self.find('undeclared', self.rel(full), 'a configuration')
            else:
                self.undeclared(repo, mounted, local, path + '/')

    def declared(self, repo, base, config, mounted, local):
        """Plan what config declares, the configuration of the node at
        base, which is the repository at repo or a directory of it. Return
        (nodes, held): a node for each repository mounted as declared, as
        (entry, node) with the entry's path relative to repo, and the
        directories of those that are there and are not planned. The
        declared paths of repositories are added to mounted and those of
        directories to local, relative to repo."""
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
                                      self.mounts(path, _config(path, child['branch']))))
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
                local.append(within)
                try:
                    own = _config(path, None)
                    if own is not None:
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
        mounted, local = [], []
        nodes, held = self.declared(directory, directory, config, mounted, local) if config else ([], [])
        self.undeclared(directory, mounted, local)
        if config:
            self.archive_excludes(directory)
        return _Node(directory, nodes, held)

    def claude_link(self, directory, wanted):
        """Plan the .claude/skills link of the repository at directory,
        made only if wanted and absent. Existing layouts are left alone."""
        link = os.path.join(directory, '.claude', 'skills')
        if wanted and _skill_path_open(directory, '.claude') and not os.path.lexists(link):
            self.exclude(directory, '.claude/skills')
            self.act('link', path=self.rel(link), target='../.agents/skills')

    def links(self, node, containers):
        """Plan the skill links of node and of the repositories beneath it.
        containers are the linkable skills of the repositories above it,
        nearest first."""
        directory = node.directory
        if not _skill_path_open(directory, '.agents/skills'):
            # Preserve this layout while still visiting its descendants.
            for _, child in node.children:
                self.links(child, containers)
            return
        skills = _skills(directory)
        entries = _entries(directory)
        made = [name for name in entries if self.tool_link(directory, name)]
        taken = [name for name in entries if name not in made]
        desired = {}
        # Down: each container's own skills, the nearer first.
        for container in containers:
            for name, target in container:
                if name not in taken and name not in desired:
                    desired[name] = target
        # Up: the own skills of each child marked for it.
        offered = [(name, target)
                   for child, below in node.children if child['skills-up'] is True
                   for name, target in _linkable(below.directory)
                   if name not in taken and name not in desired]
        names = [name for name, _ in offered]
        clashed = []
        for name, target in offered:
            if names.count(name) == 1:
                desired[name] = target
            elif name not in clashed:
                clashed.append(name)
                self.find('name-clash', self.rel(os.path.join(skills, name)))
        for name in sorted(desired):
            link = os.path.join(skills, name)
            target = os.path.relpath(desired[name], skills)
            self.exclude(directory, '.agents/skills/' + name)
            if name not in made:
                self.act('link', path=self.rel(link), target=target)
            elif os.readlink(link) != target:
                self.act('unlink', path=self.rel(link))
                self.act('link', path=self.rel(link), target=target)
        # A link into a child that is held is left: nothing is done about
        # a child with a finding, its skills in this repository included.
        for name in made:
            link = os.path.join(skills, name)
            target = os.path.normpath(os.path.join(skills, os.readlink(link)))
            if name not in desired and not any(target.startswith(held + '/') for held in node.held):
                self.act('unlink', path=self.rel(link))
        self.claude_link(directory, bool(desired or entries))
        below = [_linkable(directory), *containers]
        for _, child in node.children:
            self.links(child, below)

    def tool_link(self, directory, name):
        """Whether name, in the skills at directory, is a link this tool
        made: an untracked symbolic link whose target is a skill's
        directory in another repository of the tree."""
        skills = _skills(directory)
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


def _skills(directory):
    return os.path.join(directory, '.agents', 'skills')


def _entries(directory):
    """The names in the skills directory of the repository at directory."""
    skills = _skills(directory)
    return (sorted(os.listdir(skills))
            if _skill_path_open(directory, '.agents/skills') and os.path.isdir(skills) else [])


def _skill_path_open(directory, path):
    """Whether path can hold managed skills without replacing content.
    Existing components must be ordinary directories, never symlinks."""
    at = directory
    for part in path.split('/'):
        at = os.path.join(at, part)
        if os.path.islink(at) or (os.path.lexists(at) and not os.path.isdir(at)):
            return False
    return True


def _linkable(directory):
    """The skills of the repository at directory that are linked elsewhere,
    each (name, directory): its own, which are directories and not links,
    less any holding a .pos-local file."""
    skills = _skills(directory)
    return [(name, os.path.join(skills, name)) for name in _entries(directory)
            if not os.path.islink(os.path.join(skills, name))
            and os.path.exists(os.path.join(skills, name, 'SKILL.md'))
            and not os.path.exists(os.path.join(skills, name, '.pos-local'))]


def plan(root):
    """The plan for the tree at root, a repository: a dict of pos, the
    version; actions, what needs to be done, in an order it can be done
    in; and findings, what was found and is not acted on. Paths in it are
    relative to root. Nothing is changed and no network is used. Raises
    Refused if root is not a repository."""
    directory = os.path.abspath(root)
    if not _is_repository(directory):
        raise Refused('not-a-repository', f'Not a repository: {root}')
    made = _Plan(directory)
    try:
        made.links(made.mounts(directory, _config(directory, None)), [])
    except Refused as refused:
        made.find('config-refused', '.', f'{refused.kind}: {refused}')
    return {'pos': VERSION, 'actions': made.actions, 'findings': made.findings}


# The second step

def _run(directory, *args):
    """Run git in directory with args, never prompting; refuse if it fails."""
    status, output = _git(directory, *args, env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'})
    if status:
        raise Refused('failed', f'git {" ".join(args)}: {output}')


def _do(root, action):
    do = action['do']
    if do == 'archive-excludes':
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
        os.symlink(action['target'], link)
    elif do == 'unlink':
        link = os.path.join(root, action['path'])
        if not os.path.islink(link):
            raise Refused('failed', f'Not a link: {action["path"]}')
        os.remove(link)
    else:
        raise Refused('failed', f'Not an action this tool does: {do}')


def apply(root, given):
    """Do the actions of the plan given in the tree at root, and return the
    plan that remains. Raises Refused: stale-plan, having done nothing, if
    the tree no longer gives that plan; failed if an action cannot be done,
    in which case what was done before it stays done. Cloning uses the
    network."""
    directory = os.path.abspath(root)
    fresh = plan(root)
    if encoded(fresh) != encoded(given):
        raise Refused('stale-plan', 'The tree no longer gives this plan')
    for action in fresh['actions']:
        _do(directory, action)
    return plan(root)


def ignore_archives(root):
    """Apply only archive exclusions from a fresh plan; return the remaining plan."""
    for action in plan(root)['actions']:
        if action['do'] == 'archive-excludes':
            _do(os.path.abspath(root), action)
    return plan(root)


# Command line

USAGE = """Usage: COMMAND ...  (help prints this)

  plan ROOT
      print what needs to be done for the tree at ROOT to be as its
      configurations declare, as JSON; change nothing
  apply ROOT PLAN
      do what the plan in the file PLAN holds, or - for standard input,
      if the tree at ROOT still gives it; print the plan that remains
  archives ROOT
      update only the managed archive rules in Git's info/exclude;
      print the remaining plan; do not clone repositories or link skills

Exit 0 nothing to do, 1 something to do or to report, 2 refused.
"""


def main(args=None):
    """Run a command, poslib's pos-tree-batch command for command."""
    args = sys.argv[1:] if args is None else list(args)
    try:
        if len(args) == 2 and args[0] == 'plan':
            made = plan(args[1])
        elif len(args) == 2 and args[0] == 'archives':
            made = ignore_archives(args[1])
        elif len(args) == 3 and args[0] == 'apply':
            text = sys.stdin.buffer.read() if args[2] == '-' else Path(args[2]).read_bytes()
            try:
                given = json.loads(text)
            except ValueError:
                print('plan: Not a readable plan', file=sys.stderr)
                return 2
            made = apply(args[1], given)
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
