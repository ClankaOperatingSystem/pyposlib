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
"""pyposlib's reading of a node's configuration, against poslib.

The reader is held to the fixtures in poslib's fixtures/pos-directory/.
The two steps are tried in real trees: each test makes repositories with
git init in a temporary directory, as poslib's doc/pos-directory.txt
asks, a child's remote being a repository beside the tree. Wherever a
test looks at a plan it also asks poslib for the plan of the same tree,
which must be the same bytes; that part needs Emacs and a poslib
checkout (POSLIB), and is left out without Emacs.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from fixtures import POSLIB, fixtures
from pyposlib import tree
from pyposlib.archive_integrity import Refused, encoded

EMACS = os.environ.get('EMACS', 'emacs')
GIT = {'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
       'GIT_AUTHOR_NAME': 'Test', 'GIT_AUTHOR_EMAIL': 'test@example.org',
       'GIT_COMMITTER_NAME': 'Test', 'GIT_COMMITTER_EMAIL': 'test@example.org'}


def read(text):
    """What read_config makes of text: its configuration, or the kind it
    is refused with."""
    try:
        return tree.read_config(text)
    except Refused as refused:
        return refused.kind


def git(directory, *args):
    subprocess.run(['git', *args], cwd=directory, check=True, capture_output=True)


def write(directory, path, text):
    file = Path(directory) / path
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(text, encoding='utf-8')


def commit(directory, files=None):
    for path, text in (files or {}).items():
        write(directory, path, text)
    git(directory, 'add', '-A')
    git(directory, 'commit', '-q', '--allow-empty', '-m', 'Add files')


def repository(directory, files=None):
    """Make a repository at directory, on master, with files committed."""
    Path(directory).mkdir(parents=True, exist_ok=True)
    git(directory, 'init', '-q', '-b', 'master')
    commit(directory, files)
    return str(directory)


def skill(name):
    """The files of a repository's own skill name."""
    return {f'.agents/skills/{name}/SKILL.md': f'---\nname: {name}\ndescription: A skill.\n---\n'}


def source(directory, version, *names):
    """Make at directory a source to install from, of version: each of
    names that begins clankos- is a skill, and any other a command. What
    was at directory is replaced."""
    shutil.rmtree(directory, ignore_errors=True)
    write(directory, 'version', version + '\n')
    for name in names:
        if name.startswith('clankos-'):
            write(directory, f'skills/{name}/SKILL.md', f'---\nname: {name}\ndescription: A skill.\n---\n')
        else:
            write(directory, f'bin/{name}', '#!/bin/sh\n')
            os.chmod(os.path.join(directory, 'bin', name), 0o755)
    return str(directory)


def child(path, remote, *more):
    """A child entry of a config.yaml: path, remote and more lines."""
    return f'  - path: {path}\n    remote: {remote}\n' + ''.join(f'    {line}\n' for line in more)


def text(*children):
    """A config.yaml's text declaring children, each an entry's text."""
    return ('pos: 2\nprojects: projects/\narchives:\n  - scope: .\n    kept: committed\n'
            + ('children:\n' + ''.join(children) if children else 'children: []\n'))


def config(*children):
    return {'.pos/config.yaml': text(*children)}


def summary(plan):
    """A plan as a list of strings, its actions and then its findings."""
    lines = []
    for action in plan['actions']:
        lines.append({'exclude': 'exclude {repository} {path}', 'clone': 'clone {path}',
                      'archive-excludes': 'archive-excludes {repository}',
                      'install': 'install {path} {version}', 'note': 'note {path}',
                      'link': 'link {path} -> {target}', 'unlink': 'unlink {path}'}
                     [action['do']].format(**action))
    return lines + [f'{finding["finding"]} {finding["path"]}' for finding in plan['findings']]


def refusal(operation):
    try:
        operation()
    except Refused as refused:
        return refused.kind
    return None


def status(directory):
    return subprocess.run(['git', 'status', '--porcelain'], cwd=directory, check=True,
                          capture_output=True, text=True).stdout


def names(directory, within='.agents/skills'):
    inside = Path(directory) / within
    return sorted(os.listdir(inside)) if inside.is_dir() else []


def excludes(directory):
    file = Path(tree._exclude_file(directory))
    return file.read_text(encoding='utf-8').split('\n')[:-1] if file.exists() else []


class Reader(unittest.TestCase):
    def test_a_config_is_read_as_the_fixtures_say(self):
        found = fixtures('pos-directory')
        self.assertGreater(len(found), 20)
        for name, fixture in found:
            with self.subTest(name):
                expected = fixture['refused'] if 'refused' in fixture else fixture['config']
                self.assertEqual(read(fixture['yaml']), expected)

    def test_a_scalar_is_the_text_written_whatever_yaml_would_make_of_it(self):
        made = tree.read_config(
            'pos: 2\nchildren:\n  - path: projects/a\n    remote: 2026-10-01\n    branch: 0x1f\n')
        self.assertEqual(made['children'][0]['remote'], '2026-10-01')
        self.assertEqual(made['children'][0]['branch'], '0x1f')

    def test_text_that_is_not_yaml_is_refused(self):
        self.assertEqual(read('pos: [1\n'), 'not-yaml')


class Trees(unittest.TestCase):
    def setUp(self):
        self.dir = os.path.realpath(tempfile.mkdtemp(prefix='pyposlib-tree-'))
        self.addCleanup(shutil.rmtree, self.dir)
        patch = mock.patch.dict(os.environ, GIT)
        patch.start()
        self.addCleanup(patch.stop)

    def path(self, *parts):
        return os.path.join(self.dir, *parts)

    def plan(self, root, source=None):
        """The plan of the tree at root, with source to install from if
        any, which poslib must give too."""
        made = tree.plan(root, source)
        if shutil.which(EMACS):
            packages = [arg for name in ('markdown-mode', 'yaml')
                        for arg in ('-L', str(POSLIB.resolve() / '_deps' / name))]
            result = subprocess.run([EMACS, '-Q', '--batch', *packages, '-L', str(POSLIB / 'lisp'),
                                     '-l', 'pos-tree', '-f', 'pos-tree-batch', 'plan', root,
                                     *([] if source is None else [source])],
                                    capture_output=True)
            self.assertIn(result.returncode, (0, 1), result.stderr.decode())
            self.assertEqual(encoded(made), result.stdout)
        return made

    def settle(self, root, source=None):
        """Plan and apply at root until a plan has no action; that plan."""
        made = self.plan(root, source)
        for _ in range(10):
            if not made['actions']:
                return made
            tree.apply(root, made, source)
            made = self.plan(root, source)
        self.fail('The tree does not settle')

    # Mounts

    def test_each_scopes_archive_obeys_its_own_policy(self):
        root = repository(self.path('root'), {
            '.clanka/config.yml': 'pos: 2\nprojects: projects/\nchildren:\n  - path: work\n'
                                  'archives:\n  - scope: .\n    kept: committed\n',
            'work/.clanka/config.yml': 'pos: 2\nprojects: projects/\narchives:\n'
                                       '  - scope: published\n    kept: committed\n',
            'work/archive-integrity/README': 'The ledger stays in Git.\n',
        })
        for name in ('archives', 'work/archives', 'work/old/archives', 'work/published/archives'):
            write(root, name + '/evidence', 'Retain this.\n')
        self.settle(root)
        for name in ('work/archives/evidence', 'work/old/archives/evidence'):
            result = subprocess.run(['git', 'check-ignore', '-q', name], cwd=root)
            self.assertEqual(result.returncode, 0, name)
        for name in ('archives/evidence', 'work/published/archives/evidence'):
            result = subprocess.run(['git', 'check-ignore', '-q', name], cwd=root)
            self.assertEqual(result.returncode, 1, name)
        self.assertTrue(tree._tracked(root, 'work/archive-integrity/README'))
        self.assertEqual(Path(root, 'work/archives/evidence').read_text(), 'Retain this.\n')

    def test_archive_policy_changes_preserve_other_exclusions_and_files(self):
        root = repository(self.path('root'), {'.pos/config.yml': 'pos: 2\nprojects: projects/\n'})
        file = Path(tree._exclude_file(root))
        file.write_text('/private-file\n')
        write(root, 'archives/evidence', 'Retain this.\n')
        self.settle(root)
        self.assertEqual(subprocess.run(['git', 'check-ignore', '-q', 'archives/evidence'], cwd=root).returncode, 0)
        stale = self.plan(root)
        write(root, '.pos/config.yml', text())
        self.assertEqual(refusal(lambda: tree.apply(root, stale)), 'stale-plan')
        self.settle(root)
        self.assertEqual(file.read_text(), '/private-file\n')
        self.assertEqual(subprocess.run(['git', 'check-ignore', '-q', 'archives/evidence'], cwd=root).returncode, 1)
        self.assertEqual(Path(root, 'archives/evidence').read_text(), 'Retain this.\n')

    def test_archive_rules_stop_at_products_and_undeclared_nodes(self):
        root = repository(self.path('root'), {
            '.pos/config.yml': 'pos: 2\nprojects: projects/\nchildren:\n  - path: product\n'
                              'archives:\n  - scope: stray\n    kept: uncommitted\n',
            'product/archives/evidence': 'A product owns this.\n',
            'stray/.pos/config.yml': 'pos: 2\nprojects: projects/\n',
            'stray/archives/evidence': 'An undeclared node owns this.\n',
        })
        self.settle(root)
        rules = Path(tree._exclude_file(root)).read_text()
        self.assertIn('/archives/\n', rules)
        self.assertNotIn('/product/archives/', rules)
        self.assertNotIn('/stray/archives/', rules)

    def test_archive_patterns_are_literal_and_future_scopes_are_covered(self):
        root = repository(self.path('root'), {
            '.pos/config.yml': 'pos: 2\nprojects: projects/\narchives:\n'
                              '  - scope: "jobs/[one]* x"\n    kept: uncommitted\n'})
        self.settle(root)
        for name in ('jobs/[one]* x/archives/evidence', 'jobs/one x/archives/evidence'):
            write(root, name, 'evidence\n')
        self.assertEqual(subprocess.run(['git', 'check-ignore', '-q', 'jobs/[one]* x/archives/evidence'], cwd=root).returncode, 0)
        self.assertEqual(subprocess.run(['git', 'check-ignore', '-q', 'jobs/one x/archives/evidence'], cwd=root).returncode, 1)

    def test_mounted_archive_policy_comes_from_the_committed_configuration(self):
        origin = repository(self.path('origin'), {'.pos/config.yml': 'pos: 2\nprojects: projects/\n'})
        root = repository(self.path('root'), config(child('child', origin)))
        self.settle(root)
        mounted = self.path('root/child')
        write(mounted, '.pos/config.yml', text())
        write(mounted, 'archives/evidence', 'evidence\n')
        self.settle(root)
        self.assertEqual(subprocess.run(['git', 'check-ignore', '-q', 'archives/evidence'], cwd=mounted).returncode, 0)

    def test_archive_only_operation_does_not_clone_or_link(self):
        root = repository(self.path('root'), {
            '.pos/config.yml': 'pos: 2\nprojects: projects/\nchildren:\n'
                              '  - path: missing\n    remote: /nonexistent\n',
            **skill('own')})
        remaining = tree.ignore_archives(root)
        self.assertEqual(remaining, self.plan(root))
        self.assertNotIn('archive-excludes', [a['do'] for a in remaining['actions']])
        self.assertFalse(Path(root, 'missing').exists())
        self.assertFalse(Path(root, '.claude').exists())

    def test_bad_child_configuration_keeps_existing_archive_rules(self):
        root = repository(self.path('root'), {
            '.pos/config.yml': text('  - path: child\n'),
            'child/.pos/config.yml': 'pos: 2\nprojects: projects/\n'})
        self.settle(root)
        file = Path(tree._exclude_file(root))
        before = file.read_bytes()
        write(root, 'child/.pos/config.yml', 'pos: 999\n')
        self.settle(root)
        self.assertEqual(file.read_bytes(), before)

    def test_a_repository_that_declares_nothing_needs_nothing(self):
        root = repository(self.path('root'), {'README': 'root\n'})
        self.assertEqual(self.plan(root), {'pos': 2, 'actions': [], 'findings': [], 'warnings': []})

    def test_only_a_repository_is_planned(self):
        self.assertEqual(refusal(lambda: tree.plan(self.dir)), 'not-a-repository')

    def test_a_missing_child_is_excluded_and_then_cloned(self):
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), config(child('projects/child', origin)))
        self.assertEqual(summary(self.plan(root)), ['exclude . projects/child', 'clone projects/child'])
        self.assertEqual(summary(self.settle(root)), [])
        self.assertTrue(os.path.exists(self.path('root/projects/child/README')))

    def test_a_child_off_its_branch_is_found_and_left(self):
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), config(child('projects/child', origin)))
        self.settle(root)
        git(self.path('root/projects/child'), 'switch', '-q', '-c', 'other')
        self.assertEqual(summary(self.plan(root)), ['off-branch projects/child'])

    def test_a_path_taken_is_found_and_left(self):
        """By a repository of another remote, a plain directory and a link."""
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        other = repository(self.path('origins/other'), {'README': 'other\n'})
        root = repository(self.path('root'), config(child('projects/a', origin),
                                                    child('projects/b', origin),
                                                    child('projects/c', origin)))
        git(root, 'clone', '-q', other, self.path('root/projects/a'))
        write(root, 'projects/b/notes', 'not a repository\n')
        os.symlink('b', self.path('root/projects/c'))
        self.assertEqual([line for line in summary(self.plan(root)) if not line.startswith('exclude')],
                         ['other-remote projects/a', 'path-taken projects/b', 'path-taken projects/c'])

    def test_an_undeclared_repository_is_found(self):
        root = repository(self.path('root'), {'README': 'root\n'})
        repository(self.path('root/projects/a'))
        repository(self.path('root/responsibilities/plain/projects/b'))
        self.assertEqual(summary(self.plan(root)),
                         ['undeclared projects/a', 'undeclared responsibilities/plain/projects/b'])

    def test_a_childs_config_is_read_as_committed(self):
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), config(child('projects/child', origin)))
        self.settle(root)
        write(self.path('root/projects/child'), '.pos/config.yaml',
              config(child('projects/more', origin))['.pos/config.yaml'])
        self.assertEqual(summary(self.plan(root)), [])

    def test_a_refused_config_is_found_and_nothing_beneath_planned(self):
        """A configuration the reader refuses is a finding, and nothing is
        planned in that repository or beneath it."""
        both = 'pos: 2\nprojects: p/\nmethodologies: m/\n'
        origin = repository(self.path('origins/child'), {'.pos/config.yaml': both, **skill('c')})
        root = repository(self.path('root'), {**config(child('projects/child', origin)), **skill('r')})
        settled = self.settle(root)
        self.assertEqual([line for line in summary(settled) if 'child' in line],
                         ['config-refused projects/child'])
        self.assertEqual(settled['findings'][0]['detail'],
                         'bad-value: A node says where its projects belong or its methodologies, not both')
        write(root, '.pos/config.yaml', both)
        self.assertEqual(summary(self.plan(root)), ['config-refused .'])

    def test_an_unknown_key_is_a_warning_the_plan_carries(self):
        """A key the reader does not know refuses nothing: the configuration
        is read without it, and the plan names the node and the key."""
        root = repository(self.path('root'), {
            '.pos/config.yaml': 'pos: 2\nprojects: projects/\ncolour: blue\nchildren:\n  - path: work\n',
            'work/.clanka/config.yml': 'pos: 2\nprojects: projects/\nsweep: weekly\n'})
        made = self.plan(root)
        self.assertEqual(made['warnings'], ['.: unknown-key: colour', 'work: unknown-key: sweep'])
        self.assertEqual(made['findings'], [])

    def test_exclusions_are_inherited_until_a_node_declares_its_own(self):
        """A node's exclude replaces the default beneath it, by name, glob or
        path; a local node without one inherits, and one with its own
        replaces them beneath itself."""
        root = repository(self.path('root'), {
            '.clanka/config.yaml': ('pos: 2\nprojects: projects/\nchildren:\n  - path: work\n'
                                    '  - path: lab\nexclude:\n  - vendor\n  - "tmp*"\n  - stray/deep\n'),
            'work/.clanka/config.yml': 'pos: 2\nprojects: projects/\n',
            'lab/.clanka/config.yml': 'pos: 2\nprojects: projects/\nexclude:\n  - attic\n'})
        for path in ('vendor/lib', 'tmpfiles/lib', 'stray/deep/lib', 'attic/lib',
                     'work/vendor/lib', 'work/attic/lib', 'lab/vendor/lib', 'lab/attic/lib'):
            repository(self.path('root/' + path), {'README': 'l\n'})
        self.assertEqual([line for line in summary(self.plan(root)) if line.startswith('undeclared')],
                         ['undeclared attic/lib', 'undeclared lab/vendor/lib', 'undeclared work/attic/lib'])

    def test_archive_scopes_are_not_looked_for_in_excluded_directories(self):
        """An archives directory beneath an excluded one is no scope of the
        node's; one that is not excluded is, as before."""
        root = repository(self.path('root'), {
            '.clanka/config.yaml': 'pos: 2\nprojects: projects/\nexclude:\n  - old\n'})
        write(root, 'old/archives/evidence', 'old\n')
        write(root, 'kept/archives/evidence', 'kept\n')
        action = next(a for a in self.plan(root)['actions'] if a['do'] == 'archive-excludes')
        self.assertEqual(action['paths'], ['archives', 'kept/archives'])

    # Names, kinds and directories

    def test_a_configuration_has_either_name(self):
        """Any of the directory names and either file name is read, alike."""
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        for number, file in enumerate(('.clanka/config.yaml', '.clanka/config.yml',
                                       '.clankos/config.yaml', '.clankos/config.yml',
                                       '.pos/config.yaml', '.pos/config.yml')):
            with self.subTest(file):
                root = repository(self.path(f'root-{number}'), {'README': 'root\n'})
                write(root, file, text(child('work', origin)))
                self.assertEqual(tree.config_file(root), file)
                self.assertEqual(summary(self.plan(root)), ['exclude . work', 'clone work'])

    def test_two_configurations_are_refused(self):
        """Two directories, or both file names in one, and nothing is planned."""
        for number, other in enumerate(('.pos/config.yaml', '.clankos/config.yaml', '.clanka/config.yml')):
            with self.subTest(other):
                root = repository(self.path(f'root-{number}'), {'README': 'root\n'})
                write(root, '.clanka/config.yaml', 'pos: 2\nprojects: projects/\n')
                write(root, other, 'pos: 2\nprojects: projects/\n')
                self.assertEqual(refusal(lambda: tree.config_file(root)), 'two-configurations')
                self.assertEqual(summary(self.plan(root)), ['config-refused .'])

    def test_a_child_s_configuration_is_read_from_its_branch_by_either_name(self):
        """A mounted child that names itself .clanka/config.yml declares as
        any other."""
        grandchild = repository(self.path('origins/grandchild'), {'README': 'g\n'})
        middle = repository(self.path('origins/child'),
                            {'.clanka/config.yml': text(child('deeper', grandchild))})
        root = repository(self.path('root'), {'README': 'root\n'})
        write(root, '.clanka/config.yaml', text(child('child', middle)))
        self.assertEqual(summary(self.settle(root)), [])
        self.assertTrue(os.path.exists(self.path('root/child/deeper/README')))

    def test_a_node_that_names_neither_location_is_unconfigured(self):
        """It is found, and what it declares is planned all the same."""
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), {'README': 'root\n'})
        write(root, '.clanka/config.yaml', 'pos: 2\nchildren:\n' + child('work', origin))
        self.assertEqual(summary(self.plan(root)), ['exclude . work', 'clone work', 'archive-excludes .', 'unconfigured .'])

    def test_a_child_with_no_remote_is_a_directory(self):
        """The directory itself is not excluded or cloned; one that is not there is
        found."""
        root = repository(self.path('root'), {'README': 'root\n', 'health/README': 'health\n'})
        write(root, '.clanka/config.yaml',
              'pos: 2\nprojects: projects/\nchildren:\n  - path: health\n  - path: wealth\n'
              '  - path: README\n')
        self.assertEqual(summary(self.plan(root)), ['archive-excludes .', 'path-taken README', 'missing wealth'])

    def test_a_directory_declares_what_is_beneath_it(self):
        """A directory's own configuration mounts a repository beneath it,
        which is excluded in the repository the directory is part of, and
        is given none of that repository's skills."""
        product = repository(self.path('origins/product'), {'README': 'product\n'})
        root = repository(self.path('root'),
                          {'employment/.clanka/config.yaml': text(child('widget', product)), **skill('r')})
        write(root, '.clanka/config.yaml', 'pos: 2\nprojects: projects/\nchildren:\n  - path: employment\n')
        self.assertEqual([line for line in summary(self.plan(root)) if 'widget' in line],
                         ['exclude . employment/widget', 'clone employment/widget'])
        self.assertEqual(summary(self.settle(root)), [])
        self.assertTrue(os.path.exists(self.path('root/employment/widget/README')))
        self.assertFalse(os.path.exists(self.path('root/employment/widget/.agents')))

    def test_a_repository_declared_with_no_remote_is_found(self):
        root = repository(self.path('root'), {'README': 'root\n'})
        repository(self.path('root/health'), {'README': 'h\n'})
        write(root, '.clanka/config.yaml', 'pos: 2\nprojects: projects/\nchildren:\n  - path: health\n')
        self.assertEqual(summary(self.plan(root)), ['archive-excludes .', 'path-taken health'])

    def test_what_no_entry_declares_is_found_wherever_it_is(self):
        """A repository, and a directory with a configuration, at any depth;
        but not in an archive, an attic, or a hidden or underscore
        directory."""
        node = 'pos: 2\nprojects: projects/\n'
        root = repository(self.path('root'), {'README': 'root\n',
                                              'health/.clanka/config.yaml': node,
                                              'health/diet/.pos/config.yml': node,
                                              'stray/deep/.clanka/config.yaml': node,
                                              'archives/old/.clanka/config.yaml': node,
                                              '_work/x/.clanka/config.yaml': node})
        # A submodule is tracked, and is not found.
        module = repository(self.path('origins/module'), {'README': 'm\n'})
        git(root, '-c', 'protocol.file.allow=always', 'submodule', '--quiet', 'add', module, 'tests/module')
        commit(root)
        repository(self.path('root/vendor/lib'), {'README': 'l\n'})
        repository(self.path('root/attic/lib'), {'README': 'l\n'})
        write(root, '.clanka/config.yaml', 'pos: 2\nprojects: projects/\nchildren:\n  - path: health\n')
        made = self.plan(root)
        self.assertEqual(summary(made), ['archive-excludes .', 'undeclared health/diet', 'undeclared stray/deep',
                                         'undeclared vendor/lib'])
        self.assertEqual([finding.get('detail') for finding in made['findings']],
                         ['a configuration', 'a configuration', None])

    def test_a_worktree_of_a_child_is_excluded_and_cloned(self):
        """One on a branch the child's remote has, one on a branch made for it."""
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        git(origin, 'switch', '-q', '-c', 'feature')
        commit(origin, {'FEATURE': 'on the branch\n'})
        git(origin, 'switch', '-q', 'master')
        files = config(child('responsibilities/it', origin))
        files['.pos/config.yaml'] += ('worktrees:\n'
                                      '  - path: projects/fix/_worktrees/do-the-thing\n'
                                      '    of: responsibilities/it\n    branch: do-the-thing\n'
                                      '  - path: _worktrees/feature\n'
                                      '    of: responsibilities/it\n    branch: feature\n')
        root = repository(self.path('root'), files)
        self.assertEqual(summary(self.plan(root)),
                         ['exclude . responsibilities/it', 'clone responsibilities/it',
                          'exclude . _worktrees/feature', 'clone _worktrees/feature',
                          'exclude . projects/fix/_worktrees/do-the-thing',
                          'clone projects/fix/_worktrees/do-the-thing'])
        self.assertEqual(summary(self.settle(root)), [])
        self.assertTrue(os.path.exists(self.path('root/_worktrees/feature/FEATURE')))
        self.assertFalse(os.path.exists(self.path('root/projects/fix/_worktrees/do-the-thing/FEATURE')))
        self.assertEqual(status(root), '')

    # The second step

    def test_a_plan_the_tree_no_longer_gives_is_refused(self):
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), config(child('projects/child', origin)))
        made, before = self.plan(root), excludes(root)
        git(root, 'clone', '-q', origin, self.path('root/projects/child'))
        self.assertEqual(refusal(lambda: tree.apply(root, made)), 'stale-plan')
        self.assertEqual(excludes(root), before)

    def test_a_plan_as_printed_is_applied(self):
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), config(child('projects/child', origin)))
        printed = encoded(self.plan(root))
        self.assertEqual(summary(tree.apply(root, json.loads(printed))), [])
        self.assertTrue(os.path.exists(self.path('root/projects/child/README')))

    def test_a_clone_that_fails_is_refused_and_what_was_done_stays(self):
        root = repository(self.path('root'), config(child('projects/child', self.path('origins/absent'))))
        self.assertEqual(refusal(lambda: tree.apply(root, tree.plan(root))), 'failed')
        self.assertEqual(summary(self.plan(root)), ['clone projects/child'])

    def test_an_exclude_is_added_on_a_line_of_its_own(self):
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), config(child('projects/child', origin)))
        Path(tree._exclude_file(root)).write_text('*.log', encoding='utf-8')
        self.settle(root)
        self.assertEqual(excludes(root), ['*.log', '/projects/child'])
        self.settle(root)
        self.assertEqual(len(excludes(root)), 2)

    def test_the_command_line_plans_and_applies(self):
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), config(child('projects/child', origin)))
        file = self.path('plan.json')
        with open(file, 'wb') as out, mock.patch('sys.stdout') as stdout:
            stdout.buffer = out
            self.assertEqual(tree.main(['plan', root]), 1)
        with mock.patch('sys.stdout') as stdout:
            stdout.buffer = open(os.devnull, 'wb')
            self.addCleanup(stdout.buffer.close)
            self.assertEqual(tree.main(['apply', root, file]), 0)
            with mock.patch('sys.stderr'):
                self.assertEqual(tree.main(['apply', root, file]), 2)
        self.assertTrue(os.path.exists(self.path('root/projects/child/README')))

    # What is installed

    def test_each_configured_repository_has_the_same_installed(self):
        """A root, a responsibility mounted in it, and a product mounted in
        that. Once settled, the root and the responsibility each hold the
        source in auto/ with a link to its skill, the root has a link to the
        command where it says bin, and the product has nothing of the
        tool's. No repository sees a change to commit."""
        given = source(self.path('source'), '1', 'clankos-capture', 'pos-capture')
        product = repository(self.path('origins/product'), skill('release'))
        middle = repository(self.path('origins/child'),
                            {'.clanka/config.yml': text(child('products/product', product))})
        root = repository(self.path('root'),
                          {'.clanka/config.yml': text(child('responsibilities/child', middle)) + 'bin: bin\n'})
        self.assertEqual(summary(self.settle(root, given)), [])
        in_child = self.path('root/responsibilities/child')
        in_product = os.path.join(in_child, 'products/product')
        for directory in (root, in_child):
            self.assertEqual(Path(directory, '.clanka/auto/version').read_text(), '1\n')
            self.assertEqual(os.readlink(os.path.join(directory, '.agents/skills/clankos-capture')),
                             '../../.clanka/auto/skills/clankos-capture')
            self.assertTrue(os.path.exists(os.path.join(directory, '.agents/skills/clankos-capture/SKILL.md')))
            self.assertEqual(os.readlink(os.path.join(directory, '.claude/skills')), '../.agents/skills')
        self.assertEqual(os.readlink(os.path.join(root, 'bin/pos-capture')), '../.clanka/auto/bin/pos-capture')
        self.assertTrue(os.access(os.path.join(root, 'bin/pos-capture'), os.X_OK))
        self.assertFalse(os.path.exists(os.path.join(in_child, 'bin')))
        self.assertEqual(names(in_product), ['release'])
        self.assertFalse(os.path.lexists(os.path.join(in_product, '.claude')))
        self.assertFalse(os.path.exists(os.path.join(in_product, '.clanka')))
        for directory in (root, in_child, in_product):
            self.assertEqual(status(directory), '')
        self.assertEqual(summary(self.plan(root, given)), [])

    def test_with_no_source_nothing_is_installed(self):
        root = repository(self.path('root'), {'.clanka/config.yml': text()})
        self.assertEqual(summary(self.plan(root)), [])

    def test_a_repository_with_no_configuration_is_left_alone(self):
        """Nothing is installed in it, its own skills are not read, and no
        .claude/skills link is made."""
        given = source(self.path('source'), '1', 'clankos-capture')
        root = repository(self.path('root'), skill('own'))
        self.assertEqual(summary(self.plan(root, given)), [])

    def test_what_is_installed_stays_until_the_source_changes(self):
        given = source(self.path('source'), '1', 'clankos-capture')
        root = repository(self.path('root'), {'.clanka/config.yml': text()})
        self.settle(root, given)
        self.assertEqual(summary(self.plan(root)), [])
        self.assertEqual(names(root), ['clankos-capture'])

    def test_a_newer_source_replaces_what_was_installed(self):
        """A source of another version replaces auto/ whole. The link to a
        skill it leaves out is removed, and a link to one it adds is made."""
        given = source(self.path('source'), '1', 'clankos-capture', 'clankos-old')
        root = repository(self.path('root'), {'.clanka/config.yml': text()})
        self.settle(root, given)
        write(root, '.clanka/auto/scribble', "a person's\n")
        source(given, '2', 'clankos-capture', 'clankos-new')
        self.assertEqual(sorted(summary(self.plan(root, given))),
                         ['exclude . .agents/skills/clankos-new', 'install .clanka/auto 2',
                          'link .agents/skills/clankos-new -> ../../.clanka/auto/skills/clankos-new',
                          'unlink .agents/skills/clankos-old'])
        self.assertEqual(summary(self.settle(root, given)), [])
        self.assertEqual(names(root), ['clankos-capture', 'clankos-new'])
        self.assertEqual(names(root, '.clanka/auto/skills'), ['clankos-capture', 'clankos-new'])
        self.assertFalse(os.path.exists(os.path.join(root, '.clanka/auto/scribble')))
        self.assertEqual(status(root), '')

    def test_a_name_taken_is_found_and_left(self):
        """Where something else has a link's name, it is left and found.
        The finding says whether the repository tracks it, and the other
        links are made."""
        given = source(self.path('source'), '1', 'clankos-capture', 'clankos-seal', 'pos-capture')
        root = repository(self.path('root'),
                          {'.clanka/config.yml': text() + 'bin: bin\n', **skill('clankos-capture')})
        write(root, 'bin/pos-capture', '#!/bin/sh\n')
        settled = self.settle(root, given)
        self.assertEqual(summary(settled),
                         ['name-taken .agents/skills/clankos-capture', 'name-taken bin/pos-capture'])
        self.assertRegex(settled['findings'][0]['detail'], r'\Atracked, added in [0-9a-f]+\Z')
        self.assertEqual(settled['findings'][1]['detail'], 'untracked')
        self.assertFalse(os.path.islink(os.path.join(root, '.agents/skills/clankos-capture')))
        self.assertTrue(os.path.islink(os.path.join(root, '.agents/skills/clankos-seal')))
        self.assertEqual(Path(root, 'bin/pos-capture').read_text(), '#!/bin/sh\n')

    def test_a_skills_path_that_is_not_a_directory_is_found(self):
        given = source(self.path('source'), '1', 'clankos-capture')
        root = repository(self.path('root'), {'.clanka/config.yml': text(), '.agents': 'a file\n'})
        self.assertEqual(summary(self.settle(root, given)), ['name-taken .agents'])
        self.assertEqual(Path(root, '.agents').read_text(), 'a file\n')

    def test_an_ordinary_claude_skills_has_the_links_and_a_note(self):
        """A real .claude/skills directory gets the skill links too, and a
        note that names what in it is no skill. Once the directory is
        replaced by a link, the note is removed from where it was moved to."""
        given = source(self.path('source'), '1', 'clankos-capture')
        root = repository(self.path('root'),
                          {'.clanka/config.yml': text(),
                           '.claude/skills/old/SKILL.md': '---\nname: old\n---\n',
                           '.claude/skills/loose.md': 'Not a skill.\n'})
        self.assertEqual(summary(self.settle(root, given)), [])
        for within in ('.agents/skills', '.claude/skills'):
            self.assertEqual(os.readlink(os.path.join(root, within, 'clankos-capture')),
                             '../../.clanka/auto/skills/clankos-capture')
        note = Path(root, '.claude/skills', tree.NOTE)
        self.assertRegex(note.read_text(), r'(?m)^  loose\.md$')
        self.assertNotRegex(note.read_text(), r'(?m)^  old$')
        self.assertEqual(status(root), '')
        # The person moves everything and replaces the directory by a link.
        note.rename(Path(root, '.agents/skills', tree.NOTE))
        shutil.rmtree(os.path.join(root, '.claude/skills'))
        os.symlink('../.agents/skills', os.path.join(root, '.claude/skills'))
        self.assertEqual(summary(self.plan(root, given)), ['unlink .agents/skills/README.clankos'])
        self.assertEqual(summary(self.settle(root, given)), [])
        self.assertEqual(names(root), ['clankos-capture'])

    def test_a_claude_path_that_is_not_a_directory_is_left(self):
        """A file, a link or a dangling link at .claude or .claude/skills is
        left, in a mounted repository too. The skills are installed all the
        same, and the tree is clean after."""
        for path in ('.claude', '.claude/skills'):
            for kind in ('file', 'link', 'dangling'):
                with self.subTest(path=path, kind=kind):
                    case = self.path(path.replace('/', '-') + '-' + kind)
                    given = source(os.path.join(case, 'source'), '1', 'clankos-capture')
                    origin = repository(os.path.join(case, 'origins/child'),
                                        {'.clanka/config.yml': text()})
                    at = Path(origin, path)
                    at.parent.mkdir(parents=True, exist_ok=True)
                    if kind == 'file':
                        at.write_text('existing\n')
                    else:
                        target = Path(origin, 'foreign')
                        if kind == 'link':
                            write(target, 'skills/private/SKILL.md', 'private\n')
                        at.symlink_to(target)
                    commit(origin)
                    root = repository(os.path.join(case, 'root'),
                                      {'.clanka/config.yml': text(child('child', origin))})
                    self.assertEqual(summary(self.settle(root, given)), [])
                    mounted = Path(root, 'child')
                    self.assertEqual(status(mounted), '')
                    self.assertEqual(names(mounted), ['clankos-capture'])
                    if kind == 'file':
                        self.assertEqual((mounted / path).read_text(), 'existing\n')
                    else:
                        self.assertEqual(os.readlink(mounted / path), os.readlink(at))
                    self.assertEqual(summary(self.plan(root, given)), [])

    def test_a_link_an_earlier_tool_made_is_removed(self):
        """A link from one repository's skills to another's is removed: from
        a product too, since the tool made it."""
        product = repository(self.path('origins/product'), {'README': 'product\n'})
        root = repository(self.path('root'),
                          {'.clanka/config.yml': text(child('products/product', product)), **skill('r')})
        self.settle(root)
        link = self.path('root/products/product/.agents/skills/r')
        os.makedirs(os.path.dirname(link))
        os.symlink('../../../../.agents/skills/r', link)
        self.assertEqual(summary(self.plan(root)), ['unlink products/product/.agents/skills/r'])
        self.settle(root)
        self.assertFalse(os.path.islink(link))

    def test_a_link_to_outside_the_tree_is_left(self):
        given = source(self.path('source'), '1', 'clankos-capture')
        root = repository(self.path('root'), {'.clanka/config.yml': text()})
        elsewhere = self.path('elsewhere/.agents/skills/r')
        write(elsewhere, 'SKILL.md', '---\nname: r\n---\n')
        link = self.path('root/.agents/skills/r')
        os.makedirs(os.path.dirname(link))
        os.symlink(elsewhere, link)
        self.settle(root, given)
        self.assertEqual(os.readlink(link), elsewhere)

    def test_installing_alone_clones_nothing(self):
        """Only what is installed is done, and the rest stays planned: a
        declared child that is not there is excluded and stays to be cloned."""
        given = source(self.path('source'), '1', 'clankos-capture')
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'),
                          {'.clanka/config.yml': text(child('projects/child', origin))})
        remaining = tree.install(root, given)
        self.assertEqual(remaining, self.plan(root, given))
        self.assertEqual(summary(remaining), ['clone projects/child'])
        self.assertTrue(os.path.exists(os.path.join(root, '.agents/skills/clankos-capture/SKILL.md')))
        self.assertFalse(os.path.exists(os.path.join(root, 'projects/child')))
        self.assertEqual(status(root), '')
        with mock.patch('sys.stdout') as stdout:
            stdout.buffer = open(os.devnull, 'wb')
            self.addCleanup(stdout.buffer.close)
            self.assertEqual(tree.main(['install', root, given]), 1)

    def test_a_source_that_is_not_one_is_refused(self):
        root = repository(self.path('root'), {'.clanka/config.yml': text()})
        write(self.dir, 'unversioned/skills/clankos-a/SKILL.md', '---\n---\n')
        self.assertEqual(refusal(lambda: tree.plan(root, self.path('unversioned'))), 'bad-source')
        write(self.dir, 'misnamed/version', '1\n')
        write(self.dir, 'misnamed/skills/capture/SKILL.md', '---\n---\n')
        self.assertEqual(refusal(lambda: tree.plan(root, self.path('misnamed'))), 'bad-source')

    def test_the_command_line_installs_from_a_source(self):
        given = source(self.path('source'), '1', 'clankos-capture')
        root = repository(self.path('root'), {'.clanka/config.yml': text()})
        file = self.path('plan.json')
        with open(file, 'wb') as out, mock.patch('sys.stdout') as stdout:
            stdout.buffer = out
            self.assertEqual(tree.main(['plan', root, given]), 1)
        with mock.patch('sys.stdout') as stdout:
            stdout.buffer = open(os.devnull, 'wb')
            self.addCleanup(stdout.buffer.close)
            self.assertEqual(tree.main(['apply', root, file, given]), 0)
        self.assertEqual(names(root), ['clankos-capture'])

if __name__ == '__main__':
    unittest.main()
