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


def skill(name, local=False):
    """The files of a skill name; local marks it .pos-local."""
    files = {f'.agents/skills/{name}/SKILL.md': f'---\nname: {name}\ndescription: A skill.\n---\n'}
    if local:
        files[f'.agents/skills/{name}/.pos-local'] = ''
    return files


def child(path, remote, *more):
    """A child entry of a config.yaml: path, remote and more lines."""
    return f'  - path: {path}\n    remote: {remote}\n' + ''.join(f'    {line}\n' for line in more)


def text(*children):
    """A config.yaml's text declaring children, each an entry's text."""
    return 'pos: 2\nprojects: projects/\nchildren:\n' + ''.join(children)


def config(*children):
    return {'.pos/config.yaml': text(*children)}


def summary(plan):
    """A plan as a list of strings, its actions and then its findings."""
    lines = []
    for action in plan['actions']:
        lines.append({'exclude': 'exclude {repository} {path}', 'clone': 'clone {path}',
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


def names(directory):
    skills = Path(directory) / '.agents' / 'skills'
    return sorted(os.listdir(skills)) if skills.is_dir() else []


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

    def plan(self, root):
        """The plan of the tree at root, which poslib must give too."""
        made = tree.plan(root)
        if shutil.which(EMACS):
            packages = ('(progn (require (quote package)) (setq package-user-dir "%s") '
                        '(package-initialize))' % (POSLIB.resolve() / '_deps'))
            result = subprocess.run([EMACS, '-Q', '--batch', '--eval', packages, '-L', str(POSLIB / 'lisp'),
                                     '-l', 'pos-tree', '-f', 'pos-tree-batch', 'plan', root],
                                    capture_output=True)
            self.assertIn(result.returncode, (0, 1), result.stderr.decode())
            self.assertEqual(encoded(made), result.stdout)
        return made

    def settle(self, root):
        """Plan and apply at root until a plan has no action; that plan."""
        made = self.plan(root)
        for _ in range(10):
            if not made['actions']:
                return made
            tree.apply(root, made)
            made = self.plan(root)
        self.fail('The tree does not settle')

    # Mounts

    def test_a_repository_that_declares_nothing_needs_nothing(self):
        root = repository(self.path('root'), {'README': 'root\n'})
        self.assertEqual(self.plan(root), {'pos': 2, 'actions': [], 'findings': []})

    def test_only_a_repository_is_planned(self):
        self.assertEqual(refusal(lambda: tree.plan(self.dir)), 'not-a-repository')

    def test_a_missing_child_is_excluded_and_then_cloned(self):
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), config(child('projects/child', origin)))
        self.assertEqual(summary(self.plan(root)), ['exclude . projects/child', 'clone projects/child'])
        self.assertEqual(summary(self.settle(root)), [])
        self.assertTrue(os.path.exists(self.path('root/projects/child/README')))

    def test_a_tree_settles_with_its_skills_linked_down(self):
        """A root, a child and a child of that child, each with a skill.
        Once settled each has its containers' skills as links that resolve
        and its .claude/skills link, and no repository sees a change."""
        grandchild = repository(self.path('origins/grandchild'), skill('g'))
        middle = repository(self.path('origins/child'),
                            {**config(child('projects/grandchild', grandchild)), **skill('c')})
        root = repository(self.path('root'),
                          {**config(child('responsibilities/child', middle)), **skill('r')})
        self.assertEqual(summary(self.settle(root)), [])
        in_child = self.path('root/responsibilities/child')
        in_grandchild = os.path.join(in_child, 'projects/grandchild')
        self.assertEqual(os.readlink(os.path.join(in_child, '.agents/skills/r')),
                         '../../../../.agents/skills/r')
        for name in ('r', 'c'):
            self.assertTrue(os.path.exists(os.path.join(in_grandchild, f'.agents/skills/{name}/SKILL.md')))
        for directory in (root, in_child, in_grandchild):
            self.assertEqual(os.readlink(os.path.join(directory, '.claude/skills')), '../.agents/skills')
            self.assertEqual(status(directory), '')

    def test_a_child_off_its_branch_is_found_and_left(self):
        origin = repository(self.path('origins/child'), skill('c'))
        root = repository(self.path('root'),
                          {**config(child('projects/child', origin, 'skills-up: true')), **skill('r')})
        self.settle(root)
        in_child = self.path('root/projects/child')
        os.remove(os.path.join(in_child, '.agents/skills/r'))
        git(in_child, 'switch', '-q', '-c', 'other')
        self.assertEqual(summary(self.plan(root)), ['off-branch projects/child'])
        self.assertEqual(names(root), ['c', 'r'])

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
        origin = repository(self.path('origins/child'),
                            {'.pos/config.yaml': 'pos: 2\nteam: []\n', **skill('c')})
        root = repository(self.path('root'), {**config(child('projects/child', origin)), **skill('r')})
        settled = self.settle(root)
        self.assertEqual([line for line in summary(settled) if 'child' in line],
                         ['config-refused projects/child'])
        self.assertEqual(settled['findings'][0]['detail'],
                         'unknown-key: The file has a key this version does not define: team')
        write(root, '.pos/config.yaml', 'pos: 2\nteam: []\n')
        self.assertEqual(summary(self.plan(root)), ['config-refused .'])

    # Names, kinds and directories

    def test_a_configuration_has_either_name(self):
        """Either directory and either file name is read, alike."""
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        for number, file in enumerate(('.clanka/config.yaml', '.clanka/config.yml',
                                       '.pos/config.yaml', '.pos/config.yml')):
            with self.subTest(file):
                root = repository(self.path(f'root-{number}'), {'README': 'root\n'})
                write(root, file, text(child('work', origin)))
                self.assertEqual(tree.config_file(root), file)
                self.assertEqual(summary(self.plan(root)), ['exclude . work', 'clone work'])

    def test_two_configurations_are_refused(self):
        """Both directories, or both file names in one, and nothing is planned."""
        for number, other in enumerate(('.pos/config.yaml', '.clanka/config.yml')):
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
        self.assertEqual(summary(self.plan(root)), ['exclude . work', 'clone work', 'unconfigured .'])

    def test_a_child_with_no_remote_is_a_directory(self):
        """Nothing is excluded or cloned for it; one that is not there is
        found."""
        root = repository(self.path('root'), {'README': 'root\n', 'health/README': 'health\n'})
        write(root, '.clanka/config.yaml',
              'pos: 2\nprojects: projects/\nchildren:\n  - path: health\n  - path: wealth\n'
              '  - path: README\n')
        self.assertEqual(summary(self.plan(root)), ['path-taken README', 'missing wealth'])

    def test_a_directory_declares_what_is_beneath_it(self):
        """A directory's own configuration mounts a repository beneath it,
        which is excluded in the repository the directory is part of, and
        is given that repository's skills."""
        product = repository(self.path('origins/product'), {'README': 'product\n'})
        root = repository(self.path('root'),
                          {'employment/.clanka/config.yaml': text(child('widget', product)), **skill('r')})
        write(root, '.clanka/config.yaml', 'pos: 2\nprojects: projects/\nchildren:\n  - path: employment\n')
        self.assertEqual([line for line in summary(self.plan(root)) if 'widget' in line],
                         ['exclude . employment/widget', 'clone employment/widget'])
        self.assertEqual(summary(self.settle(root)), [])
        self.assertTrue(os.path.exists(self.path('root/employment/widget/README')))
        self.assertTrue(os.path.exists(self.path('root/employment/widget/.agents/skills/r/SKILL.md')))

    def test_a_repository_declared_with_no_remote_is_found(self):
        root = repository(self.path('root'), {'README': 'root\n'})
        repository(self.path('root/health'), {'README': 'h\n'})
        write(root, '.clanka/config.yaml', 'pos: 2\nprojects: projects/\nchildren:\n  - path: health\n')
        self.assertEqual(summary(self.plan(root)), ['path-taken health'])

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
        self.assertEqual(summary(made), ['undeclared health/diet', 'undeclared stray/deep',
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

    # Skills

    def test_the_nearer_skill_has_a_name(self):
        """A repository's own skill before a link, a nearer container's
        before a farther one's."""
        grandchild = repository(self.path('origins/grandchild'), {'README': 'grandchild\n'})
        middle = repository(self.path('origins/child'),
                            {**config(child('projects/grandchild', grandchild)), **skill('x'),
                             '.agents/skills/x/whose': "child's\n"})
        root = repository(self.path('root'), {**config(child('projects/child', middle)), **skill('x'),
                                              '.agents/skills/x/whose': "root's\n"})
        self.settle(root)
        in_child = self.path('root/projects/child')
        self.assertFalse(os.path.islink(os.path.join(in_child, '.agents/skills/x')))
        for directory in (in_child, os.path.join(in_child, 'projects/grandchild')):
            self.assertEqual(Path(directory, '.agents/skills/x/whose').read_text(), "child's\n")

    def test_a_local_skill_is_not_linked(self):
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), {**config(child('projects/child', origin)),
                                              **skill('shared'), **skill('mine', local=True)})
        self.settle(root)
        self.assertEqual(names(self.path('root/projects/child')), ['shared'])

    def test_skills_go_up_only_from_a_child_marked_for_it(self):
        """And a skill linked up is not linked on to another child."""
        marked = repository(self.path('origins/marked'), skill('m'))
        unmarked = repository(self.path('origins/unmarked'), skill('u'))
        root = repository(self.path('root'), config(child('projects/marked', marked, 'skills-up: true'),
                                                    child('projects/unmarked', unmarked)))
        self.settle(root)
        self.assertEqual(names(root), ['m'])
        self.assertEqual(os.readlink(self.path('root/.agents/skills/m')),
                         '../../projects/marked/.agents/skills/m')
        self.assertEqual(names(self.path('root/projects/unmarked')), ['u'])
        self.assertEqual(status(root), '')

    def test_two_childrens_skills_of_one_name_are_found_and_left(self):
        a = repository(self.path('origins/a'), skill('same'))
        b = repository(self.path('origins/b'), skill('same'))
        root = repository(self.path('root'), config(child('projects/a', a, 'skills-up: true'),
                                                    child('projects/b', b, 'skills-up: true')))
        self.assertEqual(summary(self.settle(root)), ['name-clash .agents/skills/same'])
        self.assertEqual(names(root), [])

    def test_a_link_whose_skill_is_gone_is_removed(self):
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), {**config(child('projects/child', origin)), **skill('r')})
        self.settle(root)
        shutil.rmtree(self.path('root/.agents/skills/r'))
        self.assertEqual(summary(self.plan(root)), ['unlink projects/child/.agents/skills/r'])
        self.settle(root)
        self.assertEqual(names(self.path('root/projects/child')), [])

    def test_a_link_to_outside_the_tree_is_left_and_keeps_its_name(self):
        origin = repository(self.path('origins/child'), {'README': 'child\n'})
        root = repository(self.path('root'), {**config(child('projects/child', origin)), **skill('r')})
        elsewhere = self.path('elsewhere/.agents/skills/r')
        write(elsewhere, 'SKILL.md', '---\nname: r\n---\n')
        git(root, 'clone', '-q', origin, self.path('root/projects/child'))
        link = self.path('root/projects/child/.agents/skills/r')
        os.makedirs(os.path.dirname(link))
        os.symlink(elsewhere, link)
        self.settle(root)
        self.assertEqual(os.readlink(link), elsewhere)

    def test_skills_beneath_claude_are_found(self):
        root = repository(self.path('root'), {'.claude/skills/old/SKILL.md': '---\nname: old\n---\n'})
        self.assertEqual(summary(self.plan(root)), ['claude-skills .claude/skills'])


if __name__ == '__main__':
    unittest.main()
