# SPDX-License-Identifier: Apache-2.0
import ast
import io

import testtools

from bandit.core import meta_ast as b_meta_ast
from bandit.core import name_resolution as b_names
from bandit.core import node_visitor as b_node_visitor
from bandit.core import test_set as b_test_set
from bandit.core import config as b_config


class _StubMetrics:
    def begin(self, *args):
        pass

    def count_locs(self, *args):
        pass

    def count_issues(self, *args):
        pass

    def note_nosec(self, *args):
        pass

    def note_skipped_test(self, *args):
        pass

    def aggregate(self, *args):
        pass


class NameResolutionTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        config = b_config.BanditConfig()
        self.test_set = b_test_set.BanditTestSet(config=config)

    def _trace(self, source):
        visitor = b_node_visitor.BanditNodeVisitor(
            "resolution_test.py",
            io.BytesIO(source.encode()),
            b_meta_ast.BanditMetaAst(),
            self.test_set,
            False,
            {},
            _StubMetrics(),
        )
        visitor.process(source)
        return visitor.resolver.call_trace

    def _call_names(self, source):
        return {
            lineno: qualname
            for lineno, (qualname, _) in self._trace(source).items()
        }

    def _shadowed(self, source):
        return {
            lineno: shadowed
            for lineno, (_, shadowed) in self._trace(source).items()
        }

    def test_direct_and_from_imports_resolve(self):
        names = self._call_names(
            """
import subprocess
import subprocess as sp
from subprocess import Popen as po, run
subprocess.run('a')
sp.run('b')
po('c')
run('d')
"""
        )
        self.assertEqual("subprocess.run", names[5])
        self.assertEqual("subprocess.run", names[6])
        self.assertEqual("subprocess.Popen", names[7])
        self.assertEqual("subprocess.run", names[8])

    def test_parameter_shadows_import(self):
        names = self._call_names(
            """
import subprocess
def f(subprocess):
    subprocess.run('shadowed')
subprocess.run('real')
"""
        )
        # The parameter is a local object; the syntactic dotted name stays
        # available but the root is reported as a shadowed local binding.
        self.assertEqual("subprocess.run", names[4])
        self.assertEqual("subprocess.run", names[5])
        shadowed = self._shadowed(
            """
import subprocess
def f(subprocess):
    subprocess.run('shadowed')
subprocess.run('real')
"""
        )
        self.assertTrue(shadowed[4])
        self.assertFalse(shadowed[5])

    def test_local_assignment_rebinds_import(self):
        names = self._call_names(
            """
import subprocess
subprocess = object()
subprocess.run('rebound')
"""
        )
        self.assertEqual("subprocess.run", names[4])
        shadowed = self._shadowed(
            """
import subprocess
subprocess = object()
subprocess.run('rebound')
"""
        )
        self.assertTrue(shadowed[4])

    def test_nested_function_uses_outer_import(self):
        shadowed = self._shadowed(
            """
import subprocess
def outer():
    def inner():
        subprocess.run('closure')
"""
        )
        self.assertEqual({5: False}, shadowed)

    def test_class_body_is_not_a_closure(self):
        shadowed = self._shadowed(
            """
class C:
    import subprocess as class_import
    def method(self):
        class_import.run('not a closure')
"""
        )
        # The class-body import is invisible to the method, so the name is an
        # unbound free name rather than a known local binding.
        self.assertEqual({5: False}, shadowed)

    def test_lambda_parameter_scope(self):
        shadowed = self._shadowed(
            """
import subprocess
f = lambda subprocess: subprocess.run('parameter')
g = lambda: subprocess.run('closure')
"""
        )
        self.assertTrue(shadowed[3])
        self.assertFalse(shadowed[4])

    def test_comprehension_scope_and_outer_iterable(self):
        names = self._call_names(
            """
import subprocess
[subprocess.run(i) for i in subprocess.queue]
[subprocess for subprocess in range(3)]
"""
        )
        self.assertEqual("subprocess.run", names[3])

    def test_branch_keeps_matching_import(self):
        names = self._call_names(
            """
import subprocess as a
import subprocess as b
if cond:
    x = a
else:
    x = b
x.run('merged')
"""
        )
        self.assertEqual("subprocess.run", names[8])
        shadowed = self._shadowed(
            """
import subprocess as a
import subprocess as b
if cond:
    x = a
else:
    x = b
x.run('merged')
"""
        )
        self.assertFalse(shadowed[8])

    def test_branch_conflict_becomes_unresolved(self):
        shadowed = self._shadowed(
            """
import subprocess as a
if cond:
    x = a
else:
    x = object()
x.run('conflict')
"""
        )
        self.assertTrue(shadowed[7])

    def test_loop_keeps_outer_import_but_marks_loop_bindings(self):
        shadowed = self._shadowed(
            """
import subprocess
for i in range(3):
    other = i
subprocess.run('after loop')
"""
        )
        # The import is untouched by the loop and stays resolved.
        self.assertFalse(shadowed[5])

        shadowed = self._shadowed(
            """
import subprocess as sp
for i in range(3):
    chosen = sp
chosen.run('loop bound')
"""
        )
        # A name only known to be assigned inside the loop cannot keep an
        # imported identity after it completes.
        self.assertTrue(shadowed[5])

    def test_global_and_nonlocal(self):
        shadowed = self._shadowed(
            """
import subprocess
def f():
    global subprocess
    subprocess.run('global')
"""
        )
        self.assertFalse(shadowed[5])

        shadowed = self._shadowed(
            """
def outer():
    value = 1
    def inner():
        nonlocal value
        value.use('nonlocal')
"""
        )
        self.assertTrue(shadowed[6])

    def test_del_removes_module_binding(self):
        shadowed = self._shadowed(
            """
import subprocess
del subprocess
subprocess.run('after del')
"""
        )
        # A deleted module name is an unbound free name, not a known local.
        self.assertEqual({4: False}, shadowed)

    def test_function_default_uses_enclosing_scope(self):
        shadowed = self._shadowed(
            """
import subprocess
def f(run=subprocess.run):
    def run(value):
        return value
    run('inside')
"""
        )
        # The nested function ``run`` is a local binding, while the default
        # expression resolves ``subprocess`` against the enclosing module.
        self.assertEqual({6: True}, shadowed)

        names = self._call_names(
            """
import subprocess
def f(run=subprocess.run()):
    run('inside')
"""
        )
        # The default call keeps the imported qualified identity.
        self.assertEqual("subprocess.run", names[3])

    def test_class_bases_evaluate_in_enclosing_scope(self):
        names = self._call_names(
            """
class Factory:
    @staticmethod
    def build():
        return object

class Sub(Factory.build()):
    pass
"""
        )
        self.assertEqual("Factory.build", names[7])

    def test_unbound_free_name_keeps_legacy_dotted_name(self):
        names = self._call_names(
            """
subprocess.run('free name')
self.eval()
"""
        )
        self.assertEqual("subprocess.run", names[2])
        self.assertEqual("self.eval", names[3])

    def test_import_aliases_view_matches_and_contains(self):
        source = (
            """
import subprocess
from os import path
def f(subprocess):
    subprocess.run('x')
"""
        )
        visitor = b_node_visitor.BanditNodeVisitor(
            "resolution_test.py",
            io.BytesIO(source.encode()),
            b_meta_ast.BanditMetaAst(),
            self.test_set,
            False,
            {},
            _StubMetrics(),
        )
        visitor.process(source)
        resolver = visitor.resolver
        # Reset to module scope to inspect its post-traversal bindings.
        resolver._stack = [resolver.module_scope]
        module_view = b_names.ImportAliasesView(resolver)
        self.assertEqual("subprocess.run", module_view["subprocess.run"])
        self.assertIn("path", module_view)
        self.assertNotIn("missing", module_view)
        self.assertIsNone(module_view.get("missing"))
        # Inside the function the parameter shadows the subprocess import.
        function_node = next(
            node
            for node in resolver.scopes
            if isinstance(node, ast.FunctionDef)
        )
        resolver._stack = [
            resolver.module_scope,
            resolver.scopes[function_node],
        ]
        function_view = b_names.ImportAliasesView(resolver)
        self.assertNotIn("subprocess", function_view)
