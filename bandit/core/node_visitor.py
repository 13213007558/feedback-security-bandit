#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import ast
import logging
import operator

from bandit.core import constants
from bandit.core import name_resolution as b_names
from bandit.core import tester as b_tester
from bandit.core import utils as b_utils

LOG = logging.getLogger(__name__)


class BanditNodeVisitor:
    def __init__(
        self, fname, fdata, metaast, testset, debug, nosec_lines, metrics
    ):
        self.debug = debug
        self.nosec_lines = nosec_lines
        self.scores = {
            "SEVERITY": [0] * len(constants.RANKING),
            "CONFIDENCE": [0] * len(constants.RANKING),
        }
        self.depth = 0
        self.fname = fname
        self.fdata = fdata
        self.metaast = metaast
        self.testset = testset
        self.imports = set()
        self.resolver = None
        self._prebound_targets = set()
        self.tester = b_tester.BanditTester(
            self.testset, self.debug, nosec_lines, metrics
        )

        # in some cases we can't determine a qualified name
        try:
            self.namespace = b_utils.get_module_qualname_from_path(fname)
        except b_utils.InvalidModulePath:
            LOG.warning(
                "Unable to find qualified name for module: %s", self.fname
            )
            self.namespace = ""
        LOG.debug("Module qualified name: %s", self.namespace)
        self.metrics = metrics

    def visit_ClassDef(self, node):
        """Visitor for AST ClassDef node

        Add class name to current namespace for all descendants.
        :param node: Node being inspected
        :return: -
        """
        # For all child nodes, add this class name to current namespace
        self.namespace = b_utils.namespace_path_join(self.namespace, node.name)

    def visit_FunctionDef(self, node):
        """Visitor for AST FunctionDef nodes

        add relevant information about the node to
        the context for use in tests which inspect function definitions.
        Add the function name to the current namespace for all descendants.
        :param node: The node that is being inspected
        :return: -
        """

        self.context["function"] = node
        qualname = self.namespace + "." + b_utils.get_func_name(node)
        name = qualname.split(".")[-1]

        self.context["qualname"] = qualname
        self.context["name"] = name

        # For all child nodes and any tests run, add this function name to
        # current namespace
        self.namespace = b_utils.namespace_path_join(self.namespace, name)
        self.update_scores(self.tester.run_tests(self.context, "FunctionDef"))

    def visit_Call(self, node):
        """Visitor for AST Call nodes

        add relevant information about the node to
        the context for use in tests which inspect function calls.
        :param node: The node that is being inspected
        :return: -
        """

        self.context["call"] = node
        qualname = self.resolver.resolve_call_name(node)
        if isinstance(node.func, ast.Attribute):
            name = node.func.attr
        elif isinstance(node.func, ast.Name):
            name = node.func.id
        else:
            name = ""

        self.context["qualname"] = qualname
        self.context["name"] = name

        self.update_scores(self.tester.run_tests(self.context, "Call"))

    def visit_Import(self, node):
        """Visitor for AST Import nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        """
        for nodename in node.names:
            if nodename.asname:
                bound_name = nodename.asname
                qualified_name = nodename.name
            else:
                bound_name = nodename.name.split(".")[0]
                qualified_name = bound_name
            self.resolver.assign(bound_name, qualified_name)
            self.imports.add(nodename.name)
            self.context["module"] = nodename.name
        self.update_scores(self.tester.run_tests(self.context, "Import"))

    def visit_ImportFrom(self, node):
        """Visitor for AST ImportFrom nodes

        add relevant information about node to
        the context for use in tests which inspect imports.
        :param node: The node that is being inspected
        :return: -
        """
        module = node.module
        if module is None:
            return self.visit_Import(node)

        for nodename in node.names:
            if nodename.name == "*":
                # Star imports cannot be resolved without importing the
                # target module, which Bandit must never execute.
                continue
            bound_name = nodename.asname or nodename.name
            if node.level:
                # Relative imports depend on the package containing the
                # scanned file; record the binding as a local object instead
                # of guessing a cross-file qualified name.
                qualified_name = b_names.UNRESOLVED
            else:
                qualified_name = module + "." + nodename.name
            self.resolver.assign(bound_name, qualified_name)
            self.imports.add(module + "." + nodename.name)
            self.context["module"] = module
            self.context["name"] = nodename.name
        self.update_scores(self.tester.run_tests(self.context, "ImportFrom"))

    def visit_Assign(self, node):
        """Bind assignment targets after the value expression is visited."""
        self._visit_node(node.value, node)
        rhs_binding = self.resolver.binding_for_expression(node.value)
        for target in node.targets:
            self._bind_assignment_value(target, rhs_binding)
            self._visit_node(target, node)
        self._prebound_targets.clear()
        node._bandit_children_handled = True

    def visit_AnnAssign(self, node):
        if node.annotation is not None:
            self._visit_node(node.annotation, node)
        if node.value is not None:
            self._visit_node(node.value, node)
            rhs_binding = self.resolver.binding_for_expression(node.value)
            if isinstance(node.target, ast.Name):
                self.resolver.assign(node.target.id, rhs_binding)
        self._visit_node(node.target, node)
        self._prebound_targets.clear()
        node._bandit_children_handled = True

    def visit_AugAssign(self, node):
        # The target is read before being written, but its post-assignment
        # identity is unknown.
        self._visit_node(node.target, node)
        self._visit_node(node.value, node)
        node._bandit_children_handled = True

    def visit_NamedExpr(self, node):
        self._visit_node(node.value, node)
        if isinstance(node.target, ast.Name):
            rhs_binding = self.resolver.binding_for_expression(node.value)
            self.resolver.assign(node.target.id, rhs_binding)
        self._visit_node(node.target, node)
        self._prebound_targets.clear()
        node._bandit_children_handled = True

    def _bind_assignment_value(self, target, value):
        if isinstance(target, ast.Name):
            self.resolver.assign(target.id, value)
            self._prebound_targets.add(id(target))
        elif isinstance(target, (ast.Tuple, ast.List)):
            # Tuple/list unpacking cannot statically map one RHS identity to
            # each element; mark every bound name unresolved.
            for element in target.elts:
                self._bind_assignment_value(element, value)
        elif isinstance(target, ast.Starred):
            self._bind_assignment_value(target.value, value)

    def visit_Global(self, node):
        self.resolver.declare_global(node.names)

    def visit_Nonlocal(self, node):
        self.resolver.declare_nonlocal(node.names)

    def visit_Delete(self, node):
        for target in node.targets:
            self._visit_node(target, node)
        node._bandit_children_handled = True

    def visit_For(self, node):
        self._visit_loop(
            node,
            iterable=node.iter,
            target=node.target,
            body=node.body,
            orelse=node.orelse,
        )

    def visit_AsyncFor(self, node):
        self._visit_loop(
            node,
            iterable=node.iter,
            target=node.target,
            body=node.body,
            orelse=node.orelse,
        )

    def visit_While(self, node):
        self._visit_node(node.test, node)
        self._merge_branches(
            node,
            branches=[node.body],
            fallback=node.orelse,
            conservative=True,
        )
        node._bandit_children_handled = True

    def visit_If(self, node):
        self._visit_node(node.test, node)
        self._merge_branches(
            node,
            branches=[node.body],
            fallback=node.orelse,
            conservative=False,
        )
        node._bandit_children_handled = True

    def visit_Try(self, node):
        branches = [node.body]
        for handler in node.handlers:
            branches.append([handler])
        if node.orelse:
            branches.append(node.orelse)
        self._merge_branches(
            node,
            branches=branches,
            fallback=node.finalbody,
            conservative=True,
        )
        node._bandit_children_handled = True

    def visit_ExceptHandler(self, node):
        self._run_node_tests(node)
        if node.type is not None:
            self._visit_node(node.type, node)
        if node.name is not None:
            self.resolver.assign(node.name, b_names.UNRESOLVED)
        for statement in node.body:
            self._visit_node(statement, node)
        node._bandit_children_handled = True

    def _run_node_tests(self, node):
        """Run tests registered for a node type without redispatching."""
        checktype = node.__class__.__name__
        self.update_scores(self.tester.run_tests(self.context, checktype))

    def visit_Match(self, node):
        self._visit_node(node.subject, node)
        branches = [case.body for case in node.cases]
        self._merge_branches(
            node,
            branches=branches,
            fallback=[],
            conservative=True,
        )
        node._bandit_children_handled = True

    def _visit_loop(self, node, iterable, target, body, orelse):
        self._visit_node(iterable, node)
        self._visit_node(target, node)
        # Loop bodies may execute zero or many times, so names bound there
        # cannot retain an imported identity after the loop.
        self._merge_branches(
            node,
            branches=[body],
            fallback=orelse,
            conservative=True,
        )
        node._bandit_children_handled = True

    def _merge_branches(self, node, branches, fallback, conservative):
        base_snapshot = self.resolver.snapshot()
        branch_snapshots = []
        for branch in branches:
            base_snapshot.restore(self.resolver)
            for statement in branch:
                self._visit_node(statement, node)
            branch_snapshots.append(self.resolver.snapshot())
        if fallback:
            base_snapshot.restore(self.resolver)
            for statement in fallback:
                self._visit_node(statement, node)
            branch_snapshots.append(self.resolver.snapshot())
        base_snapshot.restore(self.resolver)
        if conservative:
            self.resolver.conservative_merge(
                base_snapshot, branch_snapshots
            )
        else:
            self.resolver.merge(base_snapshot, branch_snapshots)

    def _visit_node(self, node, parent=None):
        if isinstance(node, ast.AST):
            node._bandit_sibling = None
            if parent is None:
                parent = getattr(
                    node, "_bandit_parent", self.context["node"]
                )
            self._drive_child(
                parent, node
            )

    def visit_Constant(self, node):
        """Visitor for AST Constant nodes

        call the appropriate method for the node type.
        this maintains compatibility with <3.6 and 3.8+

        This code is heavily influenced by Anthony Sottile (@asottile) here:
        https://bugs.python.org/msg342486

        :param node: The node that is being inspected
        :return: -
        """
        if isinstance(node.value, str):
            self.visit_Str(node)
        elif isinstance(node.value, bytes):
            self.visit_Bytes(node)

    def visit_Str(self, node):
        """Visitor for AST String nodes

        add relevant information about node to
        the context for use in tests which inspect strings.
        :param node: The node that is being inspected
        :return: -
        """
        self.context["str"] = node.value
        if not isinstance(node._bandit_parent, ast.Expr):  # docstring
            self.context["linerange"] = b_utils.linerange(node._bandit_parent)
            self.update_scores(self.tester.run_tests(self.context, "Str"))

    def visit_Bytes(self, node):
        """Visitor for AST Bytes nodes

        add relevant information about node to
        the context for use in tests which inspect strings.
        :param node: The node that is being inspected
        :return: -
        """
        self.context["bytes"] = node.value
        if not isinstance(node._bandit_parent, ast.Expr):  # docstring
            self.context["linerange"] = b_utils.linerange(node._bandit_parent)
            self.update_scores(self.tester.run_tests(self.context, "Bytes"))

    def pre_visit(self, node):
        self.resolver.enter_node(node)

        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            # Import visitors replace this unresolved binding with the
            # imported qualified name.  Assignment visitors arrange traversal
            # so the value is resolved before this event.
            parent = getattr(node, "_bandit_parent", None)
            if (
                not isinstance(parent, ast.AugAssign)
                and id(node) not in self._prebound_targets
            ):
                self.resolver.assign(node.id, b_names.UNRESOLVED)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Del):
            self.resolver.delete(node.id)

        self.context = {}
        self.context["imports"] = self.imports
        self.context["import_aliases"] = b_names.ImportAliasesView(
            self.resolver
        )
        self.context["name_resolver"] = self.resolver

        if self.debug:
            LOG.debug(ast.dump(node))
            self.metaast.add_node(node, "", self.depth)

        if hasattr(node, "lineno"):
            self.context["lineno"] = node.lineno

        if hasattr(node, "col_offset"):
            self.context["col_offset"] = node.col_offset
        if hasattr(node, "end_col_offset"):
            self.context["end_col_offset"] = node.end_col_offset

        self.context["node"] = node
        self.context["linerange"] = b_utils.linerange(node)
        self.context["filename"] = self.fname
        self.context["file_data"] = self.fdata

        LOG.debug(
            "entering: %s %s [%s]", hex(id(node)), type(node), self.depth
        )
        self.depth += 1
        LOG.debug(self.context)
        return True

    def visit(self, node):
        name = node.__class__.__name__
        method = "visit_" + name
        visitor = getattr(self, method, None)
        if visitor is not None:
            if self.debug:
                LOG.debug("%s called (%s)", method, ast.dump(node))
            visitor(node)
        else:
            self.update_scores(self.tester.run_tests(self.context, name))

    def post_visit(self, node):
        self.resolver.exit_node(node)
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            # The name belongs to the enclosing scope, which is now on top.
            self.resolver.assign(node.name, b_names.UNRESOLVED)
        self.depth -= 1
        LOG.debug("%s\texiting : %s", self.depth, hex(id(node)))

        # HACK(tkelsey): this is needed to clean up post-recursion stuff that
        # gets setup in the visit methods for these node types.
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            self.namespace = b_utils.namespace_path_split(self.namespace)[0]

    def generic_visit(self, node):
        """Drive the visitor."""
        if getattr(node, "_bandit_children_handled", False):
            node._bandit_children_handled = False
            return
        for _, value in ast.iter_fields(node):
            if isinstance(value, list):
                max_idx = len(value) - 1
                for idx, item in enumerate(value):
                    if isinstance(item, ast.AST):
                        if idx < max_idx:
                            item._bandit_sibling = value[idx + 1]
                        else:
                            item._bandit_sibling = None
                        self._drive_child(node, item)

            elif isinstance(value, ast.AST):
                value._bandit_sibling = None

                self._drive_child(node, value)

    def _drive_child(self, parent, node):
        node._bandit_parent = parent
        if self.pre_visit(node):
            self.visit(node)
            self.generic_visit(node)
            self.post_visit(node)

    def update_scores(self, scores):
        """Score updater

        Since we moved from a single score value to a map of scores per
        severity, this is needed to update the stored list.
        :param score: The score list to update our scores with
        """
        # we'll end up with something like:
        # SEVERITY: {0, 0, 0, 10}  where 10 is weighted by finding and level
        for score_type in self.scores:
            self.scores[score_type] = list(
                map(operator.add, self.scores[score_type], scores[score_type])
            )

    def process(self, data):
        """Main process loop

        Build and process the AST
        :param lines: lines code to process
        :return score: the aggregated score for the current file
        """
        f_ast = ast.parse(data)
        self.resolver = b_names.NameResolver(f_ast)
        self._drive_child(None, f_ast)
        # Run tests that do not require access to the AST,
        # but only to the whole file source:
        self.context = {
            "file_data": self.fdata,
            "filename": self.fname,
            "lineno": 0,
            "linerange": [0, 1],
            "col_offset": 0,
        }
        self.update_scores(self.tester.run_tests(self.context, "File"))
        return self.scores
