# SPDX-License-Identifier: Apache-2.0
"""Lexical name resolution for the AST visitor.

The legacy visitor stored every import alias in a single dictionary shared by
the whole file.  That dictionary had no notion of Python's lexical scoping,
so a local assignment or a parameter shadowing an import could still be
reported as the imported object and an import hidden behind another scope
could be missed entirely.

This module tracks bindings the way Python resolves names, without executing
the scanned code:

* modules, function bodies, lambda bodies, class bodies and comprehensions
  each get their own scope;
* function parameters, assignment targets, imports, ``del`` targets and
  ``global``/``nonlocal`` declarations all participate in resolution;
* name resolution walks enclosing function/module scopes but never a class
  body, matching Python's actual closure rules;
* sequential rebinding replaces earlier bindings, including imports;
* conditional control flow is merged conservatively: a binding is kept only
  when every reachable path yields the same imported object, otherwise the
  name becomes unresolved.

Bindings coming from imports carry the dotted qualified name of the imported
object.  Every other statically known local binding is represented by the
:data:`UNRESOLVED` sentinel because Bandit intentionally does not infer the
runtime type of arbitrary Python objects across files.
"""

import ast


UNRESOLVED = object()
_MISSING = object()

SCOPE_MODULE = "module"
SCOPE_FUNCTION = "function"
SCOPE_CLASS = "class"
SCOPE_COMPREHENSION = "comprehension"

_SCOPE_NODES = (
    ast.Module,
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.ClassDef,
    ast.DictComp,
    ast.ListComp,
    ast.SetComp,
    ast.GeneratorExp,
)

# Nodes whose scope is introduced while some of their child expressions are
# still evaluated in the surrounding scope.
_FUNCTION_SCOPE_NODES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
)
_CLASS_SCOPE_NODES = (ast.ClassDef,)
_COMPREHENSION_NODES = (
    ast.DictComp,
    ast.ListComp,
    ast.SetComp,
    ast.GeneratorExp,
)


class Scope:
    """A single lexical scope and the bindings currently visible in it."""

    def __init__(self, node, scope_type, parent=None):
        self.node = node
        self.scope_type = scope_type
        self.parent = parent
        self.bindings = {}
        # Names declared global/nonlocal in this scope.
        self.globals = set()
        self.nonlocals = set()

    @property
    def is_class(self):
        return self.scope_type == SCOPE_CLASS

    @property
    def is_function(self):
        return self.scope_type in (SCOPE_FUNCTION, SCOPE_COMPREHENSION)


def _declared_function_names(arguments):
    names = set()
    for arg in (
        arguments.posonlyargs
        + arguments.args
        + arguments.kwonlyargs
    ):
        names.add(arg.arg)
    if arguments.vararg is not None:
        names.add(arguments.vararg.arg)
    if arguments.kwarg is not None:
        names.add(arguments.kwarg.arg)
    return names


def _store_target_names(node):
    """Yield plain names bound by an assignment target or pattern."""
    if isinstance(node, ast.Name):
        yield node.id
    elif isinstance(node, (ast.Tuple, ast.List)):
        for elt in node.elts:
            yield from _store_target_names(elt)
    elif isinstance(node, ast.Starred):
        yield from _store_target_names(node.value)
    elif isinstance(node, ast.Attribute):
        # Binding an attribute does not rebind the base name.
        return
    elif isinstance(node, ast.Subscript):
        return
    elif hasattr(ast, "MatchAs") and isinstance(node, ast.MatchAs):
        if node.name is not None:
            yield node.name
    elif hasattr(ast, "MatchStar") and isinstance(node, ast.MatchStar):
        if node.name is not None:
            yield node.name
    elif hasattr(ast, "MatchMapping") and isinstance(
        node, ast.MatchMapping
    ):
        if node.rest is not None:
            yield node.rest
        for pattern in node.patterns:
            yield from _store_target_names(pattern)
    elif hasattr(ast, "MatchOr") and isinstance(node, ast.MatchOr):
        for pattern in node.patterns:
            yield from _store_target_names(pattern)
    elif hasattr(ast, "MatchClass") and isinstance(node, ast.MatchClass):
        for pattern in node.patterns + node.kwd_patterns:
            yield from _store_target_names(pattern)
    elif hasattr(ast, "MatchSequence") and isinstance(
        node, ast.MatchSequence
    ):
        for pattern in node.patterns:
            yield from _store_target_names(pattern)


def _import_bound_name(alias_node, is_from_import):
    """Return the local name bound by one import alias."""
    if is_from_import:
        return alias_node.asname or alias_node.name
    return alias_node.asname or alias_node.name.split(".")[0]


def build_scopes(tree):
    """Pre-analyse an AST and return ``(scopes, outer_eval)``.

    ``scopes`` maps every scope-creating node to its :class:`Scope` with the
    names that Python treats as local to that scope.  Nodes evaluated in an
    enclosing scope (function defaults/decorators/annotations, class bases and
    decorators, the outermost iterable of a comprehension) are recorded in
    ``outer_eval`` so the runtime visitor can look names up there.
    """
    scopes = {}
    outer_eval = set()

    def add_scope(node, scope_type, parent):
        scope = Scope(node, scope_type, parent)
        scopes[node] = scope
        return scope

    def declare(scope, name):
        # Only function-like scopes have statically knowable locals.  Module
        # and class bodies execute sequentially, so a name does not exist
        # before its first binding; pre-declaring it would wrongly shadow
        # earlier imports and defeat control-flow merge resolution.
        if (
            scope is not None
            and scope.is_function
            and name not in scope.bindings
        ):
            scope.bindings[name] = UNRESOLVED

    def collect_declarations(node, scope):
        """Record names bound by a non-scope-creating node."""
        if scope is None:
            return
        if isinstance(node, ast.Name) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            declare(scope, node.id)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                declare(scope, _import_bound_name(alias, False))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    declare(scope, _import_bound_name(alias, True))
        elif isinstance(node, ast.Global):
            scope.globals.update(node.names)
        elif isinstance(node, ast.Nonlocal):
            scope.nonlocals.update(node.names)
        elif isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            declare(scope, node.name)
        elif isinstance(node, ast.ExceptHandler) and node.name is not None:
            declare(scope, node.name)
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                for name in _store_target_names(target):
                    declare(scope, name)
        elif isinstance(node, ast.AnnAssign) and isinstance(
            node.target, ast.Name
        ):
            declare(scope, node.target.id)
        elif isinstance(node, ast.AugAssign) and isinstance(
            node.target, ast.Name
        ):
            declare(scope, node.target.id)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for name in _store_target_names(node.target):
                declare(scope, name)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    for name in _store_target_names(item.optional_vars):
                        declare(scope, name)
        elif isinstance(node, ast.NamedExpr) and isinstance(
            node.target, ast.Name
        ):
            declare(scope, node.target.id)
        elif hasattr(ast, "MatchAs") and isinstance(node, ast.MatchAs):
            if node.name is not None:
                declare(scope, node.name)
        elif hasattr(ast, "MatchStar") and isinstance(node, ast.MatchStar):
            if node.name is not None:
                declare(scope, node.name)
        elif hasattr(ast, "MatchMapping") and isinstance(
            node, ast.MatchMapping
        ):
            if node.rest is not None:
                declare(scope, node.rest)

    def walk(node, scope):
        """Walk with ``scope`` as the scope that owns local bindings."""
        if isinstance(node, ast.Module):
            module_scope = add_scope(node, SCOPE_MODULE, None)
            for child in node.body:
                walk(child, module_scope)
            return

        if isinstance(node, _FUNCTION_SCOPE_NODES):
            # Expressions evaluated before the function scope exists.
            outer = [
                *(node.args.defaults),
                *(node.args.kw_defaults),
            ]
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ):
                outer.extend(node.decorator_list)
                outer.append(node.returns)
                for arg in (
                    node.args.posonlyargs
                    + node.args.args
                    + node.args.kwonlyargs
                ):
                    outer.append(arg.annotation)
            for expression in outer:
                if expression is not None:
                    outer_eval.add(expression)
                    walk(expression, scope)

            function_scope = add_scope(node, SCOPE_FUNCTION, scope)
            for name in _declared_function_names(node.args):
                declare(function_scope, name)
            # Walk the body; arguments themselves have no value expressions
            # beyond the annotations already handled above.
            if isinstance(node, ast.Lambda):
                walk(node.body, function_scope)
            else:
                for statement in node.body:
                    walk(statement, function_scope)
            return

        if isinstance(node, _CLASS_SCOPE_NODES):
            outer = [
                *node.bases,
                *(keyword.value for keyword in node.keywords),
                *node.decorator_list,
            ]
            for expression in outer:
                outer_eval.add(expression)
                walk(expression, scope)
            class_scope = add_scope(node, SCOPE_CLASS, scope)
            for statement in node.body:
                walk(statement, class_scope)
            return

        if isinstance(node, _COMPREHENSION_NODES):
            comprehension_scope = add_scope(
                node, SCOPE_COMPREHENSION, scope
            )
            first = node.generators[0]
            outer_eval.add(first.iter)
            walk(first.iter, scope)
            for name in _store_target_names(first.target):
                declare(comprehension_scope, name)
            for clause in node.generators[1:]:
                walk(clause.iter, comprehension_scope)
                for name in _store_target_names(clause.target):
                    declare(comprehension_scope, name)
                for condition in clause.ifs:
                    walk(condition, comprehension_scope)
            for condition in first.ifs:
                walk(condition, comprehension_scope)
            if isinstance(node, ast.DictComp):
                walk(node.key, comprehension_scope)
                walk(node.value, comprehension_scope)
            else:
                walk(node.elt, comprehension_scope)
            return

        collect_declarations(node, scope)
        for child in ast.iter_child_nodes(node):
            walk(child, scope)

    walk(tree, None)
    return scopes, outer_eval


class _Snapshot:
    """Restorable state captured before a control-flow branch."""

    def __init__(self, resolver):
        self.binding_snapshots = {
            scope: dict(scope.bindings) for scope in resolver._stack
        }
        self.bypassed = set(resolver._bypassed)

    def restore(self, resolver):
        for scope, bindings in self.binding_snapshots.items():
            scope.bindings = dict(bindings)
        resolver._bypassed = set(self.bypassed)


class NameResolver:
    """Track bindings while the visitor walks one parsed module."""

    def __init__(self, tree):
        self.scopes, self.outer_eval = build_scopes(tree)
        self.module_scope = self.scopes[tree]
        self._stack = []
        # Scopes whose local bindings must currently be skipped because the
        # visitor is inside an expression evaluated in an outer scope.
        self._bypassed = set()
        # Diagnostic trace of every call resolution: line -> (qualname,
        # root-shadowed).  Populated while the visitor walks the live stack.
        self.call_trace = {}

    @property
    def current_scope(self):
        return self._stack[-1] if self._stack else self.module_scope

    def enter_node(self, node):
        """Push the scope introduced by ``node``, if any."""
        is_outer_eval = node in self.outer_eval
        outer_scope = self.current_scope
        scope = self.scopes.get(node)
        if scope is not None:
            self._stack.append(scope)
        if is_outer_eval:
            self._bypassed.add(outer_scope)
        return scope

    def exit_node(self, node):
        if node in self.outer_eval:
            # The bypassed scope is the one that was current on entry.  If
            # this node introduced its own scope it is now on top of it;
            # otherwise the current scope itself is the bypassed one.
            own_scope = self.scopes.get(node)
            bypassed_scope = (
                own_scope.parent
                if own_scope is not None
                else self.current_scope
            )
            self._bypassed.discard(bypassed_scope)
        scope = self.scopes.get(node)
        if scope is not None:
            popped = self._stack.pop()
            assert popped is scope

    def _target_scope(self, scope):
        """Skip class scopes currently bypassed by outer-eval expressions."""
        candidate = scope
        while candidate in self._bypassed:
            candidate = candidate.parent
        return candidate

    def assign(self, name, value):
        """Bind ``name`` according to global/nonlocal/local lexical rules."""
        scope = self._target_scope(self.current_scope)
        if name in scope.globals:
            target = self.module_scope
        else:
            target = self._nonlocal_target(scope, name) or scope
        target.bindings[name] = value

    def binding_for_expression(self, node):
        """Return the import identity an assignment RHS may propagate.

        Only a bare imported name or an attribute chain rooted at an import
        yields a definite qualified name.  Everything else is unresolved; we
        never infer arbitrary object types.
        """
        if isinstance(node, ast.Name):
            found, value = self.lookup(node.id)
            return value if found else UNRESOLVED
        if isinstance(node, ast.Attribute):
            root_name, parts = self._attribute_chain(node)
            if root_name is None:
                return UNRESOLVED
            found, value = self.lookup(root_name)
            if not found or value is UNRESOLVED:
                return UNRESOLVED
            return ".".join([value, *parts])
        return UNRESOLVED

    def _nonlocal_target(self, scope, name):
        if name not in scope.nonlocals:
            return None
        candidate = scope.parent
        while candidate is not None:
            if candidate.is_function and name in candidate.bindings:
                return candidate
            candidate = candidate.parent
        # Invalid source code would raise SyntaxError at compile time; fall
        # back to the current scope rather than crashing the security scan.
        return scope

    def delete(self, name):
        scope = self._target_scope(self.current_scope)
        if name in scope.globals:
            target = self.module_scope
        else:
            target = self._nonlocal_target(scope, name) or scope
        if target.is_function:
            # Inside a function the name remains a local; later references
            # cannot resolve to an import even though ``del`` ran.
            target.bindings[name] = UNRESOLVED
        else:
            # Module and class bodies execute sequentially: after ``del`` the
            # name simply does not exist, so later references behave like
            # unbound free names.
            target.bindings.pop(name, None)

    def declare_global(self, names):
        scope = self.current_scope
        for name in names:
            scope.globals.add(name)
            # A later assignment, not the declaration, changes the module
            # binding; until then references use whatever the module knows.

    def declare_nonlocal(self, names):
        scope = self.current_scope
        for name in names:
            scope.nonlocals.add(name)

    def lookup(self, name):
        """Resolve ``name`` at the current visitor position.

        Returns ``(found, value)``.  ``value`` is either a dotted import name
        or :data:`UNRESOLVED`; ``found`` is False for a completely unbound
        name so callers can preserve the legacy pseudo-qualified name.
        """
        scope = self.current_scope
        if name in scope.globals:
            value = self.module_scope.bindings.get(name, _MISSING)
            if value is _MISSING:
                return False, UNRESOLVED
            return True, value

        candidate = scope
        while candidate is not None:
            if candidate in self._bypassed:
                candidate = candidate.parent
                continue
            # Python closures skip class bodies.  The class body itself may
            # still resolve names locally on its first iteration.
            if candidate is not scope and candidate.is_class:
                candidate = candidate.parent
                continue
            if name in candidate.bindings:
                return True, candidate.bindings[name]
            candidate = candidate.parent
        return False, UNRESOLVED

    def snapshot(self):
        return _Snapshot(self)

    @staticmethod
    def merge(base_snapshot, branch_snapshots):
        """Merge branch states back into ``base_snapshot``.

        A name keeps a definite imported identity only when every branch and
        the unmodified base agree on that exact identity.  Any disagreement
        makes the name unresolved.
        """
        if not branch_snapshots:
            return
        base = base_snapshot.binding_snapshots
        branches = [
            snapshot.binding_snapshots for snapshot in branch_snapshots
        ]
        for scope, base_bindings in base.items():
            all_keys = set(base_bindings)
            for branch in branches:
                all_keys.update(branch.get(scope, {}))
            for name in all_keys:
                base_value = base_bindings.get(name, _MISSING)
                values = []
                if base_value is not _MISSING:
                    values.append(base_value)
                for branch in branches:
                    branch_value = branch.get(scope, {}).get(
                        name, _MISSING
                    )
                    if branch_value is _MISSING:
                        # A branch that does not bind the name leaves the
                        # base binding in effect at runtime.
                        if base_value is not _MISSING:
                            branch_value = base_value
                    values.append(branch_value)
                first_value = values[0]
                if (
                    first_value is not UNRESOLVED
                    and all(
                        value is not UNRESOLVED
                        and value == first_value
                        for value in values[1:]
                    )
                ):
                    scope.bindings[name] = first_value
                else:
                    scope.bindings[name] = UNRESOLVED

    @staticmethod
    def conservative_merge(base_snapshot, branch_snapshots):
        """Merge branches whose execution count/order is unknowable.

        Only names that a branch actually creates or changes become
        unresolved; bindings untouched by every branch (for example an
        import established before a loop) keep their identity.
        """
        base = base_snapshot.binding_snapshots
        branches = [
            snapshot.binding_snapshots for snapshot in branch_snapshots
        ]
        for scope, base_bindings in base.items():
            for branch in branches:
                branch_bindings = branch.get(scope, {})
                for name, branch_value in branch_bindings.items():
                    base_value = base_bindings.get(name, _MISSING)
                    if base_value is not branch_value:
                        scope.bindings[name] = UNRESOLVED

    def resolve_call_name(self, node):
        """Return the security-relevant qualified name of a call node."""
        func = node.func
        if isinstance(func, ast.Name):
            found, value = self.lookup(func.id)
            if found and value is not UNRESOLVED:
                qualname = value
                shadowed = False
            else:
                qualname = func.id
                shadowed = found
            self.call_trace[node.lineno] = (qualname, shadowed)
            return qualname
        if isinstance(func, ast.Attribute):
            qualname, shadowed = self._resolve_attribute(func)
            self.call_trace[node.lineno] = (qualname, shadowed)
            return qualname
        self.call_trace[node.lineno] = ("", False)
        return ""

    def _resolve_attribute(self, node):
        root_name, parts = self._attribute_chain(node)
        if root_name is None:
            return "", False
        found, value = self.lookup(root_name)
        if not found:
            # Preserve the legacy syntactic name for unknown free names; some
            # rules rely on dotted names that need no import information.
            return ".".join([root_name, *parts]), False
        if value is UNRESOLVED:
            # The root is a known local object of unknown type (a parameter,
            # an assignment target, ...), not an import.  Preserve the
            # syntactic dotted chain so method-name based rules keep their
            # historical input; exact import-identity rules should use
            # ``NameResolver.lookup`` to confirm the root is a real import.
            return ".".join([root_name, *parts]), True
        return ".".join([value, *parts]), False

    @staticmethod
    def _attribute_chain(node):
        parts = []
        current = node
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if not isinstance(current, ast.Name):
            return None, None
        parts.reverse()
        return current.id, parts

class ImportAliasesView:
    """Resolver-backed, dict-like view used by existing context consumers."""

    def __init__(self, resolver):
        self._resolver = resolver

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __getitem__(self, key):
        resolver = self._resolver
        root, _, attrs = key.partition(".")
        found, value = resolver.lookup(root)
        if not found or value is UNRESOLVED:
            raise KeyError(key)
        resolved = value
        if attrs:
            resolved = f"{resolved}.{attrs}"
        return resolved

    def __contains__(self, key):
        try:
            self[key]
        except KeyError:
            return False
        return True

    def __iter__(self):
        seen = set()
        scope = self._resolver.current_scope
        while scope is not None:
            if scope in self._resolver._bypassed:
                scope = scope.parent
                continue
            if scope is not self._resolver.current_scope and scope.is_class:
                scope = scope.parent
                continue
            for name, value in scope.bindings.items():
                if name not in seen and value is not UNRESOLVED:
                    seen.add(name)
                    yield name
            scope = scope.parent

    def keys(self):
        return list(self)

    def __repr__(self):
        return f"ImportAliasesView({ {key: self[key] for key in self} })"
