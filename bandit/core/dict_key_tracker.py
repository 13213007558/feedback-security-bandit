#
# SPDX-License-Identifier: Apache-2.0
r"""Bounded intra-function tracking of a key inside option dictionaries.

This module implements a small, fully static dataflow analysis used to
answer questions like: "when this call is reached, can the ``verify``
entry of the dictionary expanded via ``**options`` be ``False``?"

The analysis walks the statements of the scope (function or module) that
directly encloses the call of interest, in source order, and tracks a
single lattice value per local dictionary variable:

- ``SAFE``: the key is definitely absent or definitely not ``False``
- ``FALSE``: the key is definitely ``False``
- ``MAYBE_FALSE``: the key is ``False`` on some, but not all, paths
- ``UNKNOWN``: the value cannot be determined statically

The analysis never executes scanned code.  Loops are processed with a
fixed, bounded number of passes, branches are merged with a join over
the lattice, and no cross-function or whole-program evaluation is
performed.  When an unknown function call receives a tracked dictionary
it may mutate it, so the dictionary is conservatively marked ``UNKNOWN``
instead of trusting a stale constant.
"""
import ast

SAFE = "safe"
FALSE = "false"
MAYBE_FALSE = "maybe_false"
UNKNOWN = "unknown"

# loops are unrolled at most this many times; keeps the analysis bounded
_MAX_LOOP_PASSES = 2

# calls that are known not to mutate a dictionary passed as an argument
_NON_MUTATING_CALLS = frozenset(
    [
        "print",
        "len",
        "str",
        "repr",
        "type",
        "isinstance",
        "bool",
        "list",
        "tuple",
        "set",
        "frozenset",
        "sorted",
        "enumerate",
        "zip",
        "iter",
        "next",
        "hash",
        "id",
    ]
)

# dict methods that never change the dictionary they are called on
_NON_MUTATING_METHODS = frozenset(
    ["get", "items", "keys", "values", "copy", "__contains__"]
)

_SCOPE_NODES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
    ast.Lambda,
    ast.Module,
)

_TRY_NODES = (ast.Try,) + (
    (ast.TryStar,) if hasattr(ast, "TryStar") else ()
)


class TrackedValue:
    """Lattice value for one tracked dictionary, with a source line.

    ``source`` is the line number where the tracked key was most
    recently set to ``False`` (used to point reports at the origin).
    """

    __slots__ = ("level", "source")

    def __init__(self, level=SAFE, source=None):
        self.level = level
        self.source = source

    def copy(self):
        return TrackedValue(self.level, self.source)

    def __repr__(self):
        return f"TrackedValue({self.level}, source={self.source})"


def _join(left, right):
    """Join two values at a control-flow merge point."""
    if left.level == right.level:
        source = left.source if left.source is not None else right.source
        return TrackedValue(left.level, source)
    if UNKNOWN in (left.level, right.level):
        return TrackedValue(UNKNOWN)
    # one side is FALSE (or MAYBE_FALSE) and the other is not: the key
    # is False on some paths only
    source = left.source if left.level != SAFE else right.source
    return TrackedValue(MAYBE_FALSE, source)


def resolve_key_at_call(call_node, key, import_aliases, is_sink):
    """Resolve ``key`` for ``**options`` expansions of ``call_node``.

    Re-analyzes the scope enclosing ``call_node`` from the top and
    returns a :class:`TrackedValue` describing the value ``key`` has at
    that call, or ``None`` if the call never mentions the key (neither
    as an explicit keyword nor through a ``**`` expansion).

    :param call_node: the ast.Call node to inspect
    :param key: the dictionary key to track (e.g. ``"verify"``)
    :param import_aliases: import aliases known for the current file
    :param is_sink: predicate taking an ast.Call node and returning True
        if the call is a sink whose keywords should be resolved
    """
    scope = call_node
    while not isinstance(scope, _SCOPE_NODES):
        scope = getattr(scope, "_bandit_parent", None)
        if scope is None:
            return None

    flow = _KeyFlow(key, import_aliases or {}, is_sink)
    if isinstance(scope, ast.Lambda):
        flow.scan_expr(scope.body)
    else:
        flow.process_body(scope.body)
    return flow.sink_values.get(id(call_node))


class _KeyFlow:
    """Bounded static interpretation of one scope for one dict key."""

    def __init__(self, key, import_aliases, is_sink):
        self.key = key
        self.import_aliases = import_aliases
        self.is_sink = is_sink
        # maps a local name to its TrackedValue; plain ``a = b``
        # assignments share the same object, modeling aliasing
        self._vars = {}
        # id(call node) -> TrackedValue, for sink calls already reached
        self.sink_values = {}

    # -- statement processing -----------------------------------------

    def process_body(self, stmts):
        for stmt in stmts:
            self.process_stmt(stmt)

    def process_stmt(self, stmt):
        if isinstance(
            stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            # nested scopes are not analyzed (no cross-function eval)
            return
        if isinstance(stmt, ast.If):
            self.scan_expr(stmt.test)
            pre = self._snapshot()
            self.process_body(stmt.body)
            taken = self._snapshot()
            self._restore(pre)
            self.process_body(stmt.orelse)
            self._merge(taken)
        elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
            self._process_loop(stmt)
        elif isinstance(stmt, _TRY_NODES):
            self._process_try(stmt)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self.scan_expr(item.context_expr)
                self._bind_unknown(item.optional_vars)
            self.process_body(stmt.body)
        elif isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            self._process_assign(stmt)
        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                self._process_delete(target)
        elif isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self.scan_expr(stmt.value)
        elif isinstance(stmt, ast.Expr):
            self.scan_expr(stmt.value)
        else:
            # any other statement: still look at the expressions it holds
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self.scan_expr(child)

    def _process_loop(self, stmt):
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self.scan_expr(stmt.iter)
            self._bind_unknown(stmt.target)
        else:
            self.scan_expr(stmt.test)
        pre = self._snapshot()
        # bounded unrolling: enough for values set inside the body to
        # propagate, without ever looping forever
        for _ in range(_MAX_LOOP_PASSES):
            self.process_body(stmt.body)
        self._merge(pre)  # the body may run zero times
        self.process_body(stmt.orelse)

    def _process_try(self, stmt):
        pre = self._snapshot()
        self.process_body(stmt.body)
        body_state = self._snapshot()
        self._restore(pre)
        for handler in stmt.handlers:
            self.process_body(handler.body)
        self._merge(body_state)
        self.process_body(stmt.orelse)
        self.process_body(stmt.finalbody)

    # -- assignments ---------------------------------------------------

    def _process_assign(self, stmt):
        if stmt.value is not None:
            self.scan_expr(stmt.value)
        if isinstance(stmt, ast.AugAssign):
            # ``opts |= {...}`` behaves like dict.update()
            if isinstance(stmt.target, ast.Name) and self._is_tracked(
                stmt.target.id
            ):
                cell = self._vars[stmt.target.id]
                if isinstance(stmt.value, ast.Dict):
                    self._apply_update_dict(cell, stmt.value)
                else:
                    self._set_unknown(cell)
            else:
                self._bind_unknown(stmt.target)
            return
        if isinstance(stmt, ast.Assign):
            targets = stmt.targets
        else:
            targets = [stmt.target]
        for target in targets:
            self._assign_target(target, stmt.value)

    def _assign_target(self, target, value):
        if isinstance(target, ast.Name):
            self._bind_name(target.id, value)
        elif isinstance(target, ast.Subscript):
            self._assign_subscript(target, value)
        elif isinstance(target, (ast.Tuple, ast.List, ast.Starred)):
            # unpacking rebinds names to unknown values
            nodes = target.elts if hasattr(target, "elts") else [target.value]
            for elt in nodes:
                self._bind_unknown(elt)

    def _bind_name(self, name, value):
        if isinstance(value, ast.Dict):
            self._vars[name] = self._eval_dict_literal(value)
        elif isinstance(value, ast.Name):
            if self._is_tracked(value.id):
                # plain assignment aliases the same dictionary object
                self._vars[name] = self._vars[value.id]
            elif name in self._vars:
                self._vars[name] = TrackedValue(UNKNOWN)
        elif isinstance(value, ast.Call):
            copied = self._eval_copy_call(value)
            if copied is not None:
                self._vars[name] = copied
            elif name in self._vars or self._looks_like_dict_call(value):
                self._vars[name] = TrackedValue(UNKNOWN)
        elif name in self._vars:
            self._vars[name] = TrackedValue(UNKNOWN)

    def _bind_unknown(self, target):
        if isinstance(target, ast.Name) and self._is_tracked(target.id):
            self._vars[target.id] = TrackedValue(UNKNOWN)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind_unknown(elt)
        elif isinstance(target, ast.Starred):
            self._bind_unknown(target.value)

    def _assign_subscript(self, target, value):
        if not isinstance(target.value, ast.Name):
            return
        name = target.value.id
        if not self._is_tracked(name):
            return
        cell = self._vars[name]
        key_node = target.slice
        if isinstance(key_node, ast.Constant):
            if key_node.value == self.key:
                assigned = self._const_value(value)
                cell.level, cell.source = assigned.level, assigned.source
            # subscripts with unrelated constant keys change nothing
        else:
            # a computed key may or may not be the tracked one
            self._set_unknown(cell)

    def _process_delete(self, target):
        if isinstance(target, ast.Name):
            self._vars.pop(target.id, None)
        elif isinstance(target, ast.Subscript):
            if isinstance(target.value, ast.Name) and self._is_tracked(
                target.value.id
            ):
                cell = self._vars[target.value.id]
                if isinstance(target.slice, ast.Constant):
                    if target.slice.value == self.key:
                        cell.level, cell.source = SAFE, None
                else:
                    self._set_unknown(cell)

    # -- expression scanning -------------------------------------------

    def scan_expr(self, expr):
        """Scan an expression for sink calls and possible mutations."""
        for node in ast.walk(expr):
            if isinstance(node, ast.Call):
                self._process_call(node)

    def _process_call(self, node):
        if self.is_sink(node):
            value = self._eval_sink(node)
            if value is not None:
                self.sink_values[id(node)] = value
            return
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(
            func.value, ast.Name
        ):
            if self._is_tracked(func.value.id):
                self._apply_method(node, func.value.id)
                return
        if self._is_pure_call(node):
            return
        # unknown call: any tracked dict passed to it may be mutated
        for arg in node.args:
            self._taint_if_tracked(arg)
            if isinstance(arg, ast.Starred):
                self._taint_if_tracked(arg.value)
        for keyword in node.keywords:
            self._taint_if_tracked(keyword.value)

    def _taint_if_tracked(self, node):
        if isinstance(node, ast.Name) and self._is_tracked(node.id):
            self._set_unknown(self._vars[node.id])

    def _is_pure_call(self, node):
        func = node.func
        if isinstance(func, ast.Name):
            return func.id in _NON_MUTATING_CALLS or func.id == "dict"
        if isinstance(func, ast.Attribute):
            # logging.debug(...), os.path.join(...), etc. do not mutate
            # dict arguments; resolve aliases when the root is a name
            root = func.value
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name):
                name = self.import_aliases.get(root.id, root.id)
                return name.split(".")[0] in ("logging", "os", "sys", "json")
        return False

    def _apply_method(self, call, name):
        cell = self._vars[name]
        attr = call.func.attr
        if attr in _NON_MUTATING_METHODS:
            return
        if attr == "update":
            for arg in call.args[:1]:
                if isinstance(arg, ast.Dict):
                    self._apply_update_dict(cell, arg)
                elif isinstance(arg, ast.Name) and self._is_tracked(arg.id):
                    self._merge_update_value(cell, self._vars[arg.id])
                else:
                    # unknown source: the old constant can no longer
                    # be trusted
                    self._set_unknown(cell)
                    return
            for keyword in call.keywords:
                if keyword.arg == self.key:
                    assigned = self._const_value(keyword.value)
                    cell.level, cell.source = assigned.level, assigned.source
                elif keyword.arg is None:
                    self._merge_update_value(
                        cell, self._eval_expansion(keyword.value)
                    )
        elif attr == "clear":
            cell.level, cell.source = SAFE, None
        elif attr == "pop":
            if call.args and isinstance(call.args[0], ast.Constant):
                if call.args[0].value == self.key:
                    cell.level, cell.source = SAFE, None
            else:
                self._set_unknown(cell)
        elif attr == "setdefault":
            self._apply_setdefault(call, cell)
        else:
            # popitem and any unknown method may mutate the dict
            self._set_unknown(cell)

    def _apply_setdefault(self, call, cell):
        if not call.args or not isinstance(call.args[0], ast.Constant):
            self._set_unknown(cell)
            return
        if call.args[0].value != self.key:
            return
        default = (
            self._const_value(call.args[1])
            if len(call.args) > 1
            else TrackedValue(SAFE)
        )
        if default.level == FALSE and cell.level == SAFE:
            # key might be absent, in which case it becomes False
            cell.level, cell.source = MAYBE_FALSE, default.source
        elif default.level == UNKNOWN:
            self._set_unknown(cell)

    def _apply_update_dict(self, cell, dict_node):
        for key_node, value_node in zip(dict_node.keys, dict_node.values):
            if key_node is None:
                self._merge_update_value(
                    cell, self._eval_expansion(value_node)
                )
            elif isinstance(key_node, ast.Constant):
                if key_node.value == self.key:
                    assigned = self._const_value(value_node)
                    cell.level, cell.source = assigned.level, assigned.source

    def _merge_update_value(self, cell, other):
        if other.level == FALSE:
            cell.level, cell.source = FALSE, other.source
        elif other.level == UNKNOWN:
            self._set_unknown(cell)
        elif other.level == MAYBE_FALSE:
            cell.level = MAYBE_FALSE
            if other.source is not None:
                cell.source = other.source
        # SAFE: the other dict has no False for this key; it may still
        # override with a non-False value, so join rather than keep
        elif cell.level == FALSE:
            cell.level = MAYBE_FALSE

    # -- value evaluation ------------------------------------------------

    def _const_value(self, node):
        if isinstance(node, ast.Constant):
            if node.value is False:
                return TrackedValue(FALSE, node.lineno)
            # any other constant (True, strings, numbers, None) is safe;
            # a string like "False" is not the boolean False
            return TrackedValue(SAFE)
        return TrackedValue(UNKNOWN)

    def _eval_expansion(self, node):
        """Evaluate a ``**expansion`` operand."""
        if isinstance(node, ast.Name):
            if self._is_tracked(node.id):
                return self._vars[node.id].copy()
            return TrackedValue(UNKNOWN)
        if isinstance(node, ast.Dict):
            return self._eval_dict_literal(node)
        if isinstance(node, ast.Call):
            copied = self._eval_copy_call(node)
            if copied is not None:
                return copied
            return TrackedValue(UNKNOWN)
        return TrackedValue(UNKNOWN)

    def _eval_dict_literal(self, node):
        result = TrackedValue(SAFE)
        for key_node, value_node in zip(node.keys, node.values):
            if key_node is None:
                # ``{**a, "verify": False}``: later entries override
                result = self._eval_expansion(value_node)
            elif isinstance(key_node, ast.Constant):
                if key_node.value == self.key:
                    result = self._const_value(value_node)
            # unrelated keys (strings, other objects) never count
        return result

    def _eval_copy_call(self, node):
        """Evaluate dict(...) and dict.copy() producing a new dict."""
        func = node.func
        if isinstance(func, ast.Name) and func.id == "dict":
            result = TrackedValue(SAFE)
            if node.args:
                arg = node.args[0]
                if isinstance(arg, ast.Name) and self._is_tracked(arg.id):
                    result = self._vars[arg.id].copy()
                elif isinstance(arg, ast.Dict):
                    result = self._eval_dict_literal(arg)
                else:
                    result = TrackedValue(UNKNOWN)
            for keyword in node.keywords:
                if keyword.arg == self.key:
                    result = self._const_value(keyword.value)
                elif keyword.arg is None:
                    result = self._eval_expansion(keyword.value)
            return result
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "copy"
            and isinstance(func.value, ast.Name)
            and self._is_tracked(func.value.id)
        ):
            return self._vars[func.value.id].copy()
        return None

    def _looks_like_dict_call(self, node):
        func = node.func
        return isinstance(func, ast.Name) and func.id == "dict"

    def _eval_sink(self, node):
        """Resolve the tracked key for a sink call, in keyword order."""
        result = None
        for keyword in node.keywords:
            if keyword.arg == self.key:
                result = self._const_value(keyword.value)
            elif keyword.arg is None:
                # ``**options``: later expansions override earlier ones
                # and override explicit keywords listed before them
                result = self._eval_expansion(keyword.value)
        return result

    # -- state helpers ---------------------------------------------------

    def _is_tracked(self, name):
        return name in self._vars

    @staticmethod
    def _set_unknown(cell):
        cell.level, cell.source = UNKNOWN, None

    def _snapshot(self):
        return {name: value.copy() for name, value in self._vars.items()}

    def _restore(self, snapshot):
        self._vars = {name: value.copy() for name, value in snapshot.items()}

    def _merge(self, other):
        """Join the current state with a snapshot from another path."""
        merged = {}
        for name in set(self._vars) | set(other):
            current = self._vars.get(name)
            incoming = other.get(name)
            if current is None:
                # defined only on the other path: may be undefined here,
                # which is treated as "not a known False"
                merged[name] = _join(TrackedValue(SAFE), incoming)
            elif incoming is None:
                merged[name] = _join(current, TrackedValue(SAFE))
            else:
                merged[name] = _join(current, incoming)
        self._vars = merged
