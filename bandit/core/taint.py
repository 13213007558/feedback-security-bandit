#
# SPDX-License-Identifier: Apache-2.0
"""Intra-function taint analysis for shell command construction.

This module implements an optional, best-effort static analysis that
tracks external input sources (``os.environ``, ``sys.argv`` and
``input()``) through local assignments, string concatenation, string
formatting and branches within a single function, and reports whether
such values reach a shell execution entry point.

The analysis is deliberately conservative about its boundaries:

- Loops are analyzed for a single pass and recorded as explicit
  boundaries; results depending on them are never claimed to be safe.
- Calls that cannot be analyzed (unknown or local functions) produce
  an "unknown" boundary marker, not a clean result.
- ``shlex.quote`` is only honored when it quotes a complete shell
  word.  Nesting the quoted value inside another layer of quotes, or
  concatenating unprocessed values afterwards, voids the conclusion.
- Only qualified names matter: a function merely named e.g.
  ``safe_quote`` is not treated as a sanitizer.

Only source code positions and variable relations are reported; no
actual environment variable or argument values are ever read.
"""

import ast

_SOURCE_QUALNAMES = {
    "os.environ": "os.environ",
    "os.getenv": "os.environ",
    "sys.argv": "sys.argv",
    "input": "input()",
}

_QUOTE_QUALNAMES = {"shlex.quote", "pipes.quote"}

_CLEAN_CALLS = {"len", "abs", "int", "float", "bool", "repr", "ord", "chr"}

_PASSTHROUGH_METHODS = {
    "strip",
    "lstrip",
    "rstrip",
    "upper",
    "lower",
    "title",
    "capitalize",
    "replace",
    "encode",
    "decode",
    "zfill",
    "ljust",
    "rjust",
    "center",
    "removeprefix",
    "removesuffix",
}

_FUNC_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)


class Source:
    """A single external input source and its propagation chain."""

    def __init__(self, kind, lineno, steps=None):
        self.kind = kind
        self.lineno = lineno
        # list of (lineno, variable name) assignments, in order
        self.steps = list(steps or [])

    def key(self):
        return (self.kind, self.lineno, tuple(self.steps))

    def with_step(self, lineno, name):
        return Source(self.kind, self.lineno, self.steps + [(lineno, name)])


class Value:
    """Taint state of an expression.

    sources: external inputs the value may contain
    quoted: True only if every source was passed through shlex.quote
        as a complete shell word and nothing broke quoting since
    unknown: analysis boundary notes (loops, unanalyzable calls);
        a value carrying these must never be treated as proven safe
    """

    def __init__(self, sources=None, quoted=False, unknown=None):
        self.sources = list(sources or [])
        self.quoted = quoted
        self.unknown = list(unknown or [])

    @staticmethod
    def clean():
        return Value()

    def copy(self):
        return Value(self.sources, self.quoted, self.unknown)

    def with_step(self, lineno, name):
        return Value(
            [s.with_step(lineno, name) for s in self.sources],
            self.quoted,
            self.unknown,
        )


def _merge_sources(first, second):
    seen = set()
    merged = []
    for src in list(first) + list(second):
        if src.key() not in seen:
            seen.add(src.key())
            merged.append(src)
    return merged


def _combine(first, second, quoted=False):
    """Union of two values; quoted only if every tainted side is."""
    sources = _merge_sources(first.sources, second.sources)
    is_quoted = False
    if sources:
        is_quoted = quoted
        for value in (first, second):
            if value.sources and not value.quoted:
                is_quoted = False
    return Value(sources, is_quoted, first.unknown + second.unknown)


def _quote_broken(text):
    """A literal wrapping a value in quotes voids shlex.quote."""
    return "'" in text or '"' in text


class Report:
    """Result of analyzing one shell execution call."""

    def __init__(self, value, sink_lineno):
        self.value = value
        self.sink_lineno = sink_lineno

    @property
    def tainted(self):
        """External input reaches the shell command unquoted."""
        return bool(self.value.sources) and not self.value.quoted

    @property
    def properly_quoted(self):
        """External input reaches the call fully quoted as a word."""
        return bool(self.value.sources) and self.value.quoted

    @property
    def boundaries(self):
        """Explicit analysis boundaries; never a proof of safety."""
        return list(self.value.unknown)

    def format(self):
        """Human readable source/propagation/sink description.

        Only source code positions and variable names are included.
        """
        parts = []
        if self.tainted:
            for src in self.value.sources:
                chain = " -> ".join(
                    f"'{name}' (line {lineno})" for lineno, name in src.steps
                )
                if chain:
                    chain = " via " + chain
                parts.append(
                    f"external input from {src.kind} "
                    f"(line {src.lineno}) reaches the shell command "
                    f"(line {self.sink_lineno}){chain}"
                )
        for note in self.boundaries:
            parts.append(f"analysis boundary: {note}")
        return "; ".join(parts)


def _qualname(node, aliases):
    """Resolve a (possibly aliased) dotted name for an expression."""
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _qualname(node.value, aliases)
        if base:
            return base + "." + node.attr
        return None
    if isinstance(node, ast.Call):
        return _qualname(node.func, aliases)
    if isinstance(node, ast.Subscript):
        return _qualname(node.value, aliases)
    return None


def _source_for(qualname, lineno):
    kind = _SOURCE_QUALNAMES.get(qualname)
    if kind:
        return Value([Source(kind, lineno)])
    return None


class _Analyzer:
    def __init__(self, aliases):
        self.aliases = dict(aliases or {})

    # -- expression evaluation --------------------------------------

    def eval(self, node, env):
        if isinstance(node, ast.Constant):
            return Value()
        if isinstance(node, ast.Name):
            source = _source_for(
                self.aliases.get(node.id, node.id), node.lineno
            )
            if source:
                return source
            return env.get(node.id, Value())
        if isinstance(node, ast.Call):
            return self._eval_call(node, env)
        if isinstance(node, ast.BinOp):
            return self._eval_binop(node, env)
        if isinstance(node, ast.JoinedStr):
            return self._eval_joinedstr(node, env)
        if isinstance(node, ast.FormattedValue):
            return self.eval(node.value, env)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            result = Value()
            for elt in node.elts:
                result = _combine(result, self.eval(elt, env))
            return result
        if isinstance(node, ast.Dict):
            result = Value()
            for key in node.keys:
                if key is not None:
                    result = _combine(result, self.eval(key, env))
            for val in node.values:
                result = _combine(result, self.eval(val, env))
            return result
        if isinstance(node, ast.IfExp):
            return _combine(
                self.eval(node.body, env), self.eval(node.orelse, env)
            )
        if isinstance(node, ast.BoolOp):
            result = Value()
            for val in node.values:
                result = _combine(result, self.eval(val, env))
            return result
        if isinstance(node, ast.Compare):
            result = self.eval(node.left, env)
            for comp in node.comparators:
                result = _combine(result, self.eval(comp, env))
            result.quoted = False
            return result
        if isinstance(node, ast.Starred):
            return self.eval(node.value, env)
        if isinstance(node, ast.Attribute):
            source = _source_for(_qualname(node, self.aliases), node.lineno)
            if source:
                return source
            return self.eval(node.value, env)
        if isinstance(node, ast.Subscript):
            source = _source_for(_qualname(node, self.aliases), node.lineno)
            if source:
                return source
            return self.eval(node.value, env)
        if isinstance(node, (ast.UnaryOp,)):
            return self.eval(node.operand, env)
        # comprehensions, lambdas, await/yield, walrus, ... : boundary
        return Value(
            unknown=[
                f"expression {type(node).__name__} "
                f"(line {node.lineno}) cannot be analyzed"
            ]
        )

    def _eval_binop(self, node, env):
        left = self.eval(node.left, env)
        right = self.eval(node.right, env)
        if isinstance(node.op, ast.Add):
            return self._concat(
                [(left, node.left), (right, node.right)], node.lineno
            )
        if isinstance(node.op, ast.Mod):
            return self._format_like(node.left, left, [right], node.lineno)
        result = _combine(left, right)
        result.quoted = False
        return result

    def _concat(self, parts, lineno):
        """Combine string parts, honoring shlex.quote word position.

        A quoted value stays safe only as a complete shell word: if a
        literal in the same command wraps it in another layer of
        quotes, or an unquoted tainted value is concatenated, the
        result is tainted.
        """
        result = Value()
        broken = False
        for value, expr in parts:
            if (
                isinstance(expr, ast.Constant)
                and isinstance(expr.value, str)
                and _quote_broken(expr.value)
            ):
                broken = True
            result = _combine(result, value, quoted=True)
        if broken:
            result.quoted = False
        return result

    def _format_like(self, template_expr, template, args, lineno):
        """Handle %-formatting and str.format with quote awareness."""
        broken = (
            isinstance(template_expr, ast.Constant)
            and isinstance(template_expr.value, str)
            and _quote_broken(template_expr.value)
        )
        result = template.copy()
        for arg in args:
            result = _combine(result, arg, quoted=True)
        if broken:
            result.quoted = False
        return result

    def _eval_joinedstr(self, node, env):
        parts = []
        for val in node.values:
            if isinstance(val, ast.Constant):
                parts.append((Value(), val))
            else:  # FormattedValue
                parts.append((self.eval(val.value, env), val.value))
        return self._concat(parts, node.lineno)

    def _eval_call(self, node, env):
        qualname = _qualname(node.func, self.aliases)

        source = _source_for(qualname, node.lineno)
        if source:
            return source

        if qualname in _QUOTE_QUALNAMES:
            if node.args:
                quoted = self.eval(node.args[0], env)
                quoted.quoted = True
                return quoted
            return Value(
                unknown=[
                    f"call to {qualname} (line {node.lineno}) "
                    "cannot be analyzed"
                ]
            )

        if qualname in _CLEAN_CALLS:
            return Value()

        if qualname == "str" and node.args:
            return self.eval(node.args[0], env)

        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if method == "get":
                source = _source_for(
                    _qualname(node.func.value, self.aliases),
                    node.lineno,
                )
                if source:
                    return source
            if method == "format":
                template = self.eval(node.func.value, env)
                args = [self.eval(arg, env) for arg in node.args]
                args += [self.eval(kw.value, env) for kw in node.keywords]
                return self._format_like(
                    node.func.value, template, args, node.lineno
                )
            if method == "join":
                result = self.eval(node.func.value, env)
                for arg in node.args:
                    result = _combine(result, self.eval(arg, env), quoted=True)
                return result
            if method in _PASSTHROUGH_METHODS:
                base = self.eval(node.func.value, env)
                for arg in node.args:
                    base = _combine(base, self.eval(arg, env))
                base.quoted = False
                return base

        # unanalyzable call: explicit boundary, not a clean result
        name = qualname or ast.dump(node.func)[:40]
        return Value(
            unknown=[
                f"call to '{name}' (line {node.lineno}) " "cannot be analyzed"
            ]
        )

    # -- statement execution -----------------------------------------

    def _assign(self, target, value, env):
        if isinstance(target, ast.Name):
            env[target.id] = value.with_step(
                getattr(target, "lineno", 0), target.id
            )
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._assign(elt, value, env)
        # attribute/subscript targets are out of scope

    def _exec_stmt(self, stmt, env):
        if isinstance(stmt, ast.Assign):
            value = self.eval(stmt.value, env)
            if isinstance(stmt.value, (ast.Tuple, ast.List)):
                # element-wise unpacking when shapes match
                elts = stmt.value.elts
                for target in stmt.targets:
                    if isinstance(target, (ast.Tuple, ast.List)) and len(
                        target.elts
                    ) == len(elts):
                        for t_elt, v_elt in zip(target.elts, elts):
                            self._assign(t_elt, self.eval(v_elt, env), env)
                        return
            for target in stmt.targets:
                self._assign(target, value, env)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            self._assign(stmt.target, self.eval(stmt.value, env), env)
        elif isinstance(stmt, ast.AugAssign) and isinstance(
            stmt.target, ast.Name
        ):
            current = env.get(stmt.target.id, Value())
            added = self.eval(stmt.value, env)
            merged = self._concat(
                [(current, stmt.target), (added, stmt.value)],
                stmt.lineno,
            )
            env[stmt.target.id] = merged.with_step(stmt.lineno, stmt.target.id)
        elif isinstance(stmt, ast.If):
            body_env = self._exec_body(stmt.body, dict(env))
            else_env = self._exec_body(stmt.orelse, dict(env))
            env.update(_merge_envs(body_env, else_env))
        elif isinstance(stmt, (ast.For, ast.While)):
            loop_env = dict(env)
            if isinstance(stmt, ast.For):
                self._assign(stmt.target, self.eval(stmt.iter, env), loop_env)
            self._exec_body(stmt.body, loop_env)
            assigned = _assigned_names(stmt.body)
            env.update(_merge_envs(env, loop_env))
            # explicit boundary: a single unrolled pass is not proof
            for name in assigned:
                if name in env:
                    env[name] = env[name].copy()
                    env[name].unknown.append(
                        f"loop (line {stmt.lineno}) bounds the "
                        "analysis of "
                        f"'{name}'"
                    )
            self._exec_body(stmt.orelse, env)
        elif isinstance(stmt, ast.Try):
            body_env = self._exec_body(stmt.body, dict(env))
            env.update(_merge_envs(env, body_env))
            for handler in stmt.handlers:
                handler_env = self._exec_body(handler.body, dict(env))
                env.update(_merge_envs(env, handler_env))
            self._exec_body(stmt.orelse, env)
            self._exec_body(stmt.finalbody, env)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            self._exec_body(stmt.body, env)
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            self._update_aliases(stmt)
        elif isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    env.pop(target.id, None)
        elif isinstance(
            stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            pass  # nested definitions are not executed inline
        # Expr, Return, Raise, ... : no variable bindings to track

    def _update_aliases(self, stmt):
        if isinstance(stmt, ast.Import):
            for name in stmt.names:
                if name.asname:
                    self.aliases[name.asname] = name.name
        else:
            module = stmt.module or ""
            for name in stmt.names:
                self.aliases[name.asname or name.name] = (
                    module + "." + name.name
                )

    def _exec_body(self, stmts, env):
        for stmt in stmts:
            self._exec_stmt(stmt, env)
        return env

    # -- sink search --------------------------------------------------

    def run_until_sink(self, stmts, env, sink):
        """Execute statements up to the one containing the sink call.

        Returns the taint Value of the sink's first argument, or None
        if the sink was not found.
        """
        for stmt in stmts:
            if _contains_call(stmt, sink):
                return self._run_into(stmt, env, sink)
            self._exec_stmt(stmt, env)
        return None

    def _run_into(self, stmt, env, sink):
        if isinstance(stmt, ast.If):
            found = self.run_until_sink(stmt.body, dict(env), sink)
            if found is None:
                found = self.run_until_sink(stmt.orelse, dict(env), sink)
            return found
        if isinstance(stmt, (ast.For, ast.While)):
            return self.run_until_sink(stmt.body, dict(env), sink)
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            return self.run_until_sink(stmt.body, env, sink)
        if isinstance(stmt, ast.Try):
            found = self.run_until_sink(stmt.body, dict(env), sink)
            for handler in stmt.handlers:
                if found is not None:
                    break
                found = self.run_until_sink(handler.body, dict(env), sink)
            return found
        if sink.args:
            return self.eval(sink.args[0], env)
        return None


def _merge_envs(first, second):
    merged = dict(first)
    for name, value in second.items():
        if name in merged:
            merged[name] = _combine(merged[name], value, quoted=True)
        else:
            merged[name] = value
    return merged


def _assigned_names(stmts):
    names = set()
    for stmt in stmts:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del)
            ):
                names.add(node.id)
    return names


def _contains_call(stmt, call):
    return any(node is call for node in ast.walk(stmt))


def enclosing_function(call_node):
    """Find the function definition enclosing a call node, if any."""
    node = getattr(call_node, "_bandit_parent", None)
    while node is not None:
        if isinstance(node, _FUNC_TYPES):
            return node
        node = getattr(node, "_bandit_parent", None)
    return None


def analyze_call(call_node, import_aliases=None):
    """Analyze external input flow to a shell execution call.

    :param call_node: the ast.Call sink (shell execution entry point)
    :param import_aliases: import aliases known at the call site
    :return: a Report, or None when the call is not inside a function
        (intra-function analysis only) or cannot be located
    """
    func = enclosing_function(call_node)
    if func is None:
        return None
    analyzer = _Analyzer(import_aliases)
    value = analyzer.run_until_sink(func.body, {}, call_node)
    if value is None:
        return None
    return Report(value, call_node.lineno)
