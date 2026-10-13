"""Intra-function data flow: attacker-controlled sources reaching dangerous sinks.

Statements are followed in source order inside each function. A nested function (callback) starts
from a copy of the taints of its enclosing function at the point where it is defined. Calls to
unknown functions stop the taint: reliable rather than exhaustive.
"""

from dataclasses import dataclass

from tree_sitter import Node

from extray.context import EXPOSURE_LABELS, exposure
from extray.js.parser import FUNCTION_TYPES, JSFile, args, callee, params, string_value

SCOPE_TYPES = (*FUNCTION_TYPES, "method_definition")
SENDER_CHECKS = {b"url", b"id", b"origin"}  # reading one of these on sender counts as checking it
GLOBALS = ("", "window.", "self.", "globalThis.")

# sinks
EVAL = {g + f for g in GLOBALS for f in ("eval", "Function")}
TIMERS = {g + f for g in GLOBALS for f in ("setTimeout", "setInterval")}
HTML_PROPERTIES = {"innerHTML", "outerHTML"}
WRITE = {p + f for p in ("", "window.") for f in ("document.write", "document.writeln")}
LOCATIONS = {p + "location" for p in ("", "window.", "document.", "self.", "globalThis.", "window.document.")}
LOCATION_TARGETS = LOCATIONS | {loc + ".href" for loc in LOCATIONS}
NAVIGATE = {loc + m for loc in LOCATIONS for m in (".assign", ".replace")} | {g + "open" for g in GLOBALS if g}
FETCH = {g + "fetch" for g in GLOBALS}

# sources readable anywhere: the URL, the referrer and the window name are set by whoever opens the page
PAGE_SOURCES = {loc + p for loc in LOCATIONS for p in (".hash", ".search", ".href")} | {
    "document.URL", "document.documentURI", "document.referrer", "window.document.referrer", "window.name",
}
# calls that return (a transformation of) their first argument
PROPAGATORS = {"decodeURIComponent", "decodeURI", "unescape", "atob", "window.atob", "JSON.parse", "String",
               "URL", "URLSearchParams"}


@dataclass(frozen=True)
class Taint:
    node: Node  # where the data enters: the source expression or the handler parameter
    label: str  # e.g. "event.data", "location.hash"
    kind: str  # page | window_message | runtime_message | external_message


@dataclass(frozen=True)
class Sink:
    kind: str  # code | html | url
    name: str  # e.g. "innerHTML", "eval", "chrome.tabs.create url"
    value: Node  # expression written into the sink
    prop: str | None = None  # the sink reads value.<prop> (an options object passed by name)
    pattern: bool = True  # also reported by the pattern rules when dynamic but without a known source


@dataclass(frozen=True)
class Flow:
    source: Taint
    sink: Sink
    node: Node  # the call or assignment where the sink is


@dataclass(frozen=True)
class Listener:
    call: Node  # the addEventListener / addListener call
    handler: Node | None  # None when not resolvable statically
    kind: str  # window_message | runtime_message | external_message


def listeners(js: JSFile) -> list[Listener]:
    """Message listeners: window 'message' events, runtime.onMessage and runtime.onMessageExternal."""
    found = []
    for call in js.nodes("call_expression"):
        name, a = callee(call), args(call)
        if (name == "addEventListener" or name.endswith(".addEventListener")) and len(a) >= 2 \
                and string_value(a[0]) == "message":
            found.append(Listener(call, js.function(a[1]), "window_message"))
        elif a and name.endswith(("runtime.onMessage.addListener", "runtime.onMessageExternal.addListener")):
            kind = "external_message" if "External" in name else "runtime_message"
            found.append(Listener(call, js.function(a[0]), kind))
    return found


def text(node: Node) -> str:
    return node.text.decode("utf-8", "replace")


def path(node: Node) -> str | None:
    """Dotted name of an identifier or property chain ('e.data.html', o["k"] -> 'o.k'), None otherwise."""
    t = node.type
    if t in ("identifier", "this", "shorthand_property_identifier", "shorthand_property_identifier_pattern"):
        return text(node)
    if t == "member_expression":
        base = path(node.child_by_field_name("object"))
        return f"{base}.{text(node.child_by_field_name('property'))}" if base else None
    if t == "subscript_expression":
        base, key = path(node.child_by_field_name("object")), string_value(node.child_by_field_name("index"))
        return f"{base}.{key}" if base and key is not None else None
    return None


def _object_entries(obj: Node) -> list[tuple[str, Node]]:
    """(key, value) of an object literal: {url: x} and the shorthand {url}; computed keys are skipped."""
    entries = []
    for c in obj.named_children:
        if c.type == "pair" and (k := c.child_by_field_name("key")).type in ("property_identifier", "string"):
            entries.append((string_value(k) if k.type == "string" else text(k), c.child_by_field_name("value")))
        elif c.type == "shorthand_property_identifier":
            entries.append((text(c), c))
    return entries


def _options(name: str, arguments: list[Node], keys: set[str], kind: str, pattern: bool = True) -> list[Sink]:
    """Sinks for the given keys of an options object argument, inline or passed by name."""
    sinks = []
    for a in arguments:
        if a.type == "object":
            sinks += [Sink(kind, f"{name} {k}", v, None, pattern) for k, v in _object_entries(a) if k in keys]
        elif path(a):
            sinks += [Sink(kind, f"{name} {k}", a, k, pattern) for k in keys]
    return sinks


def sinks(node: Node) -> list[Sink]:
    """Dangerous sinks at a call, new or assignment node, with the expression flowing into each."""
    if node.type in ("call_expression", "new_expression"):
        name, a = callee(node), args(node)
        if name in EVAL:
            return [Sink("code", name, x) for x in a]
        if name in TIMERS and a:
            return [Sink("code", name, a[0])]
        if name.endswith(("scripting.executeScript", "tabs.executeScript")):
            return _options(name, a, {"code"}, "code") + _options(name, a, {"files", "args"}, "code", pattern=False)
        if name in WRITE:
            return [Sink("html", name, x) for x in a]
        if name.endswith(".insertAdjacentHTML") and len(a) > 1:
            return [Sink("html", "insertAdjacentHTML", a[1])]
        if name.endswith(("tabs.create", "tabs.update", "windows.create")):
            return _options(name, a, {"url"}, "url")
        if (name in FETCH or name in NAVIGATE) and a:
            return [Sink("url", name, a[0])]
    elif node.type in ("assignment_expression", "augmented_assignment_expression"):
        left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
        if left.type == "member_expression" and text(left.child_by_field_name("property")) in HTML_PROPERTIES:
            return [Sink("html", text(left.child_by_field_name("property")), right)]
        if path(left) in LOCATION_TARGETS:
            return [Sink("url", path(left), right)]
    return []


class _Analysis:
    def __init__(self, js: JSFile):
        self.js = js
        self.flows: list[Flow] = []
        self.seeds = {}  # handler (start, end) -> listener kind, for listeners whose sender is not checked
        for lst in listeners(js):
            fn = lst.handler
            if fn is None or not params(fn):
                continue
            p = params(fn)
            checked = (lst.kind == "window_message" and js.reads_property(fn, p[0], {b"origin"})) or (
                lst.kind == "external_message" and len(p) > 1 and js.reads_property(fn, p[1], SENDER_CHECKS))
            if not checked:
                self.seeds[(fn.start_byte, fn.end_byte)] = lst.kind

    # taint of expressions

    def lookup(self, p: str, env: dict) -> Taint | None:
        parts = p.split(".")
        for i in range(len(parts), 0, -1):  # e.data.html is tainted if e.data is
            key = ".".join(parts[:i])
            if key in env:
                return env[key]
            if key in PAGE_SOURCES:
                return Taint(None, key, "page")
        return None

    def taint(self, n: Node | None, env: dict) -> Taint | None:
        try:
            return self._taint(n, env)
        except RecursionError:  # absurdly deep expression in a bundle: give up on it, not on the file
            return None

    def _taint(self, n, env):
        if n is None:
            return None
        t = n.type
        if t in ("parenthesized_expression", "await_expression", "spread_element", "template_substitution",
                 "non_null_expression"):
            return next((x for c in n.named_children if (x := self._taint(c, env))), None)
        p = path(n)
        if p is not None:
            found = self.lookup(p, env)
            return Taint(n, found.label, found.kind) if found and found.node is None else found
        if t in ("member_expression", "subscript_expression"):  # a[i], f().x: tainted if the object is
            return self._taint(n.child_by_field_name("object"), env)
        if t == "binary_expression":
            operands = []  # a + b + c nests to the left: walk that spine in a loop, minified chains are long
            while n.type == "binary_expression" and n.child_by_field_name("operator").type in ("+", "||", "&&", "??"):
                operands.append(n.child_by_field_name("right"))
                n = n.child_by_field_name("left")
            if not operands:
                return None  # comparison, arithmetic...: not the data itself
            return next((x for o in [n, *reversed(operands)] if (x := self._taint(o, env))), None)
        if t == "ternary_expression":
            return self._taint(n.child_by_field_name("consequence"), env) or \
                self._taint(n.child_by_field_name("alternative"), env)
        if t in ("template_string", "array"):
            return next((x for c in n.named_children if (x := self._taint(c, env))), None)
        if t in ("assignment_expression", "augmented_assignment_expression"):
            return self._taint(n.child_by_field_name("right"), env)
        if t in ("call_expression", "new_expression"):
            a = args(n)
            if callee(n) in PROPAGATORS:
                return self._taint(a[0], env) if a else None
            fn = n.child_by_field_name("function")
            if fn is not None and fn.type == "member_expression":  # method of a tainted value: t.trim(), t.get("q")
                return self._taint(fn.child_by_field_name("object"), env)
        return None

    # bindings

    def bind(self, target: Node, taint: Taint | None, env: dict, base: str | None = None):
        """Give target (name, property path or destructuring pattern) the taint; base is the source path."""
        t = target.type
        if t == "object_pattern":
            for c in target.named_children:
                if c.type == "shorthand_property_identifier_pattern":
                    key, inner = text(c), c
                elif c.type == "pair_pattern":
                    k = c.child_by_field_name("key")
                    key, inner = string_value(k) if k.type == "string" else text(k), c.child_by_field_name("value")
                elif c.type == "object_assignment_pattern":
                    inner = c.child_by_field_name("left")
                    key = text(inner)
                elif c.type == "rest_pattern":
                    key, inner = None, c.named_children[0]
                else:
                    continue
                sub = taint or (self.lookup(f"{base}.{key}", env) if base and key else None)
                self.bind(inner, sub, env, f"{base}.{key}" if base and key else None)
        elif t == "array_pattern":
            for c in target.named_children:
                self.bind(c, taint, env)
        elif t in ("assignment_pattern", "object_assignment_pattern"):
            self.bind(target.child_by_field_name("left"), taint, env, base)
        elif t == "rest_pattern":
            self.bind(target.named_children[0], taint, env, base)
        elif (p := path(target)) is not None:
            for key in [k for k in env if k == p or k.startswith(p + ".")]:
                del env[key]
            if taint:
                env[p] = taint

    def assign(self, target: Node, value: Node | None, env: dict):
        self.bind(target, self.taint(value, env), env, value is not None and path(value) or None)
        p = path(target)
        if p and value is not None and value.type == "object":  # const opts = {url: x}: opts.url is tainted
            for key, v in _object_entries(value):
                if found := self.taint(v, env):
                    env[f"{p}.{key}"] = found

    # statements

    def handle(self, node: Node, env: dict):
        for sink in sinks(node):
            if sink.prop:
                value = self.lookup(f"{path(sink.value)}.{sink.prop}", env)
                value = value and Taint(value.node or sink.value, value.label, value.kind)
            else:
                value = self.taint(sink.value, env)
            if value:
                self.flows.append(Flow(value, sink, node))
        t = node.type
        if t == "variable_declarator":
            self.assign(node.child_by_field_name("name"), node.child_by_field_name("value"), env)
        elif t == "assignment_expression":
            self.assign(node.child_by_field_name("left"), node.child_by_field_name("right"), env)
        elif t == "augmented_assignment_expression":
            left = node.child_by_field_name("left")
            self.bind(left, self.taint(left, env) or self.taint(node.child_by_field_name("right"), env), env)

    def function(self, fn: Node, env: dict):
        ps = params(fn) if fn.type != "program" else []
        for p in ps:  # parameters shadow outer names
            self.bind(p, None, env)
        kind = self.seeds.get((fn.start_byte, fn.end_byte))
        if kind == "window_message":
            event = ps[0]
            label = f"{text(event)}.data" if event.type == "identifier" else "event.data"
            if event.type == "identifier":
                env[f"{text(event)}.data"] = Taint(event, label, kind)
            else:
                self.bind(event, None, env)
                for c in event.named_children if event.type == "object_pattern" else []:
                    if (c.type == "shorthand_property_identifier_pattern" and text(c) == "data") or (
                            c.type == "pair_pattern" and text(c.child_by_field_name("key")) == "data"):
                        target = c if c.type != "pair_pattern" else c.child_by_field_name("value")
                        self.bind(target, Taint(c, label, kind), env)
        elif kind:
            label = "onMessageExternal message" if kind == "external_message" else "onMessage message"
            self.bind(ps[0], Taint(ps[0], label, kind), env)

        body = fn.child_by_field_name("body") if fn.type != "program" else fn
        if body is None:
            return
        nested = []
        stack = [(c, False) for c in reversed(body.children)] if fn.type == "program" or body.type == "statement_block" \
            else [(body, False)]  # arrow function with an expression body
        while stack:
            node, done = stack.pop()
            if done:
                self.handle(node, env)
            elif node.type in SCOPE_TYPES:
                nested.append((node, dict(env)))  # closure: sees the taints known where it is defined
            else:
                stack.append((node, True))
                stack.extend((c, False) for c in reversed(node.children))
        return nested

    def run(self) -> list[Flow]:
        work = [(self.js.root, {})]
        while work:
            fn, env = work.pop()
            work += self.function(fn, env) or []
        seen, unique = set(), []
        for f in self.flows:  # one flow per sink expression
            key = (f.node.start_byte, f.sink.name)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return sorted(unique, key=lambda f: f.node.start_byte)


def flows(js: JSFile) -> list[Flow]:
    """Every source -> sink flow of a file, computed once and shared by the rules."""
    if getattr(js, "_flows", None) is None:
        js._flows = _Analysis(js).run()
    return js._flows


# severity of a flow by sink kind and exposure of its source
FLOW_SEVERITY = {
    "code": {"web": "high", "sites": "medium", "internal": "low"},
    "html": {"web": "high", "sites": "medium", "internal": "low"},
    "url": {"web": "medium", "sites": "low", "internal": "low"},
}


def flow_nodes(js: JSFile) -> set[tuple[int, int]]:
    """Positions of sinks reached by a flow: the pattern rules leave them to the flow rules."""
    return {(f.node.start_byte, f.node.end_byte) for f in flows(js)}


class FlowRule:
    """Mixin for the flow rules: one finding per flow into a sink of `sink_kind`."""

    sink_kind = ""

    def check_js(self, js):
        for f in flows(js):
            if f.sink.kind == self.sink_kind:
                level = exposure(f.source.kind, js.contexts, js.manifest)
                source_line = js.position(f.source.node)[0]
                sink_line = js.position(f.node)[0]
                message = (f"{f.source.label} (L{source_line}) → {f.sink.name} (L{sink_line}), "
                           f"source reachable from {EXPOSURE_LABELS[level]}")
                yield js.finding(self, f.node, message, FLOW_SEVERITY[self.sink_kind][level])
