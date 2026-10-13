from functools import cache

import jsbeautifier
import tree_sitter_javascript as tsjs
from tree_sitter import Language, Node, Parser, Query, QueryCursor

from extray.rules.base import Finding

LANGUAGE = Language(tsjs.language())
_PARSER = Parser(LANGUAGE)
SNIPPET_CHARS = 2000
SNIPPET_LINES = 8


FUNCTION_TYPES = ("function_expression", "arrow_function", "function_declaration",
                  "generator_function", "generator_function_declaration")


@cache
def _query(source: str) -> Query:
    return Query(LANGUAGE, source)


def callee(call: Node) -> str:
    """Source text of what a call/new expression calls, e.g. 'window.addEventListener'."""
    node = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    return node.text.decode("utf-8", "replace") if node else ""


def args(call: Node) -> list[Node]:
    a = call.child_by_field_name("arguments")
    return [c for c in a.named_children if c.type != "comment"] if a and a.type == "arguments" else []


def params(fn: Node) -> list[Node]:
    p = fn.child_by_field_name("parameters")
    if p:
        return [c for c in p.named_children if c.type != "comment"]
    single = fn.child_by_field_name("parameter")  # arrow function without parentheses
    return [single] if single else []


def string_value(node: Node) -> str | None:
    """Value of a plain '...' or "..." literal, None for anything else."""
    return node.text[1:-1].decode("utf-8", "replace") if node.type == "string" else None


def is_static(node: Node) -> bool:
    """A literal that cannot carry attacker data: string, number, or template without ${}."""
    return node.type in ("string", "number") or (
        node.type == "template_string" and not any(c.type == "template_substitution" for c in node.children)
    )


def is_stringish(node: Node) -> bool:
    """A string literal, a template, or a concatenation with a string operand."""
    if node.type in ("string", "template_string"):
        return True
    return node.type == "binary_expression" and any(c.type in ("string", "template_string") or is_stringish(c)
                                                    for c in node.named_children)


def snippet(code: str) -> str:
    """Readable excerpt for the report: the start of the code, beautified."""
    lines = jsbeautifier.beautify(code[:SNIPPET_CHARS]).splitlines()
    return "\n".join(lines[:SNIPPET_LINES] + (["..."] if len(lines) > SNIPPET_LINES else []))


class JSFile:
    """A JS file parsed as is (minified or not), so positions match the original file."""

    def __init__(self, file: str, source: bytes):
        self.file = file
        self.source = source
        self.root = _PARSER.parse(source).root_node
        self.contexts = set()  # extray.context.Context set by the scan, empty when unknown
        self.manifest = None  # extray.manifest.Manifest set by the scan

    def nodes(self, *types: str, root: Node | None = None) -> list[Node]:
        """Every node of the given types under root, in source order (a tree-sitter query, fast on big bundles)."""
        query = _query("[" + " ".join(f"({t})" for t in types) + "] @n")
        found = QueryCursor(query).captures(root or self.root).get("n", [])
        return sorted(found, key=lambda n: n.start_byte)

    def function(self, node: Node) -> Node | None:
        """The function a callback argument refers to: inline, or declared by name in an enclosing scope.

        Minified code reuses short names in every scope, so the nearest declaration wins; a parameter
        or a non-function declaration with that name means the callback is not known statically.
        """
        if node.type in FUNCTION_TYPES:
            return node
        if node.type != "identifier":
            return None  # e.g. this.handler.bind(this): not resolved
        scope = node.parent
        while scope is not None:
            if scope.type in FUNCTION_TYPES + ("method_definition",) and any(
                    node.text in {n.text for n in self.nodes("identifier", root=p)} for p in params(scope)):
                return None  # function(o) { addEventListener("message", o) }
            if scope.type in ("statement_block", "program"):
                for stmt in scope.named_children:
                    stmt = stmt.child_by_field_name("declaration") or stmt if stmt.type == "export_statement" else stmt
                    if stmt.type in ("function_declaration", "generator_function_declaration"):
                        decls = [(stmt.child_by_field_name("name"), stmt)]
                    elif stmt.type in ("lexical_declaration", "variable_declaration"):
                        decls = [(d.child_by_field_name("name"), d.child_by_field_name("value"))
                                 for d in stmt.named_children if d.type == "variable_declarator"]
                    else:
                        continue
                    for name, value in decls:
                        if name is not None and name.text == node.text:
                            return value if value is not None and value.type in FUNCTION_TYPES else None
            scope = scope.parent
        return None

    def position(self, node: Node) -> tuple[int, int]:
        """1-based line and column of a node; the column counts characters, not UTF-8 bytes."""
        line_start = self.source.rfind(b"\n", 0, node.start_byte) + 1
        return node.start_point.row + 1, len(self.source[line_start : node.start_byte].decode("utf-8", "replace")) + 1

    def reads_property(self, fn: Node, param: Node, names: set[bytes]) -> bool:
        """Whether fn reads one of `names` on its parameter: param.name, or a destructuring like { name }."""
        if param.type == "identifier":
            for m in self.nodes("member_expression", root=fn):
                if m.child_by_field_name("object").text == param.text and m.child_by_field_name("property").text in names:
                    return True
            where = fn  # const { origin } = event
        elif param.type == "object_pattern":
            where = param
        else:
            return True  # default value, rest element...: not analyzed, assume checked to avoid noise
        keys = self.nodes("shorthand_property_identifier_pattern", "property_identifier", root=where)
        return any(k.text in names and k.parent.type in ("object_pattern", "pair_pattern") for k in keys)

    def finding(self, rule, node: Node, message: str, severity: str | None = None) -> Finding:
        line, column = self.position(node)
        code = node.text.decode("utf-8", "replace")
        context = ", ".join(sorted(map(str, self.contexts)))
        return Finding(rule.id, severity or rule.severity, message, self.file, line, snippet(code), column, context)
