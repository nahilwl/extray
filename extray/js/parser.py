from functools import cache

import jsbeautifier
import tree_sitter_javascript as tsjs
from tree_sitter import Language, Node, Parser, Query, QueryCursor

from extray.rules.base import Finding

LANGUAGE = Language(tsjs.language())
_PARSER = Parser(LANGUAGE)
SNIPPET_CHARS = 2000
SNIPPET_LINES = 8


@cache
def _query(source: str) -> Query:
    return Query(LANGUAGE, source)


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

    def nodes(self, node_type: str, root: Node | None = None) -> list[Node]:
        """Every node of a type under root, in source order (a tree-sitter query, fast on big bundles)."""
        found = QueryCursor(_query(f"({node_type}) @n")).captures(root or self.root).get("n", [])
        return sorted(found, key=lambda n: n.start_byte)

    def position(self, node: Node) -> tuple[int, int]:
        """1-based line and column of a node; the column counts characters, not UTF-8 bytes."""
        line_start = self.source.rfind(b"\n", 0, node.start_byte) + 1
        return node.start_point.row + 1, len(self.source[line_start : node.start_byte].decode("utf-8", "replace")) + 1

    def finding(self, rule, node: Node, message: str, severity: str | None = None) -> Finding:
        line, column = self.position(node)
        code = node.text.decode("utf-8", "replace")
        return Finding(rule.id, severity or rule.severity, message, self.file, line, snippet(code), column)
