from extray.js.parser import args, callee, is_static
from extray.rules.base import Rule

HTML_PROPERTIES = {b"innerHTML", b"outerHTML"}
WRITE = {"document.write", "document.writeln", "window.document.write", "window.document.writeln"}


class HtmlSink(Rule):
    id = "js.html-sink"
    severity = "low"
    description = "Dynamic HTML written to the DOM (innerHTML, outerHTML, document.write, insertAdjacentHTML)"

    def check_js(self, js):
        for node in js.nodes("assignment_expression", "augmented_assignment_expression", "call_expression"):
            if node.type == "call_expression":
                name, a = callee(node), args(node)
                html = a if name in WRITE else a[1:2] if name.endswith(".insertAdjacentHTML") else []
                if any(not is_static(x) for x in html):
                    yield js.finding(self, node, f"{name if name in WRITE else 'insertAdjacentHTML'} with dynamic HTML")
            else:
                left, right = node.child_by_field_name("left"), node.child_by_field_name("right")
                prop = left.child_by_field_name("property") if left.type == "member_expression" else None
                if prop is not None and prop.text in HTML_PROPERTIES and not is_static(right):
                    yield js.finding(self, node, f"{prop.text.decode()} set to dynamic HTML")
