from extray.js.dataflow import sinks
from extray.js.parser import is_static
from extray.rules.base import Rule


class HtmlSink(Rule):
    id = "js.html-sink"
    severity = "low"
    description = "Dynamic HTML written to the DOM (innerHTML, outerHTML, document.write, insertAdjacentHTML)"

    def check_js(self, js):
        for node in js.nodes("assignment_expression", "augmented_assignment_expression", "call_expression"):
            for s in sinks(node):
                if s.kind == "html" and not is_static(s.value):
                    yield js.finding(self, node, f"dynamic HTML written to {s.name}")
                    break
