from extray.js.dataflow import flow_nodes, sinks
from extray.js.parser import is_static
from extray.rules.base import Rule


class HtmlSink(Rule):
    id = "js.html-sink"
    severity = "info"
    description = "Dynamic HTML written to the DOM, no attacker-controlled source found: worth a look"

    def check_js(self, js):
        reported = flow_nodes(js)  # sinks reached by a flow are reported by the flow rules
        for node in js.nodes("assignment_expression", "augmented_assignment_expression", "call_expression"):
            if (node.start_byte, node.end_byte) in reported:
                continue
            for s in sinks(node):
                if s.kind == "html" and not is_static(s.value):
                    yield js.finding(self, node, f"dynamic HTML written to {s.name}")
                    break
