from extray.js.dataflow import flow_nodes, TIMERS, sinks
from extray.js.parser import is_static, is_stringish
from extray.rules.base import Rule


class CodeExec(Rule):
    id = "js.code-exec"
    severity = "low"
    description = "Code built from a string at runtime, no attacker-controlled source found (eval, Function, string timers)"

    def check_js(self, js):
        reported = flow_nodes(js)  # sinks reached by a flow are reported by the flow rules
        for node in js.nodes("call_expression", "new_expression"):
            if (node.start_byte, node.end_byte) in reported:
                continue
            for s in sinks(node):
                if s.kind == "code" and s.pattern and not is_static(s.value) and (
                        s.name not in TIMERS or is_stringish(s.value)):
                    yield js.finding(self, node, f"dynamic code passed to {s.name}")
                    break
