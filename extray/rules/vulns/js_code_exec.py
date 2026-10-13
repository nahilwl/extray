from extray.js.dataflow import TIMERS, sinks
from extray.js.parser import is_static, is_stringish
from extray.rules.base import Rule


class CodeExec(Rule):
    id = "js.code-exec"
    severity = "medium"
    description = "Code built from a string at runtime (eval, Function, setTimeout/setInterval with a string)"

    def check_js(self, js):
        for node in js.nodes("call_expression", "new_expression"):
            for s in sinks(node):
                if s.kind == "code" and s.pattern and not is_static(s.value) and (
                        s.name not in TIMERS or is_stringish(s.value)):
                    yield js.finding(self, node, f"dynamic code passed to {s.name}")
                    break
