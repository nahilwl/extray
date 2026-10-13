from extray.js.parser import args, callee, is_static, is_stringish
from extray.rules.base import Rule

GLOBALS = ("", "window.", "self.", "globalThis.")
EVAL = {g + f for g in GLOBALS for f in ("eval", "Function")}
TIMERS = {g + f for g in GLOBALS for f in ("setTimeout", "setInterval")}


class CodeExec(Rule):
    id = "js.code-exec"
    severity = "medium"
    description = "Code built from a string at runtime (eval, Function, setTimeout/setInterval with a string)"

    def check_js(self, js):
        for call in js.nodes("call_expression", "new_expression"):
            name, a = callee(call), args(call)
            if name in EVAL and any(not is_static(x) for x in a):
                yield js.finding(self, call, f"{name} with dynamic code")
            elif name in TIMERS and a and is_stringish(a[0]) and not is_static(a[0]):
                yield js.finding(self, call, f"{name} with a dynamic code string")
