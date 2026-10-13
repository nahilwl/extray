from extray.js.parser import args, callee, params, string_value
from extray.rules.base import Rule


class MessageNoOriginCheck(Rule):
    id = "js.message-no-origin-check"
    severity = "medium"
    description = "postMessage listener that never reads event.origin: any page or frame can send it data"

    def check_js(self, js):
        for call in js.nodes("call_expression"):
            name = callee(call)
            a = args(call)
            if not (name == "addEventListener" or name.endswith(".addEventListener")):
                continue
            if len(a) < 2 or string_value(a[0]) != "message":
                continue
            handler = js.function(a[1])
            if handler is None:  # e.g. this.handler.bind(this): say it was not analyzed rather than stay silent
                yield js.finding(self, call, "handler not resolvable statically, not analyzed", "info")
                continue
            event = params(handler)
            if not event or not js.reads_property(handler, event[0], {b"origin"}):
                yield js.finding(self, call, "message listener without event.origin check")
