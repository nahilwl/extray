from extray.js.parser import args, callee, params
from extray.rules.base import Rule

SENDER_CHECKS = {b"url", b"id", b"origin"}


class ExternalMessageNoSenderCheck(Rule):
    id = "js.external-message-no-sender-check"
    severity = "medium"
    description = "onMessageExternal listener that never reads sender.url/id/origin: any allowed site or extension is trusted"

    def check_js(self, js):
        for call in js.nodes("call_expression"):
            a = args(call)
            if not callee(call).endswith("runtime.onMessageExternal.addListener") or not a:
                continue
            handler = js.function(a[0])
            if handler is None:
                continue  # handler not resolvable statically
            p = params(handler)
            if len(p) < 2 or not js.reads_property(handler, p[1], SENDER_CHECKS):
                yield js.finding(self, call, "external message listener without sender.url/id/origin check")
