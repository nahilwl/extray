from extray.context import exposure
from extray.js.dataflow import listeners
from extray.js.parser import params
from extray.rules.base import Rule


class MessageNoOriginCheck(Rule):
    id = "js.message-no-origin-check"
    severity = "medium"
    description = "postMessage listener that never reads event.origin: any page or frame can send it data"

    def check_js(self, js):
        for lst in listeners(js):
            if lst.kind != "window_message":
                continue
            if lst.handler is None:  # e.g. this.handler.bind(this): say it was not analyzed rather than stay silent
                yield js.finding(self, lst.call, "handler not resolvable statically, not analyzed", "info")
                continue
            event = params(lst.handler)
            if not event or not js.reads_property(lst.handler, event[0], {b"origin"}):
                level = exposure(lst.kind, js.contexts, js.manifest)
                yield js.finding(self, lst.call, "message listener without event.origin check",
                                 "medium" if level == "web" else "low")
