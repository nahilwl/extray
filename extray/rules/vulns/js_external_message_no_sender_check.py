from extray.context import exposure
from extray.js.dataflow import SENDER_CHECKS, listeners
from extray.js.parser import params
from extray.rules.base import Rule


class ExternalMessageNoSenderCheck(Rule):
    id = "js.external-message-no-sender-check"
    severity = "medium"
    description = "onMessageExternal listener that never reads sender.url/id/origin: any allowed site or extension is trusted"

    def check_js(self, js):
        for lst in listeners(js):
            if lst.kind != "external_message":
                continue
            if lst.handler is None:  # e.g. this.handler.bind(this): say it was not analyzed rather than stay silent
                yield js.finding(self, lst.call, "handler not resolvable statically, not analyzed", "info")
                continue
            p = params(lst.handler)
            if len(p) < 2 or not js.reads_property(lst.handler, p[1], SENDER_CHECKS):
                level = exposure(lst.kind, js.contexts, js.manifest)
                yield js.finding(self, lst.call, "external message listener without sender.url/id/origin check",
                                 "medium" if level == "web" else "low")
