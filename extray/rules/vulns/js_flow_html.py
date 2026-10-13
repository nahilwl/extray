from extray.js.dataflow import FlowRule
from extray.rules.base import Rule


class FlowHtml(FlowRule, Rule):
    id = "js.flow-html"
    severity = "high"
    description = "Attacker-controlled data written as HTML (innerHTML, outerHTML, document.write, insertAdjacentHTML)"
    sink_kind = "html"
