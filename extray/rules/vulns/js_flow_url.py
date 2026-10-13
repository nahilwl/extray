from extray.js.dataflow import FlowRule
from extray.rules.base import Rule


class FlowUrl(FlowRule, Rule):
    id = "js.flow-url"
    severity = "medium"
    description = "Attacker-controlled URL opened or fetched (tabs, fetch, location, window.open)"
    sink_kind = "url"
