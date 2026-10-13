from extray.js.dataflow import FlowRule
from extray.rules.base import Rule


class FlowCodeExec(FlowRule, Rule):
    id = "js.flow-code-exec"
    severity = "high"
    description = "Attacker-controlled data reaches code execution (eval, Function, timers, executeScript)"
    sink_kind = "code"
