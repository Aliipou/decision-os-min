package decisionos

import rego.v1

default allow := false

grants := {
    "agent:support": {"send_email"},
    "agent:finance": {"issue_payout"},
    "agent:release": {"deploy_release"},
}

purposes := {
    "customer_support": {"support_reply"},
    "finance": {"refund"},
    "ops": {"production_change"},
}

allow if {
    input.consent == true
    input.tool in grants[input.actor]
    input.purpose in purposes[input.data_label]
}
