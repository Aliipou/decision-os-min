permit (
    principal == Agent::"agent:support",
    action == Action::"send_email",
    resource == Effect::"governed"
) when {
    context.consent &&
    context.purpose == "support_reply" &&
    context.data_label == "customer_support"
};

permit (
    principal == Agent::"agent:finance",
    action == Action::"issue_payout",
    resource == Effect::"governed"
) when {
    context.consent &&
    context.purpose == "refund" &&
    context.data_label == "finance"
};

permit (
    principal == Agent::"agent:release",
    action == Action::"deploy_release",
    resource == Effect::"governed"
) when {
    context.consent &&
    context.purpose == "production_change" &&
    context.data_label == "ops"
};
