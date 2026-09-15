# POC environment

This is the only Terraform root for the current sandbox foundation. It provisions the cost-bounded evidence stores and logging baseline. AgentCore, IAM, discovery, API, and console resources are added only after their capability gates are verified.

The default environment is `sandbox`; validation rejects production labels. The audit bucket expires objects after 30 days, the CloudWatch log group retains seven days, and DynamoDB uses on-demand billing.
