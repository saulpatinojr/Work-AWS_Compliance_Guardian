# Continuous Compliance Guardian

AWS sandbox POC: detect Security-pillar configuration drift and demonstrate Cedar policy-bound remediation. See `docs/GEN_AI_AGENT_HANDOFF.md` for the complete implementation brief.

## Safety
Use a dedicated sandbox account only. Remediation is off by default. No credentials, Terraform state, or production data belong in this repository.

## Quick start
1. Review the GenAI handoff and Kiro steering.
2. Configure Terraform Cloud placeholders and workspace variables.
3. Run `terraform -chdir=terraform init`, `validate`, then reviewed `plan`.
4. Use only tagged demo resources: `CCGDemo=true`; never `Environment=prod`.
