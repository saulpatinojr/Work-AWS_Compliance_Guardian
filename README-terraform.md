# Terraform layout

The deployable configuration lives at the repository root (`main.tf`, `variables.tf`, `outputs.tf`, `versions.tf`), with reusable modules under `modules/`.

HCP Terraform runs against this root automatically (no working directory override needed). Terraform Cloud is the only state backend, and AWS authentication uses HCP Terraform OIDC dynamic credentials via the `TFC_AWS_PROVIDER_AUTH` and `TFC_AWS_RUN_ROLE_ARN` workspace environment variables.

```powershell
terraform init
terraform plan
```

Never commit state or credentials. Applies are triggered by the VCS-driven workflow after a reviewed plan.
