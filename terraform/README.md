# Terraform layout

The deployable POC root is `environments/poc`; reusable resources are under `modules/`.

```powershell
terraform -chdir=terraform/environments/poc init
terraform -chdir=terraform/environments/poc validate
terraform -chdir=terraform/environments/poc plan -var-file=terraform.tfvars
```

Terraform Cloud is the only supported state backend. Copy `environments/poc/terraform.tfvars.example` to a local ignored `terraform.tfvars`, provide only non-secret sandbox values, and review the complete plan before any manual apply. Never run an apply against production or with `Environment=prod`.
