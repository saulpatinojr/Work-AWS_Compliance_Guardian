provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "comp_guardian"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

module "audit_storage" {
  source = "./modules/audit-storage"

  name_prefix           = var.name_prefix
  audit_expiration_days = var.audit_expiration_days
}

module "findings_store" {
  source = "./modules/findings-store"

  name_prefix = var.name_prefix
}

module "observability" {
  source = "./modules/observability"

  name_prefix        = var.name_prefix
  log_retention_days = var.log_retention_days
}
