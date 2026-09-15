terraform {
  required_version = ">= 1.8.0, < 2.0.0"
  required_providers { aws = { source = "hashicorp/aws", version = "~> 5.0" } }
  cloud { organization = "REPLACE_WITH_TFC_ORGANIZATION"; workspaces { name = "REPLACE_WITH_TFC_WORKSPACE" } }
}
