provider "aws" { region = var.aws_region }
variable "aws_region" { type = string; default = "us-east-1" }
variable "name_prefix" { type = string; default = "ccg-poc" }
resource "aws_s3_bucket" "audit" { bucket_prefix = "${var.name_prefix}-audit-" }
resource "aws_s3_bucket_public_access_block" "audit" { bucket = aws_s3_bucket.audit.id; block_public_acls = true; block_public_policy = true; ignore_public_acls = true; restrict_public_buckets = true }
resource "aws_s3_bucket_lifecycle_configuration" "audit" { bucket = aws_s3_bucket.audit.id; rule { id = "expire-poc-audit"; status = "Enabled"; filter {}; expiration { days = 30 } } }
resource "aws_dynamodb_table" "drift" { name = "${var.name_prefix}-drift"; billing_mode = "PAY_PER_REQUEST"; hash_key = "finding_id"; attribute { name = "finding_id"; type = "S" } }
resource "aws_cloudwatch_log_group" "app" { name = "/ccg/${var.name_prefix}"; retention_in_days = 7 }
