output "audit_bucket_name" {
  description = "Private S3 bucket holding redacted POC audit records."
  value       = module.audit_storage.bucket_name
}

output "audit_bucket_arn" {
  description = "ARN of the private POC audit bucket."
  value       = module.audit_storage.bucket_arn
}

output "findings_table_name" {
  description = "On-demand DynamoDB table holding current findings."
  value       = module.findings_store.table_name
}

output "application_log_group_name" {
  description = "Seven-day CloudWatch application log group."
  value       = module.observability.log_group_name
}
