output "bucket_name" {
  description = "Private audit bucket name."
  value       = aws_s3_bucket.audit.bucket
}

output "bucket_arn" {
  description = "Private audit bucket ARN."
  value       = aws_s3_bucket.audit.arn
}
