output "table_name" {
  description = "Current findings table name."
  value       = aws_dynamodb_table.drift.name
}

output "table_arn" {
  description = "Current findings table ARN."
  value       = aws_dynamodb_table.drift.arn
}
