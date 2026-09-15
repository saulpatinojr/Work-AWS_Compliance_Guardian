output "log_group_name" {
  description = "Application log group name."
  value       = aws_cloudwatch_log_group.app.name
}

output "log_group_arn" {
  description = "Application log group ARN."
  value       = aws_cloudwatch_log_group.app.arn
}
