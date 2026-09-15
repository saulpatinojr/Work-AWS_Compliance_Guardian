resource "aws_cloudwatch_log_group" "app" {
  name              = "/ccg/${var.name_prefix}"
  retention_in_days = var.log_retention_days
}
