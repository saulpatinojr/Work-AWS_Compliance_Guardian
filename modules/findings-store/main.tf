resource "aws_dynamodb_table" "drift" {
  name         = "${var.name_prefix}-drift"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"

  attribute {
    name = "finding_id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }
}
