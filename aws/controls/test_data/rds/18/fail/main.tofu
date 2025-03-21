resource "aws_sns_topic" "topic" {}

resource "aws_db_event_subscription" "disabled" {
  sns_topic        = aws_sns_topic.topic.arn
  source_type      = "db-security-group"
  enabled          = false
  event_categories = ["failure", "configuration change"]
}

resource "aws_db_event_subscription" "missing_configuration_change" {
  sns_topic        = aws_sns_topic.topic.arn
  source_type      = "db-security-group"
  enabled          = true
  event_categories = ["failure"]
}

resource "aws_db_event_subscription" "missing_failure" {
  sns_topic        = aws_sns_topic.topic.arn
  source_type      = "db-security-group"
  enabled          = true
  event_categories = ["configuration change"]
}
