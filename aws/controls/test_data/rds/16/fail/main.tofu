resource "aws_sns_topic" "topic" {}

resource "aws_db_event_subscription" "disabled" {
  sns_topic        = aws_sns_topic.topic.arn
  source_type      = "db-instance"
  enabled          = false
  event_categories = ["maintenance", "failure", "configuration change"]
}

resource "aws_db_event_subscription" "missing_configuration_change" {
  sns_topic        = aws_sns_topic.topic.arn
  source_type      = "db-instance"
  enabled          = true
  event_categories = ["maintenance", "failure"]
}

resource "aws_db_event_subscription" "missing_maintenance" {
  sns_topic        = aws_sns_topic.topic.arn
  source_type      = "db-instance"
  enabled          = true
  event_categories = ["failure", "configuration change"]
}

resource "aws_db_event_subscription" "missing_failure" {
  sns_topic        = aws_sns_topic.topic.arn
  source_type      = "db-instance"
  enabled          = true
  event_categories = ["maintenance", "configuration change"]
}
