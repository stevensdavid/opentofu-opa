
resource "aws_sns_topic" "topic" {}

resource "aws_db_event_subscription" "disabled" {
  sns_topic        = aws_sns_topic.topic.arn
  source_type      = "db-parameter-group"
  enabled          = false
  event_categories = ["configuration change"]
}

resource "aws_db_event_subscription" "missing_configuration_change" {
  sns_topic        = aws_sns_topic.topic.arn
  source_type      = "db-parameter-group"
  enabled          = true
  event_categories = ["maintenance", "failure"]
}
