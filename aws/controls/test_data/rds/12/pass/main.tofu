resource "aws_sns_topic" "topic" {}

resource "aws_db_event_subscription" "unsupported_source" {
  source_type = "db-instance"
  sns_topic   = aws_sns_topic.topic.arn
  enabled     = false
}

resource "aws_db_event_subscription" "enabled" {
  source_type = "db-cluster"
  sns_topic   = aws_sns_topic.topic.arn
  enabled     = true
}

resource "aws_db_event_subscription" "enabled_default" {
  source_type = "db-cluster"
  sns_topic   = aws_sns_topic.topic.arn
}

resource "aws_db_event_subscription" "enabled_empty_list" {
  source_type      = "db-cluster"
  sns_topic        = aws_sns_topic.topic.arn
  enabled          = true
  event_categories = []
}

resource "aws_db_event_subscription" "enabled_valid_categories" {
  source_type = "db-cluster"
  sns_topic   = aws_sns_topic.topic.arn
  enabled     = true
  event_categories = [
    # maintenance and failure are required for this rule
    "failure",
    "failover",
    "maintenance",
  ]
}
