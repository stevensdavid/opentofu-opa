resource "aws_sns_topic" "topic" {}

resource "aws_db_event_subscription" "disabled" {
  source_type = "db-cluster"
  sns_topic   = aws_sns_topic.topic.arn
  enabled     = false
}

resource "aws_db_event_subscription" "only_maintenance" {
  source_type = "db-cluster"
  sns_topic   = aws_sns_topic.topic.arn
  enabled     = true
  event_categories = [
    "failover",
    "maintenance",
  ]
}

resource "aws_db_event_subscription" "only_failure" {
  source_type = "db-cluster"
  sns_topic   = aws_sns_topic.topic.arn
  enabled     = true
  event_categories = [
    "failover",
    "failure",
  ]
}

resource "aws_db_event_subscription" "wrong_categories" {
  source_type = "db-cluster"
  sns_topic   = aws_sns_topic.topic.arn
  enabled     = true
  event_categories = [
    "failover",
    "low storage",
  ]
}
