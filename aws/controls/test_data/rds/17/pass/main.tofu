resource "aws_sns_topic" "topic" {}

resource "aws_db_event_subscription" "explicit" {
  sns_topic        = aws_sns_topic.topic.arn
  source_type      = "db-parameter-group"
  enabled          = true
  event_categories = ["configuration change"]
}

resource "aws_db_event_subscription" "default" {
  sns_topic   = aws_sns_topic.topic.arn
  source_type = "db-parameter-group"
  enabled     = true
}

resource "aws_db_event_subscription" "empty_list" {
  sns_topic        = aws_sns_topic.topic.arn
  source_type      = "db-parameter-group"
  enabled          = true
  event_categories = []
}

resource "aws_db_event_subscription" "other_source" {
  sns_topic   = aws_sns_topic.topic.arn
  source_type = "db-cluster"
  enabled     = false
}
