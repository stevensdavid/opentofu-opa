resource "aws_rds_cluster" "unspecified" {
  engine = "postgres"
}

resource "aws_rds_cluster" "empty_list" {
  engine                          = "postgres"
  enabled_cloudwatch_logs_exports = []
}

resource "aws_rds_cluster" "unsupported_log_type" {
  engine = "postgres"
  # this is a mysql log type, not a psql
  enabled_cloudwatch_logs_exports = ["audit"]
}

resource "aws_rds_cluster" "missing_log_types" {
  engine = "postgres"
  # this is missing the "postgresql" log type
  enabled_cloudwatch_logs_exports = ["upgrade"]
}
