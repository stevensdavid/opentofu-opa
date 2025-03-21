resource "aws_db_instance" "unspecified" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "empty_list" {
  engine                          = "postgres"
  instance_class                  = "db.t2.micro"
  enabled_cloudwatch_logs_exports = []
}

resource "aws_db_instance" "unsupported_log_type" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
  # this is a mysql log type, not a psql
  enabled_cloudwatch_logs_exports = ["audit"]
}

resource "aws_db_instance" "missing_log_types" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
  # this is missing the "postgresql" log type
  enabled_cloudwatch_logs_exports = ["upgrade"]
}
