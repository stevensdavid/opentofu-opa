resource "aws_rds_cluster" "unsupported_engine" {
  engine = "custom-sqlserver-ee"
}

resource "aws_rds_cluster" "all_mysql_log_types" {
  engine                          = each.value
  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]
  for_each                        = toset(["mysql", "aurora-mysql"])
}

resource "aws_rds_cluster" "all_aurora_postgres_log_types" {
  engine                          = each.value
  enabled_cloudwatch_logs_exports = ["postgresql"]
  for_each                        = toset(["aurora-postgresql"])
}

resource "aws_rds_cluster" "all_postgres_log_types" {
  engine                          = each.value
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  for_each                        = toset(["postgres"])
}
