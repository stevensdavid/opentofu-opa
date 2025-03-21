resource "aws_db_instance" "unsupported_engine" {
  engine         = "custom-sqlserver-ee"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "all_mysql_log_types" {
  engine                          = each.value
  instance_class                  = "db.t2.micro"
  enabled_cloudwatch_logs_exports = ["audit", "error", "general", "slowquery"]
  for_each                        = toset(["mysql", "mariadb"])
}

resource "aws_db_instance" "all_postgres_log_types" {
  engine                          = each.value
  instance_class                  = "db.t2.micro"
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  for_each                        = toset(["postgres"])
}

resource "aws_db_instance" "all_sqlserver_log_types" {
  engine                          = each.value
  instance_class                  = "db.t2.micro"
  enabled_cloudwatch_logs_exports = ["agent", "error"]
  for_each                        = toset(["sqlserver-ee", "sqlserver-se", "sqlserver-ex", "sqlserver-web"])
}

resource "aws_db_instance" "all_oracle_log_types" {
  engine                          = each.value
  instance_class                  = "db.t2.micro"
  enabled_cloudwatch_logs_exports = ["alert", "audit", "listener", "oemagent", "trace"]
  for_each                        = toset(["oracle-ee", "oracle-se2", "oracle-ee-cdb", "oracle-se2-cdb"])
}
