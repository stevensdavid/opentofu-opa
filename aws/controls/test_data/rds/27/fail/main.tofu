resource "aws_db_parameter_group" "invalid_mysql" {
  family = each.value
  parameter {
    name  = "require_secure_transport"
    value = "no"
  }
  for_each = toset(["mysql5.7", "mariadb10.5"])
}

resource "aws_db_parameter_group" "invalid_postgres" {
  family = each.value
  parameter {
    name  = "rds.force_ssl"
    value = "false"
  }
  for_each = toset(["sqlserver", "postgres"])
}

resource "aws_db_parameter_group" "invalid_mysql_missing" {
  family   = each.value
  for_each = toset(["mysql5.7", "mariadb10.5"])
}

resource "aws_db_parameter_group" "invalid_postgres_missing" {
  family   = each.value
  for_each = toset(["sqlserver", "postgres"])
}
