locals {
  # the other versions in the rule definition are no longer supported
  unsupported_families = toset(["mariadb10.4"])
}

resource "aws_db_parameter_group" "unsupported_family" {
  family   = each.value
  for_each = local.unsupported_families
}

resource "aws_db_parameter_group" "valid_mysql" {
  family = each.value
  parameter {
    name  = "require_secure_transport"
    value = "true"
  }
  for_each = toset(["mysql5.7", "mariadb10.5"])
}

resource "aws_db_parameter_group" "valid_postgres" {
  family = each.value
  parameter {
    name  = "rds.force_ssl"
    value = "true"
  }
  for_each = toset(["sqlserver", "postgres"])
}
