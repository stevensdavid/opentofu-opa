resource "aws_rds_cluster_parameter_group" "mysql_missing_parameter" {
  family = each.value
  parameter {
    name  = "foo"
    value = "bar"
  }
  for_each = toset(["mysql", "aurora-mysql"])
}

resource "aws_rds_cluster_parameter_group" "postgres_missing_parameter" {
  family = each.value
  parameter {
    name  = "foo"
    value = "bar"
  }
  for_each = toset(["postgres", "aurora-postgresql"])
}

resource "aws_rds_cluster_parameter_group" "mysql_disabled" {
  family = each.value
  parameter {
    name  = "require_secure_transport"
    value = "OFF"
  }
  for_each = toset(["mysql", "aurora-mysql"])
}

resource "aws_rds_cluster_parameter_group" "postgres_disabled" {
  family = each.value
  parameter {
    name  = "rds.force_ssl"
    value = false
  }
  for_each = toset(["postgres", "aurora-postgresql"])
}
