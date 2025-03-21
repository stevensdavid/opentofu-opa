resource "aws_rds_cluster_parameter_group" "unsupported_family" {
  family = "sqlserver-ee"
}

resource "aws_rds_cluster_parameter_group" "mysql" {
  family = each.value
  parameter {
    name  = "require_secure_transport"
    value = "ON"
  }
  for_each = toset(["mysql", "aurora-mysql"])
}

resource "aws_rds_cluster_parameter_group" "postgres" {
  family = each.value
  parameter {
    name  = "rds.force_ssl"
    value = true
  }
  for_each = toset(["postgres", "aurora-postgresql"])
}
