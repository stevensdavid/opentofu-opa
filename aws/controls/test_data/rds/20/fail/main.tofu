resource "aws_rds_cluster" "admin" {
  engine          = "postgres"
  master_username = "admin"
}
resource "aws_rds_cluster" "postgres" {
  engine          = "postgres"
  master_username = "postgres"
}
