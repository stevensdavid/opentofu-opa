resource "aws_rds_cluster" "default" {
  engine = "postgres"
}

resource "aws_rds_cluster" "valid" {
  engine          = "postgres"
  master_username = "foo"
}
