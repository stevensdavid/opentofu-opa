resource "aws_rds_cluster" "explicit_false" {
  engine            = "postgres"
  storage_encrypted = false
}

resource "aws_rds_cluster" "missing" {
  engine = "postgres"
}
