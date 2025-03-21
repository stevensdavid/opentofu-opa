resource "aws_rds_cluster" "restored_from_source_db" {
  engine                        = "postgres"
  replication_source_identifier = "arn:aws:rds:eu-north-1:1234567890:db:database-source"
}

resource "aws_rds_cluster" "restored_from_source_db_disabled_encryption" {
  engine                        = "postgres"
  replication_source_identifier = "arn:aws:rds:eu-north-1:1234567890:db:database-source"
  storage_encrypted             = false
}

resource "aws_rds_cluster" "enabled_encryption" {
  engine            = "postgres"
  storage_encrypted = true
}
