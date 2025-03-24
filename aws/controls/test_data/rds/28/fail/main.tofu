resource "aws_db_instance" "missing_kms_key" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "explicit_null" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
  kms_key_id     = null
}
