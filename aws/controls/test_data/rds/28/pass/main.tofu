resource "aws_db_instance" "unsupported_engine" {
  engine         = "custom-sqlserver-ee"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "valid" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
  kms_key_id     = "arn:aws:kms:eu-north-1:123456789012:key/1234abcd-12ab34cd-56ef-1234567890ab"
}
