resource "aws_db_instance" "unsupported_engine" {
  engine         = "custom-sqlserver-ee"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "enabled_copying_tags" {
  engine                = "postgres"
  instance_class        = "db.t2.micro"
  copy_tags_to_snapshot = true
}
