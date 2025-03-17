resource "aws_db_instance" "unconfigured_copying_tags" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "disabled_copying_tags" {
  engine                = "postgres"
  instance_class        = "db.t2.micro"
  copy_tags_to_snapshot = false
}
