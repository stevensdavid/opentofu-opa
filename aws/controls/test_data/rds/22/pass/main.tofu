resource "aws_db_instance" "default" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "explicit_false" {
  engine              = "postgres"
  instance_class      = "db.t2.micro"
  publicly_accessible = false
}
