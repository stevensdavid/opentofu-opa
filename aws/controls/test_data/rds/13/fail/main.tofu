resource "aws_db_instance" "explicit_false" {
  engine              = "postgres"
  instance_class      = "db.t2.micro"
  deletion_protection = false
}

resource "aws_db_instance" "missing" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
}
