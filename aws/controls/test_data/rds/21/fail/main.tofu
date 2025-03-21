resource "aws_db_instance" "postgres" {
  instance_class = "db.t2.micro"
  engine         = "postgres"
  username       = "postgres"
}

resource "aws_db_instance" "admin" {
  instance_class = "db.t2.micro"
  engine         = "postgres"
  username       = "admin"
}
