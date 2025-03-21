resource "aws_db_instance" "unsupported_engine" {
  engine         = "custom-sqlserver-ee"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "valid" {
  engine              = "postgres"
  instance_class      = "db.t2.micro"
  deletion_protection = true
}
