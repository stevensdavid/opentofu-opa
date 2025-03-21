resource "aws_db_instance" "invalid" {
  engine              = "postgres"
  instance_class      = "db.t2.micro"
  publicly_accessible = true
}
