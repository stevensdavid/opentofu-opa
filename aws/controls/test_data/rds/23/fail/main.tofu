resource "aws_db_instance" "explicit_disable" {
  engine            = "postgres"
  instance_class    = "db.t2.micro"
  storage_encrypted = false
}
resource "aws_db_instance" "default" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
}
