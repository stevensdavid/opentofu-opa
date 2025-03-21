resource "aws_db_instance" "default" {
  instance_class = "db.t2.micro"
  engine         = "postgres"
}

resource "aws_db_instance" "unique" {
  instance_class = "db.t2.micro"
  engine         = "postgres"
  username       = "foo"
}
