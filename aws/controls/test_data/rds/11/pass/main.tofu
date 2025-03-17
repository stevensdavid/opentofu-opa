resource "aws_db_instance" "unsupported_engine" {
  engine         = "custom-sqlserver-ee"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "valid" {
  engine               = "mysql"
  instance_class       = "db.t2.micro"
  db_subnet_group_name = "custom-subnet-group"
}
