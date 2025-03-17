resource "aws_db_instance" "unspecified_subnet_group" {
  engine         = "mariadb"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "empty_string" {
  engine               = "mariadb"
  instance_class       = "db.t2.micro"
  db_subnet_group_name = ""
}
