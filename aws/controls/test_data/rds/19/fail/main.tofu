resource "aws_db_instance" "default" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
}

resource "aws_db_instance" "postgres" {
  engine         = "postgres"
  instance_class = "db.t2.micro"
  port           = 5432
}

resource "aws_db_instance" "mysql" {
  engine         = each.value
  instance_class = "db.t2.micro"
  port           = 3306 # default
  for_each       = toset(["mysql", "mariadb"])
}

resource "aws_db_instance" "sqlserver" {
  engine         = each.value
  instance_class = "db.t2.micro"
  port           = 1433 # default
  for_each       = toset(["sqlserver-ee", "sqlserver-ex", "sqlserver-web"])
}

resource "aws_db_instance" "oracle" {
  engine         = each.value
  instance_class = "db.t2.micro"
  port           = 1521 # default
  for_each       = toset(["oracle-ee", "oracle-se2", "oracle-ee-cdb", "oracle-se2-cdb"])
}
