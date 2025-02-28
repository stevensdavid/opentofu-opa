resource "aws_db_instance" "invalid" {
  allocated_storage           = 5
  engine                      = "postgres"
  manage_master_user_password = true
  instance_class              = "db.t2.micro"
  username                    = "foo"
  multi_az                    = false
}
