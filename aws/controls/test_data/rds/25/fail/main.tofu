resource "aws_db_proxy" "default" {
  name           = "valid"
  engine_family  = "MYSQL"
  role_arn       = ""
  vpc_subnet_ids = []
  auth {}
}

resource "aws_db_proxy" "explicit_disable" {
  name           = "valid"
  engine_family  = "MYSQL"
  role_arn       = ""
  require_tls    = false
  vpc_subnet_ids = []
  auth {}
}
