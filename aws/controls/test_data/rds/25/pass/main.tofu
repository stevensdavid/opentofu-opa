resource "aws_db_proxy" "valid" {
  name           = "valid"
  engine_family  = "MYSQL"
  require_tls    = true
  role_arn       = ""
  vpc_subnet_ids = []
  auth {}
}
