locals {
  engines = toset(["redis", "valkey"])
}

resource "aws_elasticache_cluster" "missing_retention" {
  engine               = each.value
  engine_version       = "8.0"
  cluster_id           = "example"
  node_type            = "cache.t2.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.redis6.x"
  for_each             = local.engines
}

resource "aws_elasticache_cluster" "explicit_zero" {
  engine                   = each.value
  engine_version           = "8.0"
  cluster_id               = "example"
  node_type                = "cache.t2.micro"
  num_cache_nodes          = 1
  parameter_group_name     = "default.redis6.x"
  snapshot_retention_limit = 0
  for_each                 = local.engines
}
