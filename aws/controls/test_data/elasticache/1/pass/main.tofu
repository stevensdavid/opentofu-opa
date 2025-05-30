locals {
  engines = toset(["redis", "valkey"])
}

resource "aws_elasticache_cluster" "valid" {
  engine                   = each.value
  engine_version           = "8.0"
  cluster_id               = "example"
  node_type                = "cache.t2.micro"
  num_cache_nodes          = 1
  parameter_group_name     = "default.redis6.x"
  snapshot_retention_limit = 1
  for_each                 = local.engines
}

resource "aws_elasticache_cluster" "memcached" {
  engine               = "memcached"
  cluster_id           = "example"
  node_type            = "cache.t2.micro"
  num_cache_nodes      = 1
  parameter_group_name = "default.memcached1.4"
}
