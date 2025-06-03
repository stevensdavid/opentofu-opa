locals {
  engines = toset(["redis", "valkey"])
}

resource "aws_elasticache_cluster" "explicit_false" {
  cluster_id                 = "example"
  engine                     = each.value
  engine_version             = "7.2"
  auto_minor_version_upgrade = false
  node_type                  = "cache.m4.large"
  num_cache_nodes            = 1
  for_each                   = local.engines
}
