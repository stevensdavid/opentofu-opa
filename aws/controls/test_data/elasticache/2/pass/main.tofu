locals {
  engines = toset(["redis", "valkey"])
}

resource "aws_elasticache_cluster" "memcached" {
  cluster_id      = "example"
  engine          = "memcached"
  node_type       = "cache.m4.large"
  num_cache_nodes = 1
}

resource "aws_elasticache_cluster" "old" {
  cluster_id                 = "example"
  engine                     = "redis"
  engine_version             = "3.2.10"
  node_type                  = "cache.m4.large"
  num_cache_nodes            = 1
  auto_minor_version_upgrade = false
}

resource "aws_elasticache_cluster" "new" {
  cluster_id                 = "example"
  engine                     = "redis"
  engine_version             = "7.2"
  auto_minor_version_upgrade = true
  node_type                  = "cache.m4.large"
  num_cache_nodes            = 1
}


resource "aws_elasticache_cluster" "unset" {
  cluster_id      = "example"
  engine          = each.value
  engine_version  = "7.2"
  node_type       = "cache.m4.large"
  num_cache_nodes = 1
  for_each        = local.engines
}
