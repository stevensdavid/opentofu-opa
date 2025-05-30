package aws.controls.elasticache

import data.aws.utils as aws_utils
import data.utils

evaluate_elasticache_1(plan) := {violation |
	some {"configuration": configuration, "address": address} in utils.resources(plan, "aws_elasticache_cluster")

	configuration.engine in {"valkey", "redis"}
	utils.falsy(configuration.snapshot_retention_limit)

	violation := {
		"id": {"opa": "aws.controls.elasticache.1"},
		"reason": "Require an Amazon ElastiCache (Redis OSS) cluster to have automatic backups activated",
		"resource": address,
		"severity": "medium",
		"docs": "https://github.com/stevensdavid/opentofu-opa/wiki/AWS-Controls#awscontrolselasticache1",
	}
}
