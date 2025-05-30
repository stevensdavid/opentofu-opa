package aws.controls.elasticache_test

import rego.v1

import data.aws.controls
import data.aws.controls.elasticache

test_evaluate_includes_all_rules if {
	every rule_id in object.keys(controls.mocks.elasticache) {
		opa_rule_id := sprintf("aws.controls.elasticache.%s", [rule_id])
		denies := elasticache.evaluate(controls.mocks.elasticache[rule_id].fail)
		some deny in denies
		deny.id.opa == opa_rule_id

		permits := elasticache.evaluate(controls.mocks.elasticache[rule_id].pass)
		every unrelated_deny in permits {
			unrelated_deny.id.opa != opa_rule_id
		}
	}
}
