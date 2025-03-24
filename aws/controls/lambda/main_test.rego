package aws.controls.lambda_test

import rego.v1

import data.aws.controls
import data.aws.controls.lambda

test_evaluate_includes_all_rules if {
	every rule_id in object.keys(controls.mocks.lambda) {
		opa_rule_id := sprintf("aws.controls.lambda.%s", [rule_id])
		denies := lambda.evaluate(controls.mocks.lambda[rule_id].fail)
		some deny in denies
		deny.id.opa == opa_rule_id

		permits := lambda.evaluate(controls.mocks.lambda[rule_id].pass)
		every unrelated_deny in permits {
			unrelated_deny.id.opa != opa_rule_id
		}
	}
}
